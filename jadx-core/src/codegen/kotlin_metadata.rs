//! Minimal, hand-rolled decoder for the Kotlin `@Metadata` annotation.
//!
//! Kotlin embeds a protobuf-serialised header (the `d1` element of the
//! `kotlin.Metadata` annotation) describing the original Kotlin class shape.
//! `kotlinx-metadata` / `kotlin-metadata-jvm` parse this with generated proto
//! code; here we implement just enough of the protobuf wire format to walk the
//! top-level tags so callers can introspect the metadata without pulling in an
//! external protobuf crate.
//!
//! Everything here is best-effort and panic-free: malformed buffers yield
//! whatever was successfully parsed so far rather than aborting.

/// A cursor over a protobuf-encoded byte buffer.
///
/// Implements only the slice of the wire format needed to walk a Kotlin
/// metadata header: varints, tags, length-delimited fields and field skipping.
pub struct Pbuf<'a> {
    data: &'a [u8],
    pos: usize,
}

/// Protobuf wire types (the low 3 bits of a tag).
pub mod wire {
    pub const VARINT: u32 = 0;
    pub const I64: u32 = 1;
    pub const LEN: u32 = 2;
    pub const SGROUP: u32 = 3;
    pub const EGROUP: u32 = 4;
    pub const I32: u32 = 5;
}

impl<'a> Pbuf<'a> {
    /// Wrap a byte slice in a cursor positioned at offset 0.
    pub fn new(data: &'a [u8]) -> Self {
        Pbuf { data, pos: 0 }
    }

    /// Bytes remaining to be consumed.
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    /// Whether the whole buffer has been consumed.
    pub fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    /// Current read offset.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Read a base-128 varint. Returns `None` on a truncated / overlong value.
    ///
    /// At most 10 groups are consumed (the maximum for a 64-bit varint); a
    /// continuation bit on the 10th byte is treated as malformed input.
    pub fn read_varint(&mut self) -> Option<u64> {
        let mut result: u64 = 0;
        let mut shift: u32 = 0;
        for _ in 0..10 {
            let byte = *self.data.get(self.pos)?;
            self.pos += 1;
            result |= ((byte & 0x7f) as u64) << shift;
            if byte & 0x80 == 0 {
                return Some(result);
            }
            shift += 7;
        }
        // More than 10 continuation bytes: malformed.
        None
    }

    /// Read a tag, returning `(field_number, wire_type)`.
    ///
    /// A field number of 0 is invalid in protobuf and is reported as `None`.
    pub fn read_tag(&mut self) -> Option<(u32, u32)> {
        let key = self.read_varint()?;
        let field_number = (key >> 3) as u32;
        let wire_type = (key & 0x7) as u32;
        if field_number == 0 {
            return None;
        }
        Some((field_number, wire_type))
    }

    /// Read a length-delimited field's payload as a borrowed slice.
    pub fn read_len_delimited(&mut self) -> Option<&'a [u8]> {
        let len = self.read_varint()? as usize;
        let start = self.pos;
        let end = start.checked_add(len)?;
        if end > self.data.len() {
            return None;
        }
        self.pos = end;
        Some(&self.data[start..end])
    }

    /// Read a length-delimited field's payload as an owned vector.
    pub fn read_len_delimited_vec(&mut self) -> Option<Vec<u8>> {
        self.read_len_delimited().map(|s| s.to_vec())
    }

    /// Read a fixed 32-bit little-endian field.
    pub fn read_fixed32(&mut self) -> Option<u32> {
        let end = self.pos.checked_add(4)?;
        if end > self.data.len() {
            return None;
        }
        let bytes = &self.data[self.pos..end];
        self.pos = end;
        Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Read a fixed 64-bit little-endian field.
    pub fn read_fixed64(&mut self) -> Option<u64> {
        let end = self.pos.checked_add(8)?;
        if end > self.data.len() {
            return None;
        }
        let b = &self.data[self.pos..end];
        self.pos = end;
        Some(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    /// Skip a field's payload given its wire type. Returns `false` if the
    /// buffer was malformed / truncated and nothing more can be done.
    pub fn skip_field(&mut self, wire_type: u32) -> bool {
        match wire_type {
            wire::VARINT => self.read_varint().is_some(),
            wire::I64 => self.read_fixed64().is_some(),
            wire::LEN => self.read_len_delimited().is_some(),
            wire::I32 => self.read_fixed32().is_some(),
            // Groups are deprecated; skip the start marker and let the caller
            // continue scanning (best-effort — nested groups are not tracked).
            wire::SGROUP | wire::EGROUP => true,
            _ => false,
        }
    }
}

/// Decode a zig-zag encoded varint (protobuf `sint32`/`sint64` representation)
/// into a signed integer.
pub fn zigzag_decode(n: u64) -> i64 {
    ((n >> 1) as i64) ^ -((n & 1) as i64)
}

/// Encode a signed integer with zig-zag (provided so tests/round-trips can
/// build sample buffers without an external dependency).
pub fn zigzag_encode(n: i64) -> u64 {
    ((n << 1) ^ (n >> 63)) as u64
}

/// The `kind` discriminator of a Kotlin class, as stored in `@Metadata.k`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KotlinClassKind {
    /// `k = 1` — a regular class, interface or object.
    Class,
    /// `k = 2` — a file facade (top-level declarations in a file).
    FileFacade,
    /// `k = 3` — a synthetic class (e.g. a lambda or `$DefaultImpls`).
    SyntheticClass,
    /// `k = 4` — the facade part of a `@JvmMultifileClass`.
    MultiFileClassFacade,
    /// `k = 5` — a single part of a `@JvmMultifileClass`.
    MultiFileClassPart,
    /// Any other / missing value.
    Unknown,
}

impl KotlinClassKind {
    /// Map the raw `@Metadata.k` integer to a [`KotlinClassKind`].
    pub fn from_k(k: i32) -> KotlinClassKind {
        match k {
            1 => KotlinClassKind::Class,
            2 => KotlinClassKind::FileFacade,
            3 => KotlinClassKind::SyntheticClass,
            4 => KotlinClassKind::MultiFileClassFacade,
            5 => KotlinClassKind::MultiFileClassPart,
            _ => KotlinClassKind::Unknown,
        }
    }

    /// The numeric `k` value this kind serialises to (0 for `Unknown`).
    pub fn to_k(self) -> i32 {
        match self {
            KotlinClassKind::Class => 1,
            KotlinClassKind::FileFacade => 2,
            KotlinClassKind::SyntheticClass => 3,
            KotlinClassKind::MultiFileClassFacade => 4,
            KotlinClassKind::MultiFileClassPart => 5,
            KotlinClassKind::Unknown => 0,
        }
    }
}

/// The decoded element values of a `kotlin.Metadata` annotation.
///
/// Field names mirror the annotation's element names: `kind` (`k`),
/// `metadata_version` (`mv`), `data1` (`d1`), `data2` (`d2`), `extra_int`
/// (`xi`), `extra_string` (`xs`) and `package_name` (`pn`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KotlinMetadata {
    pub kind: KotlinClassKind,
    pub metadata_version: Vec<i32>,
    pub data1: Vec<String>,
    pub data2: Vec<String>,
    pub extra_int: i32,
    pub extra_string: String,
    pub package_name: String,
}

impl Default for KotlinClassKind {
    fn default() -> Self {
        KotlinClassKind::Unknown
    }
}

impl KotlinMetadata {
    /// Build a [`KotlinMetadata`] from the raw `@Metadata` annotation element
    /// values exactly as they appear on the class.
    pub fn from_fields(
        k: i32,
        mv: &[i32],
        d1: &[String],
        d2: &[String],
        xi: i32,
        xs: &str,
        pn: &str,
    ) -> KotlinMetadata {
        KotlinMetadata {
            kind: KotlinClassKind::from_k(k),
            metadata_version: mv.to_vec(),
            data1: d1.to_vec(),
            data2: d2.to_vec(),
            extra_int: xi,
            extra_string: xs.to_string(),
            package_name: pn.to_string(),
        }
    }

    /// Decode the protobuf header carried by this metadata's `d1` strings.
    ///
    /// See [`decode_d1_header`] for the exact decoding semantics.
    pub fn decode_header(&self) -> Vec<(u32, u64)> {
        decode_d1_header(&self.data1)
    }
}

/// Reassemble the raw `d1` byte stream from the metadata strings.
///
/// Kotlin packs the protobuf bytes into a `String[]` where each character's
/// low 8 bits is one payload byte (`char.code & 0xff`). We concatenate them
/// back into a contiguous buffer.
pub fn d1_to_bytes(d1: &[String]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for s in d1 {
        for ch in s.chars() {
            bytes.push((ch as u32 & 0xff) as u8);
        }
    }
    bytes
}

/// Best-effort decode of the Kotlin metadata header stored in `d1`.
///
/// Each `d1` string is treated as a sequence of bytes (`char.code & 0xff`),
/// the strings are concatenated, and the protobuf reader walks the top-level
/// fields. For each field we return `(field_number, value)` where `value` is:
///
/// * the varint itself for VARINT / I32 / I64 fields, and
/// * the payload **length** for length-delimited fields.
///
/// Decoding stops at the first malformed tag/field and returns everything
/// gathered so far; it never panics.
pub fn decode_d1_header(d1: &[String]) -> Vec<(u32, u64)> {
    let bytes = d1_to_bytes(d1);
    decode_proto_tags(&bytes)
}

/// Walk the top-level protobuf fields of `bytes`, returning `(field_number,
/// value)` pairs as described on [`decode_d1_header`].
pub fn decode_proto_tags(bytes: &[u8]) -> Vec<(u32, u64)> {
    let mut buf = Pbuf::new(bytes);
    let mut tags = Vec::new();
    while !buf.is_empty() {
        let (field, wire) = match buf.read_tag() {
            Some(t) => t,
            None => break,
        };
        match wire {
            wire::VARINT => match buf.read_varint() {
                Some(v) => tags.push((field, v)),
                None => break,
            },
            wire::I64 => match buf.read_fixed64() {
                Some(v) => tags.push((field, v)),
                None => break,
            },
            wire::I32 => match buf.read_fixed32() {
                Some(v) => tags.push((field, v as u64)),
                None => break,
            },
            wire::LEN => match buf.read_len_delimited() {
                Some(payload) => tags.push((field, payload.len() as u64)),
                None => break,
            },
            // Deprecated group markers carry no scalar value; record a 0 and
            // continue so a stray marker does not abort the whole scan.
            wire::SGROUP | wire::EGROUP => tags.push((field, 0)),
            _ => break,
        }
    }
    tags
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Append a protobuf tag (field number + wire type) to `buf`.
    fn put_tag(buf: &mut Vec<u8>, field: u32, wire: u32) {
        put_varint(buf, ((field << 3) | wire) as u64);
    }

    /// Append a base-128 varint to `buf`.
    fn put_varint(buf: &mut Vec<u8>, mut v: u64) {
        loop {
            let mut byte = (v & 0x7f) as u8;
            v >>= 7;
            if v != 0 {
                byte |= 0x80;
            }
            buf.push(byte);
            if v == 0 {
                break;
            }
        }
    }

    /// Encode a byte buffer back into the `d1` `char.code & 0xff` string form.
    fn bytes_to_d1(bytes: &[u8]) -> Vec<String> {
        vec![bytes.iter().map(|&b| b as char).collect()]
    }

    #[test]
    fn varint_roundtrip() {
        for &v in &[0u64, 1, 127, 128, 300, 16384, u32::MAX as u64, u64::MAX] {
            let mut buf = Vec::new();
            put_varint(&mut buf, v);
            let mut p = Pbuf::new(&buf);
            assert_eq!(p.read_varint(), Some(v), "varint {v}");
            assert!(p.is_empty());
        }
    }

    #[test]
    fn varint_truncated_is_none() {
        // A lone continuation byte with no follow-up.
        let buf = [0x80u8];
        let mut p = Pbuf::new(&buf);
        assert_eq!(p.read_varint(), None);
    }

    #[test]
    fn varint_overlong_is_none() {
        // 11 continuation bytes — exceeds the 10-group max.
        let buf = [0x80u8; 11];
        let mut p = Pbuf::new(&buf);
        assert_eq!(p.read_varint(), None);
    }

    #[test]
    fn tag_decode() {
        let mut buf = Vec::new();
        put_tag(&mut buf, 1, wire::VARINT);
        put_tag(&mut buf, 2, wire::LEN);
        put_tag(&mut buf, 19, wire::I32);
        let mut p = Pbuf::new(&buf);
        assert_eq!(p.read_tag(), Some((1, wire::VARINT)));
        assert_eq!(p.read_tag(), Some((2, wire::LEN)));
        assert_eq!(p.read_tag(), Some((19, wire::I32)));
    }

    #[test]
    fn zero_field_number_is_invalid() {
        // key = 0 -> field 0, wire 0 -> invalid.
        let buf = [0x00u8];
        let mut p = Pbuf::new(&buf);
        assert_eq!(p.read_tag(), None);
    }

    #[test]
    fn len_delimited_reads_payload() {
        let mut buf = Vec::new();
        put_tag(&mut buf, 2, wire::LEN);
        put_varint(&mut buf, 5);
        buf.extend_from_slice(b"hello");
        let mut p = Pbuf::new(&buf);
        let (field, wire) = p.read_tag().expect("tag");
        assert_eq!((field, wire), (2, wire::LEN));
        assert_eq!(p.read_len_delimited(), Some(&b"hello"[..]));
        assert!(p.is_empty());
    }

    #[test]
    fn len_delimited_truncated_is_none() {
        let mut buf = Vec::new();
        put_varint(&mut buf, 10); // claims 10 bytes...
        buf.extend_from_slice(b"abc"); // ...but only 3 present.
        let mut p = Pbuf::new(&buf);
        assert_eq!(p.read_len_delimited(), None);
    }

    #[test]
    fn fixed_widths() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0x1122_3344u32.to_le_bytes());
        buf.extend_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
        let mut p = Pbuf::new(&buf);
        assert_eq!(p.read_fixed32(), Some(0x1122_3344));
        assert_eq!(p.read_fixed64(), Some(0x1122_3344_5566_7788));
        assert!(p.is_empty());
    }

    #[test]
    fn zigzag_roundtrips() {
        for &v in &[0i64, -1, 1, -2, 2, 63, -64, i32::MIN as i64, i32::MAX as i64] {
            assert_eq!(zigzag_decode(zigzag_encode(v)), v, "zigzag {v}");
        }
    }

    #[test]
    fn skip_field_advances_cursor() {
        let mut buf = Vec::new();
        // field 1 varint 300, field 2 len "ab", then field 3 varint 7.
        put_tag(&mut buf, 1, wire::VARINT);
        put_varint(&mut buf, 300);
        put_tag(&mut buf, 2, wire::LEN);
        put_varint(&mut buf, 2);
        buf.extend_from_slice(b"ab");
        put_tag(&mut buf, 3, wire::VARINT);
        put_varint(&mut buf, 7);

        let mut p = Pbuf::new(&buf);
        let (_, w1) = p.read_tag().unwrap();
        assert!(p.skip_field(w1));
        let (_, w2) = p.read_tag().unwrap();
        assert!(p.skip_field(w2));
        // We should now be exactly at field 3.
        let (f3, w3) = p.read_tag().unwrap();
        assert_eq!(f3, 3);
        assert_eq!(p.read_varint(), Some(7));
        let _ = w3;
    }

    #[test]
    fn decode_proto_tags_mixed() {
        let mut buf = Vec::new();
        put_tag(&mut buf, 1, wire::VARINT);
        put_varint(&mut buf, 42);
        put_tag(&mut buf, 2, wire::LEN);
        put_varint(&mut buf, 3);
        buf.extend_from_slice(b"xyz");
        put_tag(&mut buf, 7, wire::I32);
        buf.extend_from_slice(&1000u32.to_le_bytes());

        let tags = decode_proto_tags(&buf);
        assert_eq!(tags, vec![(1, 42), (2, 3), (7, 1000)]);
    }

    #[test]
    fn decode_d1_header_via_strings() {
        // Build a buffer then re-encode it through the d1 string packing.
        let mut buf = Vec::new();
        put_tag(&mut buf, 1, wire::VARINT);
        put_varint(&mut buf, 9);
        put_tag(&mut buf, 4, wire::LEN);
        put_varint(&mut buf, 2);
        buf.extend_from_slice(&[0x00, 0xff]); // arbitrary bytes incl. high bit

        let d1 = bytes_to_d1(&buf);
        // Round-trips through char.code & 0xff packing.
        assert_eq!(d1_to_bytes(&d1), buf);
        let tags = decode_d1_header(&d1);
        assert_eq!(tags, vec![(1, 9), (4, 2)]);
    }

    #[test]
    fn decode_d1_header_malformed_returns_partial() {
        let mut buf = Vec::new();
        put_tag(&mut buf, 1, wire::VARINT);
        put_varint(&mut buf, 5);
        // Now a length-delimited field claiming more bytes than exist.
        put_tag(&mut buf, 2, wire::LEN);
        put_varint(&mut buf, 50);
        buf.extend_from_slice(b"short");

        let d1 = bytes_to_d1(&buf);
        let tags = decode_d1_header(&d1);
        // Only the first, well-formed field survives.
        assert_eq!(tags, vec![(1, 5)]);
    }

    #[test]
    fn from_k_mapping() {
        assert_eq!(KotlinClassKind::from_k(1), KotlinClassKind::Class);
        assert_eq!(KotlinClassKind::from_k(2), KotlinClassKind::FileFacade);
        assert_eq!(KotlinClassKind::from_k(3), KotlinClassKind::SyntheticClass);
        assert_eq!(
            KotlinClassKind::from_k(4),
            KotlinClassKind::MultiFileClassFacade
        );
        assert_eq!(
            KotlinClassKind::from_k(5),
            KotlinClassKind::MultiFileClassPart
        );
        assert_eq!(KotlinClassKind::from_k(0), KotlinClassKind::Unknown);
        assert_eq!(KotlinClassKind::from_k(6), KotlinClassKind::Unknown);
        assert_eq!(KotlinClassKind::from_k(-1), KotlinClassKind::Unknown);
    }

    #[test]
    fn from_k_to_k_roundtrip() {
        for k in 1..=5 {
            assert_eq!(KotlinClassKind::from_k(k).to_k(), k);
        }
        assert_eq!(KotlinClassKind::Unknown.to_k(), 0);
    }

    #[test]
    fn from_fields_roundtrips_inputs() {
        let mv = [1, 9, 0];
        let d1 = ["abc".to_string(), "def".to_string()];
        let d2 = ["Lcom/example/Foo;".to_string()];
        let md = KotlinMetadata::from_fields(2, &mv, &d1, &d2, 48, "xs", "com/example");
        assert_eq!(md.kind, KotlinClassKind::FileFacade);
        assert_eq!(md.metadata_version, vec![1, 9, 0]);
        assert_eq!(md.data1, vec!["abc".to_string(), "def".to_string()]);
        assert_eq!(md.data2, vec!["Lcom/example/Foo;".to_string()]);
        assert_eq!(md.extra_int, 48);
        assert_eq!(md.extra_string, "xs");
        assert_eq!(md.package_name, "com/example");
    }

    #[test]
    fn decode_header_method_matches_free_fn() {
        let mut buf = Vec::new();
        put_tag(&mut buf, 1, wire::VARINT);
        put_varint(&mut buf, 11);
        let d1: Vec<String> = vec![buf.iter().map(|&b| b as char).collect()];
        let md = KotlinMetadata::from_fields(1, &[], &d1, &[], 0, "", "");
        assert_eq!(md.decode_header(), decode_d1_header(&d1));
        assert_eq!(md.decode_header(), vec![(1, 11)]);
    }

    #[test]
    fn empty_d1_decodes_to_nothing() {
        assert!(decode_d1_header(&[]).is_empty());
        assert!(decode_d1_header(&["".to_string()]).is_empty());
    }
}
