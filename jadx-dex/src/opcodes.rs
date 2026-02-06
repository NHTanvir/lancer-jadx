//! The full Dalvik opcode table: mnemonic + instruction format for every byte.

/// Dalvik instruction encoding formats (Android `dalvik/docs/instruction-formats`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsnFormat {
    F10x,
    F12x,
    F11n,
    F11x,
    F10t,
    F20t,
    F20bc,
    F22x,
    F21t,
    F21s,
    F21h,
    F21c,
    F23x,
    F22b,
    F22t,
    F22s,
    F22c,
    F22cs,
    F30t,
    F32x,
    F31i,
    F31t,
    F31c,
    F35c,
    F35ms,
    F35mi,
    F3rc,
    F3rms,
    F3rmi,
    F45cc,
    F4rcc,
    F51l,
    /// One of the trailing payload pseudo-instructions (packed/sparse/array).
    Payload,
    /// Unused / reserved opcode slot.
    Unused,
}

impl InsnFormat {
    /// Fixed instruction width in 16-bit code units (payloads computed separately).
    pub fn width(self) -> usize {
        use InsnFormat::*;
        match self {
            F10x | F12x | F11n | F11x | F10t => 1,
            F20t | F20bc | F22x | F21t | F21s | F21h | F21c | F23x | F22b | F22t | F22s | F22c
            | F22cs => 2,
            F30t | F32x | F31i | F31t | F31c | F35c | F35ms | F35mi | F3rc | F3rms | F3rmi => 3,
            F45cc | F4rcc => 4,
            F51l => 5,
            Payload | Unused => 1,
        }
    }
}

/// What kind of constant-pool index an instruction's `c` field refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexKind {
    None,
    String,
    Type,
    Field,
    Method,
    Proto,
    CallSite,
    MethodHandle,
    MethodAndProto,
}

/// Static metadata for one opcode.
#[derive(Debug, Clone, Copy)]
pub struct OpInfo {
    pub name: &'static str,
    pub format: InsnFormat,
    pub index: IndexKind,
}

impl OpInfo {
    const fn n(name: &'static str, format: InsnFormat) -> OpInfo {
        OpInfo {
            name,
            format,
            index: IndexKind::None,
        }
    }
    const fn i(name: &'static str, format: InsnFormat, index: IndexKind) -> OpInfo {
        OpInfo {
            name,
            format,
            index,
        }
    }
}

/// Look up the static metadata for an opcode byte.
pub fn op_info(op: u8) -> OpInfo {
    use IndexKind as K;
    use InsnFormat::*;
    match op {
        0x00 => OpInfo::n("nop", F10x),
        0x01 => OpInfo::n("move", F12x),
        0x02 => OpInfo::n("move/from16", F22x),
        0x03 => OpInfo::n("move/16", F32x),
        0x04 => OpInfo::n("move-wide", F12x),
        0x05 => OpInfo::n("move-wide/from16", F22x),
        0x06 => OpInfo::n("move-wide/16", F32x),
        0x07 => OpInfo::n("move-object", F12x),
        0x08 => OpInfo::n("move-object/from16", F22x),
        0x09 => OpInfo::n("move-object/16", F32x),
        0x0a => OpInfo::n("move-result", F11x),
        0x0b => OpInfo::n("move-result-wide", F11x),
        0x0c => OpInfo::n("move-result-object", F11x),
        0x0d => OpInfo::n("move-exception", F11x),
        0x0e => OpInfo::n("return-void", F10x),
        0x0f => OpInfo::n("return", F11x),
        0x10 => OpInfo::n("return-wide", F11x),
        0x11 => OpInfo::n("return-object", F11x),
        0x12 => OpInfo::n("const/4", F11n),
        0x13 => OpInfo::n("const/16", F21s),
        0x14 => OpInfo::n("const", F31i),
        0x15 => OpInfo::n("const/high16", F21h),
        0x16 => OpInfo::n("const-wide/16", F21s),
        0x17 => OpInfo::n("const-wide/32", F31i),
        0x18 => OpInfo::n("const-wide", F51l),
        0x19 => OpInfo::n("const-wide/high16", F21h),
        0x1a => OpInfo::i("const-string", F21c, K::String),
        0x1b => OpInfo::i("const-string/jumbo", F31c, K::String),
        0x1c => OpInfo::i("const-class", F21c, K::Type),
        0x1d => OpInfo::n("monitor-enter", F11x),
        0x1e => OpInfo::n("monitor-exit", F11x),
        0x1f => OpInfo::i("check-cast", F21c, K::Type),
        0x20 => OpInfo::i("instance-of", F22c, K::Type),
        0x21 => OpInfo::n("array-length", F12x),
        0x22 => OpInfo::i("new-instance", F21c, K::Type),
        0x23 => OpInfo::i("new-array", F22c, K::Type),
        0x24 => OpInfo::i("filled-new-array", F35c, K::Type),
        0x25 => OpInfo::i("filled-new-array/range", F3rc, K::Type),
        0x26 => OpInfo::n("fill-array-data", F31t),
        0x27 => OpInfo::n("throw", F11x),
        0x28 => OpInfo::n("goto", F10t),
        0x29 => OpInfo::n("goto/16", F20t),
        0x2a => OpInfo::n("goto/32", F30t),
        0x2b => OpInfo::n("packed-switch", F31t),
        0x2c => OpInfo::n("sparse-switch", F31t),
        0x2d => OpInfo::n("cmpl-float", F23x),
        0x2e => OpInfo::n("cmpg-float", F23x),
        0x2f => OpInfo::n("cmpl-double", F23x),
        0x30 => OpInfo::n("cmpg-double", F23x),
        0x31 => OpInfo::n("cmp-long", F23x),
        0x32 => OpInfo::n("if-eq", F22t),
        0x33 => OpInfo::n("if-ne", F22t),
        0x34 => OpInfo::n("if-lt", F22t),
        0x35 => OpInfo::n("if-ge", F22t),
        0x36 => OpInfo::n("if-gt", F22t),
        0x37 => OpInfo::n("if-le", F22t),
        0x38 => OpInfo::n("if-eqz", F21t),
        0x39 => OpInfo::n("if-nez", F21t),
        0x3a => OpInfo::n("if-ltz", F21t),
        0x3b => OpInfo::n("if-gez", F21t),
        0x3c => OpInfo::n("if-gtz", F21t),
        0x3d => OpInfo::n("if-lez", F21t),
        0x3e..=0x43 => OpInfo::n("unused", Unused),
        0x44 => OpInfo::n("aget", F23x),
        0x45 => OpInfo::n("aget-wide", F23x),
        0x46 => OpInfo::n("aget-object", F23x),
        0x47 => OpInfo::n("aget-boolean", F23x),
        0x48 => OpInfo::n("aget-byte", F23x),
        0x49 => OpInfo::n("aget-char", F23x),
        0x4a => OpInfo::n("aget-short", F23x),
        0x4b => OpInfo::n("aput", F23x),
        0x4c => OpInfo::n("aput-wide", F23x),
        0x4d => OpInfo::n("aput-object", F23x),
        0x4e => OpInfo::n("aput-boolean", F23x),
        0x4f => OpInfo::n("aput-byte", F23x),
        0x50 => OpInfo::n("aput-char", F23x),
        0x51 => OpInfo::n("aput-short", F23x),
        0x52 => OpInfo::i("iget", F22c, K::Field),
        0x53 => OpInfo::i("iget-wide", F22c, K::Field),
        0x54 => OpInfo::i("iget-object", F22c, K::Field),
        0x55 => OpInfo::i("iget-boolean", F22c, K::Field),
        0x56 => OpInfo::i("iget-byte", F22c, K::Field),
        0x57 => OpInfo::i("iget-char", F22c, K::Field),
        0x58 => OpInfo::i("iget-short", F22c, K::Field),
        0x59 => OpInfo::i("iput", F22c, K::Field),
        0x5a => OpInfo::i("iput-wide", F22c, K::Field),
        0x5b => OpInfo::i("iput-object", F22c, K::Field),
        0x5c => OpInfo::i("iput-boolean", F22c, K::Field),
        0x5d => OpInfo::i("iput-byte", F22c, K::Field),
        0x5e => OpInfo::i("iput-char", F22c, K::Field),
        0x5f => OpInfo::i("iput-short", F22c, K::Field),
        0x60 => OpInfo::i("sget", F21c, K::Field),
        0x61 => OpInfo::i("sget-wide", F21c, K::Field),
        0x62 => OpInfo::i("sget-object", F21c, K::Field),
        0x63 => OpInfo::i("sget-boolean", F21c, K::Field),
        0x64 => OpInfo::i("sget-byte", F21c, K::Field),
        0x65 => OpInfo::i("sget-char", F21c, K::Field),
        0x66 => OpInfo::i("sget-short", F21c, K::Field),
        0x67 => OpInfo::i("sput", F21c, K::Field),
        0x68 => OpInfo::i("sput-wide", F21c, K::Field),
        0x69 => OpInfo::i("sput-object", F21c, K::Field),
        0x6a => OpInfo::i("sput-boolean", F21c, K::Field),
        0x6b => OpInfo::i("sput-byte", F21c, K::Field),
        0x6c => OpInfo::i("sput-char", F21c, K::Field),
        0x6d => OpInfo::i("sput-short", F21c, K::Field),
        0x6e => OpInfo::i("invoke-virtual", F35c, K::Method),
        0x6f => OpInfo::i("invoke-super", F35c, K::Method),
        0x70 => OpInfo::i("invoke-direct", F35c, K::Method),
        0x71 => OpInfo::i("invoke-static", F35c, K::Method),
        0x72 => OpInfo::i("invoke-interface", F35c, K::Method),
        0x73 => OpInfo::n("unused", Unused),
        0x74 => OpInfo::i("invoke-virtual/range", F3rc, K::Method),
        0x75 => OpInfo::i("invoke-super/range", F3rc, K::Method),
        0x76 => OpInfo::i("invoke-direct/range", F3rc, K::Method),
        0x77 => OpInfo::i("invoke-static/range", F3rc, K::Method),
        0x78 => OpInfo::i("invoke-interface/range", F3rc, K::Method),
        0x79 | 0x7a => OpInfo::n("unused", Unused),
        0x7b => OpInfo::n("neg-int", F12x),
        0x7c => OpInfo::n("not-int", F12x),
        0x7d => OpInfo::n("neg-long", F12x),
        0x7e => OpInfo::n("not-long", F12x),
        0x7f => OpInfo::n("neg-float", F12x),
        0x80 => OpInfo::n("neg-double", F12x),
        0x81 => OpInfo::n("int-to-long", F12x),
        0x82 => OpInfo::n("int-to-float", F12x),
        0x83 => OpInfo::n("int-to-double", F12x),
        0x84 => OpInfo::n("long-to-int", F12x),
        0x85 => OpInfo::n("long-to-float", F12x),
        0x86 => OpInfo::n("long-to-double", F12x),
        0x87 => OpInfo::n("float-to-int", F12x),
        0x88 => OpInfo::n("float-to-long", F12x),
        0x89 => OpInfo::n("float-to-double", F12x),
        0x8a => OpInfo::n("double-to-int", F12x),
        0x8b => OpInfo::n("double-to-long", F12x),
        0x8c => OpInfo::n("double-to-float", F12x),
        0x8d => OpInfo::n("int-to-byte", F12x),
        0x8e => OpInfo::n("int-to-char", F12x),
        0x8f => OpInfo::n("int-to-short", F12x),
        0x90 => OpInfo::n("add-int", F23x),
        0x91 => OpInfo::n("sub-int", F23x),
        0x92 => OpInfo::n("mul-int", F23x),
        0x93 => OpInfo::n("div-int", F23x),
        0x94 => OpInfo::n("rem-int", F23x),
        0x95 => OpInfo::n("and-int", F23x),
        0x96 => OpInfo::n("or-int", F23x),
        0x97 => OpInfo::n("xor-int", F23x),
        0x98 => OpInfo::n("shl-int", F23x),
        0x99 => OpInfo::n("shr-int", F23x),
        0x9a => OpInfo::n("ushr-int", F23x),
        0x9b => OpInfo::n("add-long", F23x),
        0x9c => OpInfo::n("sub-long", F23x),
        0x9d => OpInfo::n("mul-long", F23x),
        0x9e => OpInfo::n("div-long", F23x),
        0x9f => OpInfo::n("rem-long", F23x),
        0xa0 => OpInfo::n("and-long", F23x),
        0xa1 => OpInfo::n("or-long", F23x),
        0xa2 => OpInfo::n("xor-long", F23x),
        0xa3 => OpInfo::n("shl-long", F23x),
        0xa4 => OpInfo::n("shr-long", F23x),
        0xa5 => OpInfo::n("ushr-long", F23x),
        0xa6 => OpInfo::n("add-float", F23x),
        0xa7 => OpInfo::n("sub-float", F23x),
        0xa8 => OpInfo::n("mul-float", F23x),
        0xa9 => OpInfo::n("div-float", F23x),
        0xaa => OpInfo::n("rem-float", F23x),
        0xab => OpInfo::n("add-double", F23x),
        0xac => OpInfo::n("sub-double", F23x),
        0xad => OpInfo::n("mul-double", F23x),
        0xae => OpInfo::n("div-double", F23x),
        0xaf => OpInfo::n("rem-double", F23x),
        0xb0 => OpInfo::n("add-int/2addr", F12x),
        0xb1 => OpInfo::n("sub-int/2addr", F12x),
        0xb2 => OpInfo::n("mul-int/2addr", F12x),
        0xb3 => OpInfo::n("div-int/2addr", F12x),
        0xb4 => OpInfo::n("rem-int/2addr", F12x),
        0xb5 => OpInfo::n("and-int/2addr", F12x),
        0xb6 => OpInfo::n("or-int/2addr", F12x),
        0xb7 => OpInfo::n("xor-int/2addr", F12x),
        0xb8 => OpInfo::n("shl-int/2addr", F12x),
        0xb9 => OpInfo::n("shr-int/2addr", F12x),
        0xba => OpInfo::n("ushr-int/2addr", F12x),
        0xbb => OpInfo::n("add-long/2addr", F12x),
        0xbc => OpInfo::n("sub-long/2addr", F12x),
        0xbd => OpInfo::n("mul-long/2addr", F12x),
        0xbe => OpInfo::n("div-long/2addr", F12x),
        0xbf => OpInfo::n("rem-long/2addr", F12x),
        0xc0 => OpInfo::n("and-long/2addr", F12x),
        0xc1 => OpInfo::n("or-long/2addr", F12x),
        0xc2 => OpInfo::n("xor-long/2addr", F12x),
        0xc3 => OpInfo::n("shl-long/2addr", F12x),
        0xc4 => OpInfo::n("shr-long/2addr", F12x),
        0xc5 => OpInfo::n("ushr-long/2addr", F12x),
        0xc6 => OpInfo::n("add-float/2addr", F12x),
        0xc7 => OpInfo::n("sub-float/2addr", F12x),
        0xc8 => OpInfo::n("mul-float/2addr", F12x),
        0xc9 => OpInfo::n("div-float/2addr", F12x),
        0xca => OpInfo::n("rem-float/2addr", F12x),
        0xcb => OpInfo::n("add-double/2addr", F12x),
        0xcc => OpInfo::n("sub-double/2addr", F12x),
        0xcd => OpInfo::n("mul-double/2addr", F12x),
        0xce => OpInfo::n("div-double/2addr", F12x),
        0xcf => OpInfo::n("rem-double/2addr", F12x),
        0xd0 => OpInfo::n("add-int/lit16", F22s),
        0xd1 => OpInfo::n("rsub-int", F22s),
        0xd2 => OpInfo::n("mul-int/lit16", F22s),
        0xd3 => OpInfo::n("div-int/lit16", F22s),
        0xd4 => OpInfo::n("rem-int/lit16", F22s),
        0xd5 => OpInfo::n("and-int/lit16", F22s),
        0xd6 => OpInfo::n("or-int/lit16", F22s),
        0xd7 => OpInfo::n("xor-int/lit16", F22s),
        0xd8 => OpInfo::n("add-int/lit8", F22b),
        0xd9 => OpInfo::n("rsub-int/lit8", F22b),
        0xda => OpInfo::n("mul-int/lit8", F22b),
        0xdb => OpInfo::n("div-int/lit8", F22b),
        0xdc => OpInfo::n("rem-int/lit8", F22b),
        0xdd => OpInfo::n("and-int/lit8", F22b),
        0xde => OpInfo::n("or-int/lit8", F22b),
        0xdf => OpInfo::n("xor-int/lit8", F22b),
        0xe0 => OpInfo::n("shl-int/lit8", F22b),
        0xe1 => OpInfo::n("shr-int/lit8", F22b),
        0xe2 => OpInfo::n("ushr-int/lit8", F22b),
        0xe3..=0xf9 => OpInfo::n("unused", Unused),
        0xfa => OpInfo::i("invoke-polymorphic", F45cc, K::MethodAndProto),
        0xfb => OpInfo::i("invoke-polymorphic/range", F4rcc, K::MethodAndProto),
        0xfc => OpInfo::i("invoke-custom", F35c, K::CallSite),
        0xfd => OpInfo::i("invoke-custom/range", F3rc, K::CallSite),
        0xfe => OpInfo::i("const-method-handle", F21c, K::MethodHandle),
        0xff => OpInfo::i("const-method-type", F21c, K::Proto),
    }
}

/// Classify an opcode for IR construction.
pub fn is_branch(op: u8) -> bool {
    matches!(op, 0x28..=0x2c | 0x32..=0x3d)
}
pub fn is_return(op: u8) -> bool {
    matches!(op, 0x0e..=0x11)
}
pub fn is_throw(op: u8) -> bool {
    op == 0x27
}
pub fn is_invoke(op: u8) -> bool {
    matches!(op, 0x6e..=0x72 | 0x74..=0x78 | 0xfa..=0xfd)
}
pub fn is_switch(op: u8) -> bool {
    matches!(op, 0x2b | 0x2c)
}
pub fn is_if(op: u8) -> bool {
    matches!(op, 0x32..=0x3d)
}
pub fn is_goto(op: u8) -> bool {
    matches!(op, 0x28..=0x2a)
}
/// True for ops that terminate a basic block (block end after this insn).
pub fn is_block_end(op: u8) -> bool {
    is_branch(op) || is_return(op) || is_throw(op)
}
