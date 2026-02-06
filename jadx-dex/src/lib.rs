//! jadx-dex — DEX bytecode parser + DEX→high-level Java IR.
//!
//! Parses the Dalvik Executable (`.dex`) container (header, string/type/proto/
//! field/method pools, class defs, code items, try/catch tables, debug info),
//! decodes the full 256-opcode instruction set, and lowers methods into a
//! control-flow / SSA / region IR for the Java + Kotlin code generators in
//! `jadx-core`.

pub mod access;
pub mod annotation;
pub mod code;
pub mod descriptor;
pub mod dexfile;
pub mod error;
pub mod header;
pub mod insn;
pub mod ir;
pub mod opcodes;
pub mod reader;

pub use annotation::{Annotation, EncodedValue};
pub use code::{CatchHandler, CodeItem, DebugInfo, TryItem};
pub use dexfile::{DexClass, DexFieldEntry, DexFile, DexMethodEntry, FieldRef, MethodRef};
pub use error::{DexError, Result};
pub use header::{find_dex_headers, DexHeader, NO_INDEX};
pub use insn::{decode_method, Insn, Payload};
pub use opcodes::{op_info, IndexKind, InsnFormat, OpInfo};
