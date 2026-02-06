//! Dalvik/JVM access flags and their source-level rendering.

pub const ACC_PUBLIC: u32 = 0x1;
pub const ACC_PRIVATE: u32 = 0x2;
pub const ACC_PROTECTED: u32 = 0x4;
pub const ACC_STATIC: u32 = 0x8;
pub const ACC_FINAL: u32 = 0x10;
pub const ACC_SYNCHRONIZED: u32 = 0x20;
pub const ACC_VOLATILE: u32 = 0x40;
pub const ACC_BRIDGE: u32 = 0x40;
pub const ACC_TRANSIENT: u32 = 0x80;
pub const ACC_VARARGS: u32 = 0x80;
pub const ACC_NATIVE: u32 = 0x100;
pub const ACC_INTERFACE: u32 = 0x200;
pub const ACC_ABSTRACT: u32 = 0x400;
pub const ACC_STRICT: u32 = 0x800;
pub const ACC_SYNTHETIC: u32 = 0x1000;
pub const ACC_ANNOTATION: u32 = 0x2000;
pub const ACC_ENUM: u32 = 0x4000;
pub const ACC_CONSTRUCTOR: u32 = 0x10000;
pub const ACC_DECLARED_SYNCHRONIZED: u32 = 0x20000;

/// Which declaration kind we are rendering flags for (some bits are reused).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AccessKind {
    Class,
    Field,
    Method,
}

/// Render the source-level modifier list (e.g. `public static final`).
pub fn modifiers(flags: u32, kind: AccessKind) -> String {
    let mut parts = Vec::new();
    if flags & ACC_PUBLIC != 0 {
        parts.push("public");
    }
    if flags & ACC_PRIVATE != 0 {
        parts.push("private");
    }
    if flags & ACC_PROTECTED != 0 {
        parts.push("protected");
    }
    if flags & ACC_STATIC != 0 {
        parts.push("static");
    }
    if flags & ACC_FINAL != 0 {
        parts.push("final");
    }
    match kind {
        AccessKind::Method => {
            if flags & ACC_SYNCHRONIZED != 0 || flags & ACC_DECLARED_SYNCHRONIZED != 0 {
                parts.push("synchronized");
            }
            if flags & ACC_NATIVE != 0 {
                parts.push("native");
            }
            if flags & ACC_ABSTRACT != 0 {
                parts.push("abstract");
            }
            if flags & ACC_STRICT != 0 {
                parts.push("strictfp");
            }
        }
        AccessKind::Field => {
            if flags & ACC_VOLATILE != 0 {
                parts.push("volatile");
            }
            if flags & ACC_TRANSIENT != 0 {
                parts.push("transient");
            }
        }
        AccessKind::Class => {
            if flags & ACC_ABSTRACT != 0 && flags & ACC_INTERFACE == 0 {
                parts.push("abstract");
            }
        }
    }
    parts.join(" ")
}

pub fn is_static(flags: u32) -> bool {
    flags & ACC_STATIC != 0
}
pub fn is_interface(flags: u32) -> bool {
    flags & ACC_INTERFACE != 0
}
pub fn is_enum(flags: u32) -> bool {
    flags & ACC_ENUM != 0
}
pub fn is_annotation(flags: u32) -> bool {
    flags & ACC_ANNOTATION != 0
}
pub fn is_synthetic(flags: u32) -> bool {
    flags & ACC_SYNTHETIC != 0
}
pub fn is_abstract(flags: u32) -> bool {
    flags & ACC_ABSTRACT != 0
}
pub fn is_native(flags: u32) -> bool {
    flags & ACC_NATIVE != 0
}
pub fn is_constructor(flags: u32) -> bool {
    flags & ACC_CONSTRUCTOR != 0
}

/// The `class`/`interface`/`enum`/`@interface` keyword for a class.
pub fn class_keyword(flags: u32) -> &'static str {
    if is_annotation(flags) {
        "@interface"
    } else if is_interface(flags) {
        "interface"
    } else if is_enum(flags) {
        "enum"
    } else {
        "class"
    }
}
