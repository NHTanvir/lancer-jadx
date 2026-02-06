//! Source code generation: Java emitter + Kotlin transformer.

pub mod cfg;
pub mod imports;
pub mod java;
pub mod kotlin;
pub mod kotlin_metadata;

pub use java::render_class as render_java_class;
pub use kotlin::render_class as render_kotlin_class;
pub use kotlin_metadata::{KotlinClassKind, KotlinMetadata};
