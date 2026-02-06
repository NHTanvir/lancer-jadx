//! Source code generation: Java emitter + Kotlin transformer.

pub mod imports;
pub mod java;
pub mod kotlin;

pub use java::render_class as render_java_class;
pub use kotlin::render_class as render_kotlin_class;
