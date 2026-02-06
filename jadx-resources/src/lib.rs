//! jadx-resources — Android binary resource decoders.
//!
//! * `axml`     — binary XML (`AndroidManifest.xml`, layouts) → tree + text.
//! * `arsc`     — `resources.arsc` table → resolved `R.type.name` entries.
//! * `manifest` — structured `AndroidManifest.xml` extraction for findings.

pub mod arsc;
pub mod axml;
pub mod error;
pub mod manifest;
pub mod pool;
pub mod reader;
pub mod value;

pub use arsc::{Arsc, ResEntry};
pub use axml::{AxmlDocument, XmlAttr, XmlElement, XmlNode, ANDROID_NS};
pub use error::{ResError, Result};
pub use manifest::{Component, DataSpec, IntentFilter, ManifestInfo};
pub use pool::StringPool;
