//! Cross-reference index: who-calls-X, who-reads/writes-field-X,
//! who-extends-X, who-implements-X. Drives GUI/LSP "find references".

use jadx_dex::ir::ssa;
use jadx_dex::{decode_method, DexFile};
use std::collections::BTreeMap;

#[derive(Debug, Default, Clone)]
pub struct XrefIndex {
    /// callee `Class->method` → list of caller `Class->method`.
    pub method_callers: BTreeMap<String, Vec<String>>,
    pub field_readers: BTreeMap<String, Vec<String>>,
    pub field_writers: BTreeMap<String, Vec<String>>,
    /// superclass → subclasses.
    pub subclasses: BTreeMap<String, Vec<String>>,
    /// interface → implementors.
    pub implementors: BTreeMap<String, Vec<String>>,
}

impl XrefIndex {
    pub fn build(dex_files: &[DexFile]) -> XrefIndex {
        let mut idx = XrefIndex::default();
        for dex in dex_files {
            for class in &dex.classes {
                let class_name = dex.class_name(class);
                if let Some(sup) = dex.superclass_name(class) {
                    idx.subclasses.entry(sup).or_default().push(class_name.clone());
                }
                for iface in dex.interface_names(class) {
                    idx.implementors.entry(iface).or_default().push(class_name.clone());
                }
                for m in class.direct_methods.iter().chain(class.virtual_methods.iter()) {
                    let caller = format!("{}->{}", class_name, dex.method_entry_ref(m).name);
                    if let Some(code) = &m.code {
                        for insn in decode_method(&code.insns) {
                            if jadx_dex::opcodes::is_invoke(insn.opcode) {
                                let callee = method_sig(dex, insn.index);
                                idx.method_callers.entry(callee).or_default().push(caller.clone());
                            } else {
                                let _ = ssa::def_reg(&insn); // keep ssa linked for analyses
                                match insn.opcode {
                                    0x52..=0x58 | 0x60..=0x66 => {
                                        let f = field_sig(dex, insn.index);
                                        idx.field_readers.entry(f).or_default().push(caller.clone());
                                    }
                                    0x59..=0x5f | 0x67..=0x6d => {
                                        let f = field_sig(dex, insn.index);
                                        idx.field_writers.entry(f).or_default().push(caller.clone());
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
            }
        }
        idx.dedup();
        idx
    }

    fn dedup(&mut self) {
        for v in self.method_callers.values_mut() {
            v.sort();
            v.dedup();
        }
        for v in self.field_readers.values_mut() {
            v.sort();
            v.dedup();
        }
        for v in self.field_writers.values_mut() {
            v.sort();
            v.dedup();
        }
        for v in self.subclasses.values_mut() {
            v.sort();
            v.dedup();
        }
        for v in self.implementors.values_mut() {
            v.sort();
            v.dedup();
        }
    }

    pub fn callers_of(&self, callee: &str) -> &[String] {
        self.method_callers.get(callee).map(|v| v.as_slice()).unwrap_or(&[])
    }
}

fn method_sig(dex: &DexFile, method_idx: u32) -> String {
    let m = dex.method_ref(method_idx);
    format!("{}->{}", m.class, m.name)
}

fn field_sig(dex: &DexFile, field_idx: u32) -> String {
    let f = dex.field_ref(field_idx);
    format!("{}->{}", f.class, f.name)
}
