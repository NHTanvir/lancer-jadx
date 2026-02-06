//! Java source emitter: walks the structured region tree of each method and
//! renders readable (best-effort) Java, mirroring jadx's output style.
//!
//! Control flow that cannot be fully structured degrades to labelled comments
//! and a trailing block dump (jadx's "bad code" fallback); exception handlers
//! are surfaced via a coarse `try { } catch (Throwable) { }` wrapper.

use super::imports::{is_primitive, Imports};
use crate::args::JadxArgs;
use jadx_dex::access::{self, AccessKind};
use jadx_dex::dexfile::is_init_method;
use jadx_dex::ir::block::{Block, Cfg};
use jadx_dex::ir::region::{Region, SwitchCase};
use jadx_dex::ir::{self};
use jadx_dex::{DexClass, DexFieldEntry, DexFile, DexMethodEntry};
use std::collections::{HashMap, HashSet};

const INDENT: &str = "    ";

/// Render a full Java compilation unit for one DEX class.
pub fn render_class(dex: &DexFile, class: &DexClass, args: &JadxArgs) -> String {
    let class_name = dex.class_name(class);
    let package = jadx_dex::descriptor::package_of(&class_name);
    let mut imports = Imports::new(args.no_imports, &package);

    // Body first (collects imports), header prepended afterwards.
    let body = render_class_body(dex, class, args, &mut imports);

    let mut out = String::new();
    if !package.is_empty() {
        out.push_str(&format!("package {package};\n\n"));
    }
    let import_block = imports.render();
    out.push_str(&import_block);
    out.push_str(&body);
    out
}

fn render_class_body(
    dex: &DexFile,
    class: &DexClass,
    args: &JadxArgs,
    imports: &mut Imports,
) -> String {
    let class_name = dex.class_name(class);
    let simple = jadx_dex::descriptor::simple_name(&class_name);
    let mut out = String::new();

    if let Some(src) = dex.source_file(class) {
        if !args.no_debug_info {
            out.push_str(&format!("/* compiled from: {src} */\n"));
        }
    }

    // NOTE: anonymous / inner-class inlining is intentionally deferred — it
    // requires cross-class context (the enclosing method + captured locals)
    // that is not available in this per-class rendering pass.

    // Class annotations (user-facing only).
    render_annotations(dex, &class.class_annotations, "", imports, &mut out);

    // Generics from the dalvik.annotation.Signature, if any and parseable.
    let generics = dex
        .class_signature(class)
        .and_then(|sig| parse_class_header(&sig, imports));

    let modifiers = access::modifiers(class.access_flags, AccessKind::Class);
    let keyword = access::class_keyword(class.access_flags);
    if !modifiers.is_empty() {
        out.push_str(&modifiers);
        out.push(' ');
    }
    out.push_str(&format!("{keyword} {simple}"));
    if let Some(g) = &generics {
        out.push_str(&g.type_params);
    }

    // extends clause: prefer the generic superclass when available.
    if !access::is_interface(class.access_flags) {
        if let Some(g) = &generics {
            if let Some(sup) = &g.superclass {
                if sup != "java.lang.Object" && sup != "Object" {
                    out.push_str(&format!(" extends {sup}"));
                }
            }
        } else if let Some(sup) = dex.superclass_name(class) {
            if sup != "java.lang.Object" {
                out.push_str(&format!(" extends {}", imports.use_type(&sup)));
            }
        }
    }

    // implements / interface-extends clause.
    let iface_names: Vec<String> = match &generics {
        Some(g) if !g.interfaces.is_empty() => g.interfaces.clone(),
        _ => {
            let ifaces = dex.interface_names(class);
            ifaces.iter().map(|i| imports.use_type(i)).collect()
        }
    };
    if !iface_names.is_empty() {
        let kw = if access::is_interface(class.access_flags) {
            "extends"
        } else {
            "implements"
        };
        out.push_str(&format!(" {kw} {}", iface_names.join(", ")));
    }
    out.push_str(" {\n");

    // Fields.
    let mut field_lines = Vec::new();
    for f in class.static_fields.iter().chain(class.instance_fields.iter()) {
        field_lines.push(render_field(dex, class, f, imports));
    }
    for line in &field_lines {
        out.push_str(line);
    }
    if !field_lines.is_empty() {
        out.push('\n');
    }

    // Methods.
    let methods = class.direct_methods.iter().chain(class.virtual_methods.iter());
    for m in methods {
        if let Some(sc) = &args.single_class {
            // single-class filtering happens at a higher level; keep all here.
            let _ = sc;
        }
        out.push_str(&render_method(dex, class, m, args, imports));
        out.push('\n');
    }

    out.push_str("}\n");
    out
}

fn render_field(dex: &DexFile, class: &DexClass, f: &DexFieldEntry, imports: &mut Imports) -> String {
    let fref = dex.field_entry_ref(f);
    let modifiers = access::modifiers(f.access_flags, AccessKind::Field);
    // Prefer the generic field type from the Signature annotation when present.
    let ty = dex
        .field_signature(class, f.field_idx)
        .and_then(|sig| parse_field_type(&sig, imports))
        .unwrap_or_else(|| imports.use_type(&fref.field_type));
    let mut line = String::new();
    if let Some(anns) = class.field_annotations.get(&f.field_idx) {
        render_annotations(dex, anns, INDENT, imports, &mut line);
    }
    line.push_str(INDENT);
    if !modifiers.is_empty() {
        line.push_str(&modifiers);
        line.push(' ');
    }
    line.push_str(&format!("{ty} {};\n", fref.name));
    line
}

fn render_method(
    dex: &DexFile,
    class: &DexClass,
    m: &DexMethodEntry,
    args: &JadxArgs,
    imports: &mut Imports,
) -> String {
    let mref = dex.method_entry_ref(m);
    let modifiers = access::modifiers(m.access_flags, AccessKind::Method);
    let is_static = access::is_static(m.access_flags);
    let is_ctor = is_init_method(&mref.name);

    // Generics from the dalvik.annotation.Signature, if present and parseable.
    let generics = dex
        .method_signature(class, m.method_idx)
        .and_then(|sig| parse_method_generics(&sig, imports));

    // Parameter registers (only known precisely with a code item).
    let (this_reg, param_regs) = match &m.code {
        Some(code) => compute_param_regs(&mref, code.registers_size, code.ins_size, is_static),
        None => (None, infer_param_regs_no_code(&mref, is_static)),
    };

    // Use generic parameter types positionally when the count matches the
    // erased parameter list; otherwise keep the erased types.
    let use_generic_params = generics
        .as_ref()
        .map(|g| g.params.len() == param_regs.len())
        .unwrap_or(false);
    let param_list: Vec<String> = param_regs
        .iter()
        .enumerate()
        .map(|(i, (reg, ty))| {
            let rendered = if use_generic_params {
                generics.as_ref().unwrap().params[i].clone()
            } else {
                imports.use_type(ty)
            };
            format!("{} {}", rendered, reg_name(is_static, this_reg, *reg))
        })
        .collect();

    // Method-level annotations.
    let mut sig = String::new();
    if let Some(anns) = class.method_annotations.get(&m.method_idx) {
        render_annotations(dex, anns, INDENT, imports, &mut sig);
    }
    sig.push_str(INDENT);
    if !modifiers.is_empty() {
        sig.push_str(&modifiers);
        sig.push(' ');
    }
    // Method type-parameter list (`<T> ...`) for generic methods.
    if let Some(g) = &generics {
        if !g.type_params.is_empty() {
            sig.push_str(&g.type_params);
            sig.push(' ');
        }
    }
    if !is_ctor {
        let ret = match &generics {
            Some(g) => g.return_type.clone(),
            None => imports.use_type(&mref.return_type),
        };
        sig.push_str(&format!("{ret} "));
    }
    let display_name = if mref.name == "<init>" {
        jadx_dex::descriptor::simple_name(&dex.class_name(class))
    } else if mref.name == "<clinit>" {
        // static initialiser
        return render_clinit(dex, class, m, args, imports);
    } else {
        mref.name.clone()
    };
    sig.push_str(&format!("{display_name}({})", param_list.join(", ")));

    let no_body = access::is_abstract(m.access_flags)
        || access::is_native(m.access_flags)
        || m.code.is_none();
    if no_body {
        return format!("{sig};\n");
    }

    let code = m.code.as_ref().unwrap();
    let body = render_method_body(dex, class, m, code, args, imports, is_static, this_reg);
    format!("{sig} {{\n{body}{INDENT}}}\n")
}

fn render_clinit(
    dex: &DexFile,
    class: &DexClass,
    m: &DexMethodEntry,
    args: &JadxArgs,
    imports: &mut Imports,
) -> String {
    let code = match &m.code {
        Some(c) => c,
        None => return String::new(),
    };
    let body = render_method_body(dex, class, m, code, args, imports, true, None);
    format!("{INDENT}static {{\n{body}{INDENT}}}\n")
}

#[allow(clippy::too_many_arguments)]
fn render_method_body(
    dex: &DexFile,
    _class: &DexClass,
    _m: &DexMethodEntry,
    code: &jadx_dex::CodeItem,
    _args: &JadxArgs,
    imports: &mut Imports,
    is_static: bool,
    this_reg: Option<u16>,
) -> String {
    let ir = ir::lower(code);
    let types = infer_types(dex, &ir);

    let mut ctx = MethodCtx {
        dex,
        is_static,
        this_reg,
        types,
        cfg: &ir.cfg,
        pending_new: HashMap::new(),
    };

    // Local declarations for non-parameter destination registers.
    let mut decls = Vec::new();
    let param_set: HashSet<u16> = param_register_set(code, is_static);
    let mut declared: HashSet<u16> = param_set.clone();
    for b in &ir.cfg.blocks {
        for insn in &b.insns {
            if let Some(r) = ir::ssa::def_reg(insn) {
                if declared.insert(r) {
                    let ty = ctx
                        .types
                        .get(&r)
                        .cloned()
                        .unwrap_or_else(|| "int".to_string());
                    decls.push(format!(
                        "{INDENT}{INDENT}{} {} = {};\n",
                        ty,
                        reg_name(is_static, this_reg, r),
                        default_value(&ty)
                    ));
                }
            }
        }
    }

    // Structured region.
    let mut region_lines: Vec<String> = Vec::new();
    let mut emitted: HashSet<usize> = HashSet::new();
    collect_region_blocks(&ir.region, &mut emitted);
    ctx.render_region(&ir.region, 2, imports, &mut region_lines);

    // Leftover (handler / unstructured) blocks, sorted by code offset.
    let mut leftover_ids: Vec<usize> = (0..ir.cfg.len()).filter(|id| !emitted.contains(id)).collect();
    leftover_ids.sort_by_key(|&id| ir.cfg.block(id).start_off);

    let mut out = String::new();
    for d in &decls {
        out.push_str(d);
    }

    let has_handlers = !ir.try_regions.is_empty() && !leftover_ids.is_empty();
    if has_handlers {
        // Resolve catch branches to (Option<type-name>, handler_off), preserving
        // declaration order and de-duplicating identical branches. A `None`
        // type_idx is a catch-all (`finally`/`Throwable`).
        let mut catch_specs: Vec<(Option<String>, u32)> = Vec::new();
        let mut seen: HashSet<(Option<u32>, u32)> = HashSet::new();
        for tr in &ir.try_regions {
            for cb in &tr.catches {
                let key = (cb.type_idx, cb.handler_off);
                if !seen.insert(key) {
                    continue;
                }
                let ty = cb.type_idx.map(|idx| ctx.dex.type_name(idx));
                catch_specs.push((ty, cb.handler_off));
            }
        }

        // Assign each leftover block to the catch whose handler_off matches its
        // start offset; blocks that don't match any handler entry are emitted in
        // a trailing catch-all so no decompiled code is silently dropped.
        let handler_offs: HashSet<u32> = catch_specs.iter().map(|(_, off)| *off).collect();
        let mut by_handler: HashMap<u32, Vec<usize>> = HashMap::new();
        let mut unassigned: Vec<usize> = Vec::new();
        for &id in &leftover_ids {
            let off = ir.cfg.block(id).start_off;
            if handler_offs.contains(&off) {
                by_handler.entry(off).or_default().push(id);
            } else {
                unassigned.push(id);
            }
        }

        out.push_str(&format!("{}try {{\n", INDENT.repeat(2)));
        for l in &region_lines {
            out.push_str(&indent_line(l));
        }

        // Pick exactly one clause to receive any blocks not tied to a specific
        // handler entry: the (first) catch-all if present, else the last clause.
        let has_catch_all = catch_specs.iter().any(|(ty, _)| ty.is_none());
        let dump_idx = if has_catch_all {
            catch_specs.iter().position(|(ty, _)| ty.is_none())
        } else {
            catch_specs.len().checked_sub(1)
        };
        let mut exc_n = 0usize;
        for (idx, (ty, off)) in catch_specs.iter().enumerate() {
            // Build the catch header. Catch-all -> Throwable.
            let decl = match ty {
                Some(t) => {
                    let var = format!("e{exc_n}");
                    exc_n += 1;
                    format!("{} {var}", imports.use_type(t))
                }
                None => "Throwable th".to_string(),
            };
            out.push_str(&format!("{}}} catch ({decl}) {{\n", INDENT.repeat(2)));
            let assigned: Vec<usize> = by_handler.get(off).cloned().unwrap_or_default();
            for id in assigned {
                for l in ctx.leftover_block_lines(id, imports) {
                    out.push_str(&indent_line(&l));
                }
            }
            if Some(idx) == dump_idx {
                for &id in &unassigned {
                    for l in ctx.leftover_block_lines(id, imports) {
                        out.push_str(&indent_line(&l));
                    }
                }
            }
        }
        out.push_str(&format!("{}}}\n", INDENT.repeat(2)));
    } else {
        for l in &region_lines {
            out.push_str(l);
        }
        if !leftover_ids.is_empty() {
            out.push_str(&format!(
                "{}/* jadx: unstructured blocks */\n",
                INDENT.repeat(2)
            ));
            for &id in &leftover_ids {
                for l in ctx.leftover_block_lines(id, imports) {
                    out.push_str(&l);
                }
            }
        }
    }
    out
}

fn indent_line(line: &str) -> String {
    format!("{INDENT}{line}")
}

// ---------------------------------------------------------------------------
// Method context + statement / region translation.
// ---------------------------------------------------------------------------

struct MethodCtx<'a> {
    dex: &'a DexFile,
    is_static: bool,
    this_reg: Option<u16>,
    types: HashMap<u16, String>,
    cfg: &'a Cfg,
    pending_new: HashMap<u16, String>,
}

impl<'a> MethodCtx<'a> {
    fn rn(&self, r: u16) -> String {
        reg_name(self.is_static, self.this_reg, r)
    }

    fn render_region(
        &mut self,
        region: &Region,
        depth: usize,
        imports: &mut Imports,
        out: &mut Vec<String>,
    ) {
        let pad = INDENT.repeat(depth);
        match region {
            Region::Empty => {}
            Region::Block(id) => {
                for s in self.block_statements(self.cfg.block(*id), imports) {
                    out.push(format!("{pad}{s}\n"));
                }
            }
            Region::Seq(items) => {
                for r in items {
                    self.render_region(r, depth, imports, out);
                }
            }
            Region::If {
                cond_block,
                then_branch,
                else_branch,
            } => {
                // Emit the condition block's non-terminator statements first.
                for s in self.block_statements(self.cfg.block(*cond_block), imports) {
                    out.push(format!("{pad}{s}\n"));
                }
                let cond = self.condition(self.cfg.block(*cond_block));
                out.push(format!("{pad}if ({cond}) {{\n"));
                self.render_region(then_branch, depth + 1, imports, out);
                if let Some(eb) = else_branch {
                    out.push(format!("{pad}}} else {{\n"));
                    self.render_region(eb, depth + 1, imports, out);
                }
                out.push(format!("{pad}}}\n"));
            }
            Region::Loop { header, body } => {
                let _ = header;
                out.push(format!("{pad}while (true) {{\n"));
                self.render_region(body, depth + 1, imports, out);
                out.push(format!("{pad}}}\n"));
            }
            Region::Switch { block, cases } => {
                for s in self.block_statements(self.cfg.block(*block), imports) {
                    out.push(format!("{pad}{s}\n"));
                }
                let expr = self.switch_expr(self.cfg.block(*block));
                out.push(format!("{pad}switch ({expr}) {{\n"));
                for case in cases {
                    self.render_case(case, depth + 1, imports, out);
                }
                out.push(format!("{pad}}}\n"));
            }
            Region::Break => out.push(format!("{pad}break;\n")),
            Region::Continue => out.push(format!("{pad}continue;\n")),
            Region::Goto(id) => out.push(format!(
                "{pad}// goto block_{id} @ 0x{:x}\n",
                self.cfg.block(*id).start_off
            )),
        }
    }

    fn render_case(
        &mut self,
        case: &SwitchCase,
        depth: usize,
        imports: &mut Imports,
        out: &mut Vec<String>,
    ) {
        let pad = INDENT.repeat(depth);
        if case.is_default {
            out.push(format!("{pad}default:\n"));
        }
        for k in &case.keys {
            out.push(format!("{pad}case {k}:\n"));
        }
        self.render_region(&case.body, depth + 1, imports, out);
        out.push(format!("{}break;\n", INDENT.repeat(depth + 1)));
    }

    /// Render a leftover (handler / unstructured) block's statements at handler
    /// indent, prefixed with a provenance comment.
    fn leftover_block_lines(&mut self, id: usize, imports: &mut Imports) -> Vec<String> {
        let block = self.cfg.block(id);
        let mut lines = vec![format!(
            "{}// block_{id} @ 0x{:x}\n",
            INDENT.repeat(3),
            block.start_off
        )];
        for s in self.block_statements(block, imports) {
            lines.push(format!("{}{}\n", INDENT.repeat(3), s));
        }
        lines
    }

    /// Emit a block's statements, skipping the trailing structuring terminator.
    fn block_statements(&mut self, block: &Block, imports: &mut Imports) -> Vec<String> {
        let mut out = Vec::new();
        let n = block.insns.len();
        let mut i = 0;
        while i < n {
            let insn = &block.insns[i];
            let is_last = i == n - 1;
            // Terminators handled structurally.
            if is_last
                && (jadx_dex::opcodes::is_if(insn.opcode)
                    || jadx_dex::opcodes::is_goto(insn.opcode)
                    || jadx_dex::opcodes::is_switch(insn.opcode))
            {
                break;
            }
            let next = block.insns.get(i + 1);
            let (lines, consumed) = self.translate(insn, next, imports);
            for l in lines {
                out.push(l);
            }
            i += if consumed { 2 } else { 1 };
        }
        out
    }

    fn condition(&self, block: &Block) -> String {
        let insn = match block.last() {
            Some(i) => i,
            None => return "true".to_string(),
        };
        let a = insn.regs.first().map(|&r| self.rn(r)).unwrap_or_default();
        let b = insn.regs.get(1).map(|&r| self.rn(r)).unwrap_or_default();
        match insn.opcode {
            0x32 => format!("{a} == {b}"),
            0x33 => format!("{a} != {b}"),
            0x34 => format!("{a} < {b}"),
            0x35 => format!("{a} >= {b}"),
            0x36 => format!("{a} > {b}"),
            0x37 => format!("{a} <= {b}"),
            0x38 => format!("{a} == 0"),
            0x39 => format!("{a} != 0"),
            0x3a => format!("{a} < 0"),
            0x3b => format!("{a} >= 0"),
            0x3c => format!("{a} > 0"),
            0x3d => format!("{a} <= 0"),
            _ => "true".to_string(),
        }
    }

    fn switch_expr(&self, block: &Block) -> String {
        block
            .last()
            .and_then(|i| i.regs.first())
            .map(|&r| self.rn(r))
            .unwrap_or_else(|| "0".to_string())
    }

    /// Translate one instruction into zero or more Java statements.
    /// Returns (lines, consumed_next) where consumed_next folds a following
    /// `move-result` into this instruction.
    fn translate(
        &mut self,
        insn: &jadx_dex::Insn,
        next: Option<&jadx_dex::Insn>,
        imports: &mut Imports,
    ) -> (Vec<String>, bool) {
        let op = insn.opcode;
        let regs = &insn.regs;
        let one = |s: String| (vec![s], false);

        // invoke family
        if jadx_dex::opcodes::is_invoke(op) {
            return self.translate_invoke(insn, next, imports);
        }

        match op {
            0x00 => (vec![], false), // nop
            // move family
            0x01..=0x09 => one(format!("{} = {};", self.rn(regs[0]), self.rn(regs[1]))),
            // move-result*: handled by invoke combine; standalone -> comment
            0x0a..=0x0c => (vec![], false),
            0x0d => one(format!("{} = th;", self.rn(regs[0]))), // move-exception
            // returns
            0x0e => one("return;".to_string()),
            0x0f | 0x10 | 0x11 => one(format!("return {};", self.rn(regs[0]))),
            // const family
            0x12..=0x15 => one(format!("{} = {};", self.rn(regs[0]), insn.literal)),
            0x16..=0x19 => one(format!("{} = {}L;", self.rn(regs[0]), insn.literal)),
            0x1a | 0x1b => one(format!(
                "{} = \"{}\";",
                self.rn(regs[0]),
                escape_string(self.dex.string(insn.index))
            )),
            0x1c => one(format!(
                "{} = {}.class;",
                self.rn(regs[0]),
                imports.use_type(&self.dex.type_name(insn.index))
            )),
            0x1d => one(format!("// monitor-enter {}", self.rn(regs[0]))),
            0x1e => one(format!("// monitor-exit {}", self.rn(regs[0]))),
            0x1f => {
                let ty = imports.use_type(&self.dex.type_name(insn.index));
                one(format!("{} = ({ty}) {};", self.rn(regs[0]), self.rn(regs[0])))
            }
            0x20 => {
                let ty = imports.use_type(&self.dex.type_name(insn.index));
                one(format!(
                    "{} = ({} instanceof {ty});",
                    self.rn(regs[0]),
                    self.rn(regs[1])
                ))
            }
            0x21 => one(format!("{} = {}.length;", self.rn(regs[0]), self.rn(regs[1]))),
            0x22 => {
                // new-instance: remember type, materialise at <init>.
                self.pending_new
                    .insert(regs[0], self.dex.type_name(insn.index));
                (vec![], false)
            }
            0x23 => {
                let arr = self.dex.type_name(insn.index);
                let elem = arr.strip_suffix("[]").unwrap_or(&arr).to_string();
                one(format!(
                    "{} = new {}[{}];",
                    self.rn(regs[0]),
                    imports.use_type(&elem),
                    self.rn(regs[1])
                ))
            }
            0x24 | 0x25 => {
                // filled-new-array: combine with move-result.
                let ty = self.dex.type_name(insn.index);
                let elem = ty.strip_suffix("[]").unwrap_or(&ty).to_string();
                let elems: Vec<String> = regs.iter().map(|&r| self.rn(r)).collect();
                let rhs = format!("new {}[]{{{}}}", imports.use_type(&elem), elems.join(", "));
                self.assign_or_expr(rhs, next)
            }
            0x26 => one(format!("// fill-array-data {}", self.rn(regs[0]))),
            0x27 => one(format!("throw {};", self.rn(regs[0]))),
            // aget
            0x44..=0x4a => one(format!(
                "{} = {}[{}];",
                self.rn(regs[0]),
                self.rn(regs[1]),
                self.rn(regs[2])
            )),
            // aput
            0x4b..=0x51 => one(format!(
                "{}[{}] = {};",
                self.rn(regs[1]),
                self.rn(regs[2]),
                self.rn(regs[0])
            )),
            // iget
            0x52..=0x58 => {
                let f = self.dex.field_ref(insn.index);
                one(format!(
                    "{} = {}.{};",
                    self.rn(regs[0]),
                    self.rn(regs[1]),
                    f.name
                ))
            }
            // iput
            0x59..=0x5f => {
                let f = self.dex.field_ref(insn.index);
                one(format!(
                    "{}.{} = {};",
                    self.rn(regs[1]),
                    f.name,
                    self.rn(regs[0])
                ))
            }
            // sget
            0x60..=0x66 => {
                let f = self.dex.field_ref(insn.index);
                one(format!(
                    "{} = {}.{};",
                    self.rn(regs[0]),
                    imports.use_type(&f.class),
                    f.name
                ))
            }
            // sput
            0x67..=0x6d => {
                let f = self.dex.field_ref(insn.index);
                one(format!(
                    "{}.{} = {};",
                    imports.use_type(&f.class),
                    f.name,
                    self.rn(regs[0])
                ))
            }
            // unary
            0x7b..=0x80 => {
                let symbol = if (0x7c..=0x7e).contains(&op) && insn.name.starts_with("not") {
                    "~"
                } else {
                    "-"
                };
                one(format!(
                    "{} = {}{};",
                    self.rn(regs[0]),
                    symbol,
                    self.rn(regs[1])
                ))
            }
            // conversions
            0x81..=0x8f => {
                let target = conversion_target(insn.name);
                one(format!(
                    "{} = ({target}) {};",
                    self.rn(regs[0]),
                    self.rn(regs[1])
                ))
            }
            // cmp family
            0x2d..=0x31 => {
                let a = self.rn(regs[1]);
                let b = self.rn(regs[2]);
                one(format!(
                    "{} = ({a} > {b} ? 1 : ({a} == {b} ? 0 : -1));",
                    self.rn(regs[0])
                ))
            }
            // binary (3-addr) and 2addr
            0x90..=0xaf => {
                let sym = op_symbol(insn.name);
                one(format!(
                    "{} = {} {sym} {};",
                    self.rn(regs[0]),
                    self.rn(regs[1]),
                    self.rn(regs[2])
                ))
            }
            0xb0..=0xcf => {
                let sym = op_symbol(insn.name);
                one(format!(
                    "{} = {} {sym} {};",
                    self.rn(regs[0]),
                    self.rn(regs[0]),
                    self.rn(regs[1])
                ))
            }
            // lit ops
            0xd0..=0xe2 => {
                let sym = op_symbol(insn.name);
                if insn.name.starts_with("rsub") {
                    one(format!(
                        "{} = {} {sym} {};",
                        self.rn(regs[0]),
                        insn.literal,
                        self.rn(regs[1])
                    ))
                } else {
                    one(format!(
                        "{} = {} {sym} {};",
                        self.rn(regs[0]),
                        self.rn(regs[1]),
                        insn.literal
                    ))
                }
            }
            0xfe | 0xff => one(format!("// {} {}", insn.name, self.rn(regs[0]))),
            _ => (vec![format!("// {} (unhandled)", insn.name)], false),
        }
    }

    fn translate_invoke(
        &mut self,
        insn: &jadx_dex::Insn,
        next: Option<&jadx_dex::Insn>,
        imports: &mut Imports,
    ) -> (Vec<String>, bool) {
        let op = insn.opcode;
        let mref = self.dex.method_ref(insn.index);
        let is_static = matches!(op, 0x71 | 0x77);
        let is_super = matches!(op, 0x6f | 0x75);
        let regs = &insn.regs;

        // Constructor call.
        if mref.name == "<init>" && !is_static {
            let receiver_reg = regs.first().copied();
            let arg_regs: Vec<u16> = regs.iter().skip(1).copied().collect();
            let arglist = self.map_args(&arg_regs, &mref.params).join(", ");
            if let Some(rr) = receiver_reg {
                if Some(rr) == self.this_reg {
                    let kw = if is_super { "super" } else { "this" };
                    return (vec![format!("{kw}({arglist});")], false);
                }
                if let Some(ty) = self.pending_new.remove(&rr) {
                    return (
                        vec![format!(
                            "{} = new {}({arglist});",
                            self.rn(rr),
                            imports.use_type(&ty)
                        )],
                        false,
                    );
                }
                return (
                    vec![format!(
                        "{} = new {}({arglist});",
                        self.rn(rr),
                        imports.use_type(&mref.class)
                    )],
                    false,
                );
            }
        }

        let (receiver_part, arg_regs): (String, Vec<u16>) = if is_static {
            (imports.use_type(&mref.class), regs.to_vec())
        } else if is_super {
            ("super".to_string(), regs.iter().skip(1).copied().collect())
        } else {
            let recv = regs.first().map(|&r| self.rn(r)).unwrap_or_default();
            (recv, regs.iter().skip(1).copied().collect())
        };
        let arglist = self.map_args(&arg_regs, &mref.params).join(", ");
        let call = format!("{receiver_part}.{}({arglist})", mref.name);
        let returns = mref.return_type != "void";
        if returns {
            self.assign_or_expr(call, next)
        } else {
            (vec![format!("{call};")], false)
        }
    }

    /// If `next` is a `move-result*`, assign `rhs` to it; else emit `rhs;`.
    fn assign_or_expr(&self, rhs: String, next: Option<&jadx_dex::Insn>) -> (Vec<String>, bool) {
        if let Some(n) = next {
            if matches!(n.opcode, 0x0a..=0x0c) {
                if let Some(&dst) = n.regs.first() {
                    return (vec![format!("{} = {rhs};", self.rn(dst))], true);
                }
            }
        }
        (vec![format!("{rhs};")], false)
    }

    fn map_args(&self, arg_regs: &[u16], param_types: &[String]) -> Vec<String> {
        let mut out = Vec::new();
        let mut ri = 0usize;
        for pty in param_types {
            if ri >= arg_regs.len() {
                break;
            }
            out.push(self.rn(arg_regs[ri]));
            ri += if is_wide_type(pty) { 2 } else { 1 };
        }
        while ri < arg_regs.len() {
            out.push(self.rn(arg_regs[ri]));
            ri += 1;
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

fn reg_name(is_static: bool, this_reg: Option<u16>, r: u16) -> String {
    if !is_static && this_reg == Some(r) {
        "this".to_string()
    } else {
        format!("v{r}")
    }
}

fn compute_param_regs(
    mref: &jadx_dex::MethodRef,
    registers_size: u16,
    ins_size: u16,
    is_static: bool,
) -> (Option<u16>, Vec<(u16, String)>) {
    let param_base = registers_size.saturating_sub(ins_size);
    let this_reg = if is_static { None } else { Some(param_base) };
    let mut reg = param_base + if is_static { 0 } else { 1 };
    let mut out = Vec::new();
    for p in &mref.params {
        out.push((reg, p.clone()));
        reg += if is_wide_type(p) { 2 } else { 1 };
    }
    (this_reg, out)
}

fn infer_param_regs_no_code(
    mref: &jadx_dex::MethodRef,
    is_static: bool,
) -> Vec<(u16, String)> {
    let mut reg = if is_static { 0 } else { 1 };
    let mut out = Vec::new();
    for p in &mref.params {
        out.push((reg, p.clone()));
        reg += if is_wide_type(p) { 2 } else { 1 };
    }
    out
}

fn param_register_set(code: &jadx_dex::CodeItem, is_static: bool) -> HashSet<u16> {
    let mut set = HashSet::new();
    let base = code.registers_size.saturating_sub(code.ins_size);
    for r in base..code.registers_size {
        set.insert(r);
    }
    let _ = is_static;
    set
}

fn infer_types(dex: &DexFile, ir: &ir::MethodIr) -> HashMap<u16, String> {
    let mut types: HashMap<u16, String> = HashMap::new();
    for b in &ir.cfg.blocks {
        for insn in &b.insns {
            if let Some(r) = ir::ssa::def_reg(insn) {
                let cand = candidate_type(dex, insn);
                let entry = types.entry(r).or_insert_with(|| "int".to_string());
                if entry == "int" && cand != "int" {
                    *entry = cand;
                }
            }
        }
    }
    types
}

fn candidate_type(dex: &DexFile, insn: &jadx_dex::Insn) -> String {
    let op = insn.opcode;
    match op {
        0x1a | 0x1b => "java.lang.String".to_string(),
        0x1c => "java.lang.Class".to_string(),
        0x12..=0x15 => "int".to_string(),
        0x16..=0x19 => "long".to_string(),
        0x04..=0x06 => "long".to_string(),
        0x07..=0x09 => "java.lang.Object".to_string(),
        0x22 | 0x1f => dex.type_name(insn.index),
        0x23 => dex.type_name(insn.index),
        0x20 | 0x21 => "int".to_string(),
        0x53 | 0x61 => "long".to_string(),
        0x54 | 0x62 => dex.field_ref(insn.index).field_type,
        0x52 | 0x55..=0x58 | 0x60 | 0x63..=0x66 => dex.field_ref(insn.index).field_type,
        0x45 => "long".to_string(),
        0x46 => "java.lang.Object".to_string(),
        0x44 | 0x47..=0x4a => "int".to_string(),
        _ => {
            if insn.name.contains("-long") || insn.name.contains("long/") {
                "long".to_string()
            } else if insn.name.contains("-double") || insn.name.contains("double/") {
                "double".to_string()
            } else if insn.name.contains("-float") || insn.name.contains("float/") {
                "float".to_string()
            } else {
                "int".to_string()
            }
        }
    }
}

fn collect_region_blocks(region: &Region, out: &mut HashSet<usize>) {
    match region {
        Region::Block(id) | Region::Goto(id) => {
            out.insert(*id);
        }
        Region::Seq(items) => items.iter().for_each(|r| collect_region_blocks(r, out)),
        Region::If {
            cond_block,
            then_branch,
            else_branch,
        } => {
            out.insert(*cond_block);
            collect_region_blocks(then_branch, out);
            if let Some(eb) = else_branch {
                collect_region_blocks(eb, out);
            }
        }
        Region::Loop { header, body } => {
            out.insert(*header);
            collect_region_blocks(body, out);
        }
        Region::Switch { block, cases } => {
            out.insert(*block);
            for c in cases {
                collect_region_blocks(&c.body, out);
            }
        }
        Region::Break | Region::Continue | Region::Empty => {}
    }
}

fn is_wide_type(t: &str) -> bool {
    t == "long" || t == "double"
}

fn default_value(ty: &str) -> &'static str {
    match ty {
        "boolean" => "false",
        "byte" | "short" | "int" | "char" => "0",
        "long" => "0L",
        "float" => "0.0f",
        "double" => "0.0",
        _ => {
            if is_primitive(ty) {
                "0"
            } else {
                "null"
            }
        }
    }
}

fn op_symbol(name: &str) -> &'static str {
    let base = name.split(['-', '/']).next().unwrap_or(name);
    match base {
        "add" => "+",
        "sub" | "rsub" => "-",
        "mul" => "*",
        "div" => "/",
        "rem" => "%",
        "and" => "&",
        "or" => "|",
        "xor" => "^",
        "shl" => "<<",
        "shr" => ">>",
        "ushr" => ">>>",
        _ => "+",
    }
}

fn conversion_target(name: &str) -> &'static str {
    // names like "int-to-long", "double-to-int", "int-to-byte"
    let target = name.rsplit("-to-").next().unwrap_or("int");
    match target {
        "long" => "long",
        "int" => "int",
        "float" => "float",
        "double" => "double",
        "byte" => "byte",
        "char" => "char",
        "short" => "short",
        _ => "int",
    }
}

fn escape_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Annotation emission.
// ---------------------------------------------------------------------------

/// Render the user annotations in `anns` as source lines at `pad`, one per line
/// (system / synthetic annotations are filtered out). Types are routed through
/// the imports manager so `@Foo` resolves correctly.
fn render_annotations(
    dex: &DexFile,
    anns: &[jadx_dex::annotation::Annotation],
    pad: &str,
    imports: &mut Imports,
    out: &mut String,
) {
    for ann in dex.user_annotations(anns) {
        let ty = imports.use_type(&ann.type_name);
        out.push_str(pad);
        out.push('@');
        out.push_str(&ty);
        if !ann.elements.is_empty() {
            out.push('(');
            // A single element named "value" is rendered without the name=.
            if ann.elements.len() == 1 && ann.elements[0].0 == "value" {
                out.push_str(&ann.elements[0].1.to_string());
            } else {
                let parts: Vec<String> = ann
                    .elements
                    .iter()
                    .map(|(name, val)| format!("{name} = {val}"))
                    .collect();
                out.push_str(&parts.join(", "));
            }
            out.push(')');
        }
        out.push('\n');
    }
}

// ---------------------------------------------------------------------------
// Generics: JLS signature-grammar parser + Java rendering.
//
// Parses the `dalvik.annotation.Signature` payload (a JVM generic signature)
// and re-renders type arguments, type parameters, and wildcards. Any parse
// failure returns `None`, and callers fall back to the erased rendering — the
// parser never panics and never produces partial garbage.
// ---------------------------------------------------------------------------

/// A formal type parameter: `T extends Bound & Bound2`.
struct TypeParam {
    name: String,
    bounds: Vec<JType>,
}

/// A parsed (possibly generic) JVM type from a signature.
enum JType {
    /// Primitive or `void` (single descriptor char).
    Prim(String),
    /// A class type, dotted, with optional type arguments and `$`-inner chains.
    Class { name: String, args: Vec<TypeArg> },
    /// A type variable (`T`).
    Var(String),
    /// An array of the inner type.
    Array(Box<JType>),
}

/// A type argument inside `<...>`.
enum TypeArg {
    Type(JType),
    ExtendsWild(JType),
    SuperWild(JType),
    Unbounded, // `*` -> `?`
}

struct SigParser<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> SigParser<'a> {
    fn new(s: &'a str) -> Self {
        SigParser {
            b: s.as_bytes(),
            i: 0,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let c = self.b.get(self.i).copied();
        if c.is_some() {
            self.i += 1;
        }
        c
    }

    fn eat(&mut self, c: u8) -> Result<(), ()> {
        if self.peek() == Some(c) {
            self.i += 1;
            Ok(())
        } else {
            Err(())
        }
    }

    /// `<` FormalTypeParameter+ `>` (optional).
    fn formal_type_params(&mut self) -> Result<Vec<TypeParam>, ()> {
        if self.peek() != Some(b'<') {
            return Ok(Vec::new());
        }
        self.bump();
        let mut params = Vec::new();
        while self.peek() != Some(b'>') {
            if self.peek().is_none() {
                return Err(());
            }
            params.push(self.formal_type_param()?);
        }
        self.eat(b'>')?;
        Ok(params)
    }

    fn formal_type_param(&mut self) -> Result<TypeParam, ()> {
        // Identifier up to ':'.
        let start = self.i;
        while let Some(c) = self.peek() {
            if c == b':' {
                break;
            }
            self.i += 1;
        }
        if self.i == start || self.peek() != Some(b':') {
            return Err(());
        }
        let name = std::str::from_utf8(&self.b[start..self.i])
            .map_err(|_| ())?
            .to_string();
        let mut bounds = Vec::new();
        // First `:` is the class bound (may be empty: `T:` then interface bounds).
        self.eat(b':')?;
        if self.peek() != Some(b':') && self.peek() != Some(b'>') && self.peek().is_some() {
            // A class bound is present unless immediately another ':'.
            if matches!(self.peek(), Some(b'L') | Some(b'T') | Some(b'[')) {
                bounds.push(self.field_type()?);
            }
        }
        // Interface bounds: each prefixed with ':'.
        while self.peek() == Some(b':') {
            self.bump();
            bounds.push(self.field_type()?);
        }
        Ok(TypeParam { name, bounds })
    }

    /// A `TypeSignature` used for fields, args, type args (reference or prim).
    fn field_type(&mut self) -> Result<JType, ()> {
        match self.peek() {
            Some(b'[') => {
                self.bump();
                let inner = self.field_type()?;
                Ok(JType::Array(Box::new(inner)))
            }
            Some(b'T') => {
                self.bump();
                let start = self.i;
                while let Some(c) = self.peek() {
                    if c == b';' {
                        break;
                    }
                    self.i += 1;
                }
                let name = std::str::from_utf8(&self.b[start..self.i])
                    .map_err(|_| ())?
                    .to_string();
                self.eat(b';')?;
                Ok(JType::Var(name))
            }
            Some(b'L') => self.class_type(),
            Some(c) if is_prim_desc(c) => {
                self.bump();
                Ok(JType::Prim((c as char).to_string()))
            }
            _ => Err(()),
        }
    }

    /// `L` PackageSpec ClassName TypeArgs? (`.` Inner TypeArgs?)* `;`
    fn class_type(&mut self) -> Result<JType, ()> {
        self.eat(b'L')?;
        let mut name = String::new();
        let mut args: Vec<TypeArg> = Vec::new();
        loop {
            let start = self.i;
            while let Some(c) = self.peek() {
                if matches!(c, b'<' | b';' | b'.') {
                    break;
                }
                self.i += 1;
            }
            let seg = std::str::from_utf8(&self.b[start..self.i]).map_err(|_| ())?;
            if !name.is_empty() {
                name.push('.'); // inner-class separator; rendered later
            }
            name.push_str(seg);
            // Type arguments for this segment (only the outermost are kept for
            // rendering; inner args replace any earlier ones, mirroring jadx's
            // simple inner-class handling).
            if self.peek() == Some(b'<') {
                args = self.type_args()?;
            }
            match self.peek() {
                Some(b'.') => {
                    self.bump();
                    continue;
                }
                Some(b';') => {
                    self.bump();
                    break;
                }
                None => return Err(()),
                _ => return Err(()),
            }
        }
        Ok(JType::Class { name, args })
    }

    fn type_args(&mut self) -> Result<Vec<TypeArg>, ()> {
        self.eat(b'<')?;
        let mut out = Vec::new();
        while self.peek() != Some(b'>') {
            match self.peek() {
                None => return Err(()),
                Some(b'*') => {
                    self.bump();
                    out.push(TypeArg::Unbounded);
                }
                Some(b'+') => {
                    self.bump();
                    out.push(TypeArg::ExtendsWild(self.field_type()?));
                }
                Some(b'-') => {
                    self.bump();
                    out.push(TypeArg::SuperWild(self.field_type()?));
                }
                _ => out.push(TypeArg::Type(self.field_type()?)),
            }
        }
        self.eat(b'>')?;
        Ok(out)
    }
}

fn is_prim_desc(c: u8) -> bool {
    matches!(
        c,
        b'V' | b'Z' | b'B' | b'S' | b'C' | b'I' | b'J' | b'F' | b'D'
    )
}

fn prim_to_java(c: &str) -> &'static str {
    match c {
        "V" => "void",
        "Z" => "boolean",
        "B" => "byte",
        "S" => "short",
        "C" => "char",
        "I" => "int",
        "J" => "long",
        "F" => "float",
        "D" => "double",
        _ => "int",
    }
}

/// Render a parsed `JType` to Java source, routing class names through imports.
fn render_jtype(t: &JType, imports: &mut Imports) -> String {
    match t {
        JType::Prim(c) => prim_to_java(c).to_string(),
        JType::Var(name) => name.clone(),
        JType::Array(inner) => format!("{}[]", render_jtype(inner, imports)),
        JType::Class { name, args } => {
            // `name` uses `.` for both package and inner-class separators; the
            // imports manager resolves it as a dotted FQN (inner classes render
            // with their dotted tail, matching the erased path's simple_name).
            let dotted = name.replace('/', ".");
            let base = imports.use_type(&dotted);
            if args.is_empty() {
                base
            } else {
                let rendered: Vec<String> =
                    args.iter().map(|a| render_type_arg(a, imports)).collect();
                format!("{base}<{}>", rendered.join(", "))
            }
        }
    }
}

fn render_type_arg(a: &TypeArg, imports: &mut Imports) -> String {
    match a {
        TypeArg::Type(t) => render_jtype(t, imports),
        TypeArg::ExtendsWild(t) => format!("? extends {}", render_jtype(t, imports)),
        TypeArg::SuperWild(t) => format!("? super {}", render_jtype(t, imports)),
        TypeArg::Unbounded => "?".to_string(),
    }
}

/// Render a formal type-parameter list `<T extends X, U>` (empty -> "").
fn render_type_params(params: &[TypeParam], imports: &mut Imports) -> String {
    if params.is_empty() {
        return String::new();
    }
    let parts: Vec<String> = params
        .iter()
        .map(|p| {
            // A leading bound of `java.lang.Object` is the implicit default and
            // is omitted, matching idiomatic Java output.
            let bounds: Vec<String> = p
                .bounds
                .iter()
                .map(|b| render_jtype(b, imports))
                .filter(|b| b != "java.lang.Object" && b != "Object")
                .collect();
            if bounds.is_empty() {
                p.name.clone()
            } else {
                format!("{} extends {}", p.name, bounds.join(" & "))
            }
        })
        .collect();
    format!("<{}>", parts.join(", "))
}

/// Generic class-header pieces parsed from a class signature.
struct ClassHeaderGenerics {
    type_params: String,
    superclass: Option<String>,
    interfaces: Vec<String>,
}

/// Parse a class signature into rendered header pieces. Returns `None` on any
/// parse error so the caller falls back to erased rendering.
fn parse_class_header(sig: &str, imports: &mut Imports) -> Option<ClassHeaderGenerics> {
    let mut p = SigParser::new(sig);
    let params = p.formal_type_params().ok()?;
    // SuperclassSignature.
    let superclass = match p.field_type() {
        Ok(t) => Some(render_jtype(&t, imports)),
        Err(_) => return None,
    };
    // SuperinterfaceSignature* until end.
    let mut interfaces = Vec::new();
    while p.peek().is_some() {
        match p.field_type() {
            Ok(t) => interfaces.push(render_jtype(&t, imports)),
            Err(_) => return None,
        }
    }
    Some(ClassHeaderGenerics {
        type_params: render_type_params(&params, imports),
        superclass,
        interfaces,
    })
}

/// Generic method pieces parsed from a method signature.
struct MethodGenerics {
    type_params: String,
    params: Vec<String>,
    return_type: String,
}

/// Parse a method signature `<...>(args)ret` into rendered pieces.
fn parse_method_generics(sig: &str, imports: &mut Imports) -> Option<MethodGenerics> {
    let mut p = SigParser::new(sig);
    let tparams = p.formal_type_params().ok()?;
    p.eat(b'(').ok()?;
    let mut params = Vec::new();
    while p.peek() != Some(b')') {
        if p.peek().is_none() {
            return None;
        }
        match p.field_type() {
            Ok(t) => params.push(render_jtype(&t, imports)),
            Err(_) => return None,
        }
    }
    p.eat(b')').ok()?;
    let ret = p.field_type().ok()?;
    Some(MethodGenerics {
        type_params: render_type_params(&tparams, imports),
        params,
        return_type: render_jtype(&ret, imports),
    })
}

/// Parse a single field type signature, rendered to Java. `None` on error.
fn parse_field_type(sig: &str, imports: &mut Imports) -> Option<String> {
    let mut p = SigParser::new(sig);
    let t = p.field_type().ok()?;
    // Trailing junk means the signature was not a clean field type; bail.
    if p.peek().is_some() {
        return None;
    }
    Some(render_jtype(&t, imports))
}
