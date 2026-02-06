//! Native eframe/egui GUI — the Lancer-standard three-pane layout.
//!
//! Left: inputs/jobs. Center: tabbed result views (source tree, findings,
//! strings, manifest). Right: detail pane (selected source / finding). Top:
//! menu bar. Bottom: status bar with primary actions. Long-running decompiles
//! run on a worker thread; results return via an mpsc channel so the egui
//! thread never blocks.

#![cfg(feature = "gui")]

use crate::http_server::{self, SharedState, StateHandle};
use eframe::egui;
use jadx_core::report::Finding;
use jadx_core::{Jadx, JadxArgs};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};

/// Launch the GUI window.
pub fn launch() -> anyhow::Result<()> {
    let state: StateHandle = Arc::new(Mutex::new(SharedState {
        status: "idle".to_string(),
        ..Default::default()
    }));
    let port = http_server::start(state.clone()).unwrap_or(0);

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 800.0])
            .with_min_inner_size([800.0, 500.0])
            .with_title("lancer-jadx"),
        ..Default::default()
    };

    eframe::run_native(
        "lancer-jadx",
        native_options,
        Box::new(move |_cc| Box::new(JadxApp::new(state.clone(), port))),
    )
    .map_err(|e| anyhow::anyhow!("GUI error: {e}"))
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum Tab {
    Tree,
    Findings,
    Strings,
    Manifest,
}

/// A decompiled class summary for the source tree.
struct ClassEntry {
    name: String,
    package: String,
    source: String,
}

/// Result payload produced by the worker thread.
struct LoadResult {
    input: String,
    classes: Vec<ClassEntry>,
    findings: Vec<Finding>,
    strings_json: String,
    manifest: Option<String>,
    tree_json: String,
    error: Option<String>,
}

enum WorkerMsg {
    Done(Box<LoadResult>),
    Progress(String),
}

struct JadxApp {
    state: StateHandle,
    port: u16,

    inputs: Vec<PathBuf>,
    active_tab: Tab,

    classes: Vec<ClassEntry>,
    findings: Vec<Finding>,
    strings_json: String,
    manifest: Option<String>,

    selected_class: Option<usize>,
    selected_finding: Option<usize>,
    filter: String,
    kotlin: bool,
    deobf: bool,

    status: String,
    busy: bool,
    rx: Option<Receiver<WorkerMsg>>,
}

impl JadxApp {
    fn new(state: StateHandle, port: u16) -> Self {
        JadxApp {
            state,
            port,
            inputs: Vec::new(),
            active_tab: Tab::Tree,
            classes: Vec::new(),
            findings: Vec::new(),
            strings_json: String::new(),
            manifest: None,
            selected_class: None,
            selected_finding: None,
            filter: String::new(),
            kotlin: false,
            deobf: false,
            status: format!("idle — cross-tool port {port}"),
            busy: false,
            rx: None,
        }
    }

    fn open_dialog(&mut self) {
        if let Some(files) = rfd::FileDialog::new()
            .add_filter("Android / JVM", &["apk", "aab", "xapk", "dex", "odex", "aar", "jar", "class", "zip"])
            .pick_files()
        {
            self.inputs = files;
            self.run_decompile();
        }
    }

    fn run_decompile(&mut self) {
        if self.inputs.is_empty() || self.busy {
            return;
        }
        self.busy = true;
        self.status = "decompiling…".to_string();
        if let Ok(mut s) = self.state.lock() {
            s.status = "decompiling".to_string();
            s.current_input = self.inputs.first().map(|p| p.display().to_string());
        }

        let (tx, rx): (Sender<WorkerMsg>, Receiver<WorkerMsg>) = std::sync::mpsc::channel();
        self.rx = Some(rx);

        let mut args = JadxArgs::default();
        args.inputs = self.inputs.clone();
        args.kotlin = self.kotlin;
        args.deobf = self.deobf;

        std::thread::spawn(move || {
            let _ = tx.send(WorkerMsg::Progress("loading inputs".to_string()));
            let result = run_worker(args);
            let _ = tx.send(WorkerMsg::Done(Box::new(result)));
        });
    }

    fn poll_worker(&mut self) {
        let mut done_payload = None;
        if let Some(rx) = &self.rx {
            while let Ok(msg) = rx.try_recv() {
                match msg {
                    WorkerMsg::Progress(p) => self.status = p,
                    WorkerMsg::Done(r) => done_payload = Some(r),
                }
            }
        }
        if let Some(r) = done_payload {
            self.apply_result(*r);
            self.rx = None;
            self.busy = false;
        }
    }

    fn apply_result(&mut self, r: LoadResult) {
        if let Some(err) = r.error {
            self.status = format!("error: {err}");
            return;
        }
        self.status = format!(
            "{} classes · {} findings",
            r.classes.len(),
            r.findings.len()
        );
        if let Ok(mut s) = self.state.lock() {
            s.status = "done".to_string();
            s.item_count = r.classes.len();
            s.current_input = Some(r.input.clone());
            s.export_json = r.tree_json.clone();
        }
        self.classes = r.classes;
        self.findings = r.findings;
        self.strings_json = r.strings_json;
        self.manifest = r.manifest;
        self.selected_class = None;
        self.selected_finding = None;
    }

    fn export_dialog(&self) {
        if let Some(path) = rfd::FileDialog::new()
            .add_filter("JSON", &["json"])
            .set_file_name("lancer-jadx-findings.json")
            .save_file()
        {
            let json = jadx_core::report::findings_json(&self.findings);
            let _ = std::fs::write(path, json);
        }
    }
}

fn run_worker(args: JadxArgs) -> LoadResult {
    let input = args
        .inputs
        .first()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    match Jadx::load(args) {
        Ok(jadx) => {
            let decompiled = jadx.decompile_all();
            let classes = decompiled
                .iter()
                .map(|c| ClassEntry {
                    name: c.simple_name.clone(),
                    package: c.package.clone(),
                    source: c.source.clone(),
                })
                .collect();
            LoadResult {
                input,
                classes,
                findings: jadx.run_findings(),
                strings_json: jadx.extract_strings_json(),
                manifest: jadx.manifest_xml(),
                tree_json: jadx.tree_json(),
                error: None,
            }
        }
        Err(e) => LoadResult {
            input,
            classes: Vec::new(),
            findings: Vec::new(),
            strings_json: String::new(),
            manifest: None,
            tree_json: String::new(),
            error: Some(e.to_string()),
        },
    }
}

impl eframe::App for JadxApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_worker();
        if self.busy {
            ctx.request_repaint();
        }

        self.top_menu(ctx);
        self.bottom_status(ctx);
        self.left_sidebar(ctx);
        self.right_detail(ctx);
        self.center_view(ctx);
    }
}

impl JadxApp {
    fn top_menu(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Open…").clicked() {
                        self.open_dialog();
                        ui.close_menu();
                    }
                    if ui.button("Export findings…").clicked() {
                        self.export_dialog();
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Quit").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });
                ui.menu_button("Tools", |ui| {
                    ui.checkbox(&mut self.kotlin, "Emit Kotlin");
                    ui.checkbox(&mut self.deobf, "Deobfuscate");
                    if ui.button("Re-run decompile").clicked() {
                        self.run_decompile();
                        ui.close_menu();
                    }
                });
                ui.menu_button("Settings", |ui| {
                    ui.label("Theme:");
                    egui::widgets::global_dark_light_mode_buttons(ui);
                });
                ui.menu_button("Help", |ui| {
                    ui.label("lancer-jadx");
                    ui.label(format!("version {}", env!("CARGO_PKG_VERSION")));
                    ui.label(format!("upstream parity: jadx {}", jadx_core::UPSTREAM_PARITY));
                    ui.label(format!("cross-tool port: {}", self.port));
                });
            });
        });
    }

    fn bottom_status(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(format!("Status: {}", self.status));
                ui.separator();
                ui.label(format!("Items: {}", self.classes.len()));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Export").clicked() {
                        self.export_dialog();
                    }
                    if ui.add_enabled(!self.busy, egui::Button::new("Run")).clicked() {
                        self.run_decompile();
                    }
                    if ui.button("Open").clicked() {
                        self.open_dialog();
                    }
                });
            });
        });
    }

    fn left_sidebar(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("inputs")
            .resizable(true)
            .default_width(240.0)
            .show(ctx, |ui| {
                ui.heading("Inputs");
                if ui.button("➕ Add input…").clicked() {
                    self.open_dialog();
                }
                ui.separator();
                if self.inputs.is_empty() {
                    ui.weak("Drag & drop or click Open.");
                }
                for inp in &self.inputs {
                    ui.label(
                        inp.file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("?")
                            .to_string(),
                    );
                }
                ui.separator();
                ui.heading("View");
                ui.selectable_value(&mut self.active_tab, Tab::Tree, "📦 Source tree");
                ui.selectable_value(&mut self.active_tab, Tab::Findings, "🛡 Findings");
                ui.selectable_value(&mut self.active_tab, Tab::Strings, "🔤 Strings");
                ui.selectable_value(&mut self.active_tab, Tab::Manifest, "📄 Manifest");

                // Accept dropped files.
                let dropped: Vec<PathBuf> = ctx.input(|i| {
                    i.raw
                        .dropped_files
                        .iter()
                        .filter_map(|f| f.path.clone())
                        .collect()
                });
                if !dropped.is_empty() {
                    self.inputs = dropped;
                    self.run_decompile();
                }
            });
    }

    fn center_view(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| match self.active_tab {
            Tab::Tree => self.view_tree(ui),
            Tab::Findings => self.view_findings(ui),
            Tab::Strings => self.view_strings(ui),
            Tab::Manifest => self.view_manifest(ui),
        });
    }

    fn view_tree(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Filter:");
            ui.text_edit_singleline(&mut self.filter);
        });
        ui.separator();
        let filter = self.filter.to_lowercase();
        egui::ScrollArea::vertical().show(ui, |ui| {
            for (i, c) in self.classes.iter().enumerate() {
                if !filter.is_empty()
                    && !c.name.to_lowercase().contains(&filter)
                    && !c.package.to_lowercase().contains(&filter)
                {
                    continue;
                }
                let label = format!("{}.{}", c.package, c.name);
                if ui
                    .selectable_label(self.selected_class == Some(i), label)
                    .clicked()
                {
                    self.selected_class = Some(i);
                }
            }
        });
    }

    fn view_findings(&mut self, ui: &mut egui::Ui) {
        ui.heading(format!("{} findings", self.findings.len()));
        ui.separator();
        egui::ScrollArea::vertical().show(ui, |ui| {
            for (i, f) in self.findings.iter().enumerate() {
                let text = format!("[{}] {} — {}:{}", f.category, f.message, f.file, f.line);
                if ui
                    .selectable_label(self.selected_finding == Some(i), text)
                    .clicked()
                {
                    self.selected_finding = Some(i);
                }
            }
        });
    }

    fn view_strings(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.monospace(&self.strings_json);
        });
    }

    fn view_manifest(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical().show(ui, |ui| match &self.manifest {
            Some(xml) => {
                ui.monospace(xml);
            }
            None => {
                ui.weak("No AndroidManifest.xml decoded.");
            }
        });
    }

    fn right_detail(&mut self, ctx: &egui::Context) {
        egui::SidePanel::right("detail")
            .resizable(true)
            .default_width(420.0)
            .show(ctx, |ui| {
                ui.heading("Detail");
                ui.separator();
                if let Some(i) = self.selected_finding {
                    if let Some(f) = self.findings.get(i) {
                        ui.label(format!("Rule: {}", f.rule_id));
                        ui.label(format!("Severity: {:?}", f.severity));
                        ui.label(format!("{}:{}", f.file, f.line));
                        ui.separator();
                        ui.monospace(&f.snippet);
                        return;
                    }
                }
                if let Some(i) = self.selected_class {
                    if let Some(c) = self.classes.get(i) {
                        ui.label(format!("{}.{}", c.package, c.name));
                        ui.separator();
                        egui::ScrollArea::vertical().show(ui, |ui| {
                            ui.monospace(&c.source);
                        });
                        return;
                    }
                }
                ui.weak("Select a class or finding.");
            });
    }
}
