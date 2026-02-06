# lancer-jadx

Rust clone of [`jadx`](https://github.com/skylot/jadx) — an Android **APK / DEX / AAR / JAR / class decompiler** (DEX → Java/Kotlin source). Part of the Lancer ecosystem, a 2026 AI-era bug-bounty toolkit. Targets upstream-jadx **1.5.5** feature parity plus a native Rust GUI.

## What it does

Given an `.apk`, `.aab`, `.xapk`, `.dex`, `.odex`, `.aar`, `.jar`, `.class`, or `.zip`, lancer-jadx:

- unpacks resources + bytecode (multi-dex and the Android 14+ DEX container format),
- parses the full DEX format and decodes the complete 256-opcode Dalvik instruction set,
- lowers each method through a CFG → SSA → loop/try/region pipeline,
- emits readable **Java** (or **Kotlin** with `--kotlin`),
- decodes binary resources (`AndroidManifest.xml` via AXML, `resources.arsc` via ARSC, `strings.xml`),
- runs an optional heuristic **deobfuscator** (with an AI-rename integration seam),
- builds a **cross-reference index** (callers, field readers/writers, subclasses, implementors),
- runs a **security findings** scan (80+ secret regexes, insecure-crypto / WebView / TLS / IPC / manifest matchers) with **SARIF** and **Quark** export.

## Workspace layout

| Crate | Role |
|-------|------|
| `lancer-jadx` | GUI binary (eframe/egui, 3-pane) + `--cli` passthrough + cross-tool HTTP server |
| `jadx-cli` | Upstream-compatible `jadx` CLI surface + Lancer subcommands; LSP + MCP servers; ships the `jadx` compat binary |
| `jadx-core` | Orchestration: input dispatch, Java/Kotlin codegen, deobf, xref, findings/report |
| `jadx-dex` | DEX parser + opcode decoder + IR (CFG / SSA / loops / try-regions / structuring) |
| `jadx-resources` | AXML (binary XML) + ARSC (`resources.arsc`) decoders + manifest reconstruction |

## CLI

A bare `lancer-jadx <input>` opens the **GUI**. For headless/CI use `--cli` (or any subcommand):

```
# Upstream-compatible decompile (all upstream flags supported)
lancer-jadx --cli decompile app.apk -d out/ --kotlin --deobf

# Lancer subcommands
lancer-jadx --cli extract-strings  app.apk --out strings.json
lancer-jadx --cli extract-manifest app.apk --out AndroidManifest.xml
lancer-jadx --cli find             app.apk --pattern 'addJavascriptInterface'
lancer-jadx --cli tree             app.apk --json
lancer-jadx --cli findings         app.apk --sarif            # or --quark
lancer-jadx --cli serve            --port 8081                # MCP server (JSON-RPC)
lancer-jadx --cli lsp                                         # LSP server over stdio
lancer-jadx --cli self-test                                  # parity matrix
```

The `jadx` compatibility binary (`jadx-cli`) accepts the upstream flag set directly
(`-d/--output-dir`, `-r/--no-res`, `-s/--no-src`, `--single-class`, `--output-format`,
`--show-bad-code`, `--no-imports`, `--no-debug-info`, `--deobf`, `--deobf-min/max`,
`--rename-flags`, `--threads-count`, `--export-gradle`, `--plugin-decompiler`, …).

## Build

### Windows
```
build.bat
```
Output: `build\lancer-jadx.exe` (double-click opens the GUI).

Packaged dist:
```
build-windows.bat
```

### Linux / macOS
```bash
./build-linux.sh
```
Output: `build/lancer-jadx`.

For a fast headless build without the GUI dependency tree:
```bash
cargo build --release -p lancer-jadx --no-default-features
```

### Requirements
- [Rust / Cargo](https://rustup.rs)
- (Windows) Visual C++ Build Tools 2019/2022

## Status

All five crates implemented and compiling (`cargo check --workspace` is green).
GUI parity with the full `jadx-gui`, R8 control-flow-flattening defeat, and the
external-decompiler plugin runtime are phase-2 items (see local `plan.md`).
