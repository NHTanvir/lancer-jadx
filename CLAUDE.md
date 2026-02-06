# CLAUDE.md

Guidance for Claude Code (and humans) working in this repository.

## What this is

`lancer-jadx` — A Rust clone of the popular `jadx` Android decompiler (targeting upstream jadx 1.5.5 feature parity), capable of decompiling APK, DEX, AAR, JAR, and class files into readable Java or Kotlin source. It is part of the Lancer 2026 AI-era bug-bounty toolkit, providing both a native egui GUI and a full headless CLI surface. Beyond decompilation it includes security-findings scanning (80+ secret regexes, SARIF/Quark export), a cross-reference index, deobfuscation, and optional LSP/MCP server modes.

## Architecture

This is a Cargo workspace with five crates:

- `lancer-jadx/src/main.rs` — binary entry point; launches egui GUI or delegates to `--cli`
- `lancer-jadx/src/gui.rs` — 3-pane egui/eframe desktop GUI (feature-gated behind `gui`)
- `lancer-jadx/src/http_server.rs` — cross-tool HTTP server for inter-process communication
- `jadx-cli/src/lib.rs` — upstream-compatible `jadx` CLI surface plus Lancer subcommands
- `jadx-cli/src/bin/jadx.rs` — `jadx` compatibility binary (accepts upstream flag set)
- `jadx-cli/src/server/lsp.rs` — LSP server implementation (stdio)
- `jadx-cli/src/server/mcp.rs` — MCP server implementation (JSON-RPC over HTTP)
- `jadx-core/src/lib.rs` — orchestration: input dispatch, Java/Kotlin codegen, deobf, xref, findings/report
- `jadx-core/src/decompiler.rs` — core decompilation pipeline
- `jadx-core/src/codegen/` — Java and Kotlin code emitters
- `jadx-core/src/deobf/` — heuristic deobfuscator with AI-rename integration seam
- `jadx-core/src/xref/` — cross-reference index (callers, field readers/writers, subclasses)
- `jadx-core/src/report/` — SARIF and Quark findings export
- `jadx-dex/src/lib.rs` — DEX parser, opcode decoder, and IR (CFG/SSA/loops/try-regions/structuring)
- `jadx-dex/src/dexfile.rs` — DEX file format parsing
- `jadx-dex/src/insn.rs` — full 256-opcode Dalvik instruction set decoder
- `jadx-dex/src/ir/` — CFG → SSA → loop/try/region IR pipeline
- `jadx-resources/src/lib.rs` — AXML binary XML + ARSC resources.arsc decoders
- `jadx-resources/src/axml.rs` — binary AndroidManifest.xml decoder
- `jadx-resources/src/arsc.rs` — resources.arsc decoder
- `jadx-resources/src/manifest.rs` — manifest reconstruction

## Conventions

- Error propagation uses `anyhow::Result`; no `unwrap`/`expect` on fallible I/O.
- GUI is gated behind the default `gui` feature; `--no-default-features` builds a headless CLI binary.
- Library code lives in `src/lib.rs` within each crate; binary entry points in `src/main.rs` or `src/bin/`.
- Workspace-level dependency versions are pinned in the root `Cargo.toml`; crates reference them via `workspace = true`.
- The `jadx` compat binary (`jadx-cli`) must accept the full upstream flag set without breaking changes.
- Security findings scanning uses `regex` + `aho-corasick` for performance; new secret patterns go in `jadx-core/src/report/`.

## Build / test / run

```
build.bat                   # Windows → build\lancer-jadx.exe
build-windows.bat           # Windows packaged dist
./build-linux.sh            # Linux/macOS
cargo build --release       # standard release build
cargo build --release -p lancer-jadx --no-default-features   # headless CLI, no GUI deps
cargo test                  # unit + integration tests
```

## Repo notes

- `plan.md` is local-only and must NOT be committed. It is gitignored; if ever tracked, run `git rm --cached plan.md`.
- `.claude/` and `target/`/`build/`/`dist/` are local-only and gitignored.
