# RESEARCH DOSSIER: jadx

> Part of the Lancer ecosystem. A Rust clone of skylot/jadx — DEX → Java/Kotlin decompiler. Build with Claude Code.
> Upstream: github.com/skylot/jadx (Java, Apache-2.0, 1.4.x → 1.5.x as of 2026). The de-facto Android APK reverse-engineering tool.

## Feature Parity Mandate

**`lancer-jadx` MUST ship with 100% feature parity to the upstream `jadx` tool — every flag, every subcommand, every output format, every probe / detector / module / payload / mode — plus a native Rust GUI on top.** This is not a "subset clone" — this is a full reimplementation in Rust with a GUI wrapper.

### Parity contract

- **Every CLI flag** documented in upstream `jadx --help` (and the long-form man page / docs) must work in `lancer-jadx --cli`.
- **Every output format** the upstream tool emits (text, JSON, XML, CSV, SARIF, custom formats) must round-trip through `lancer-jadx` byte-equivalent where the format allows.
- **Every probe / detector / module / category / payload class / built-in script** must be ported. None silently dropped.
- **Every supported target type / input format / protocol / file format / language** must work.
- **Every configuration option** (config files, env vars, registry / settings entries) must be honoured.
- **Companion binaries / sub-tools** in the upstream suite (if any) must each get their own binary in this workspace.

### GUI on top

Every feature reachable via CLI is also reachable from the GUI (see `## GUI (Lancer-standard pattern)` below). The GUI is not a subset — it is an alternate frontend over the same `core` library that the CLI uses. The `core` crate is GUI-agnostic.

### Verification

- The `## Granular feature catalog` section below enumerates everything that must be supported.
- Reference: `tests/upstream_parity/` will pin upstream flag combinations + canned outputs as parity tests. CI fails if any flag is unsupported or output diverges.
- A `lancer-jadx --self-test` flag runs the full parity matrix against a bundled reference target and prints pass/fail per upstream feature group.

### What is allowed to diverge

- **Performance** — Rust-native, async-first; we are allowed to be faster.
- **Memory footprint** — we are allowed to be smaller.
- **GUI** — entirely new (no upstream GUI to copy except where the upstream ships its own GUI like Zenmap / Wireshark UI / Ghidra GUI / jadx-gui — in which case our GUI must cover every panel the upstream GUI has, plus the Lancer-standard layout from `## GUI` below).
- **AI augmentation** — net-new (see `## AI augmentation ideas`).

### What is NOT allowed to diverge

- Any flag silently dropped, renamed, or behavior-changed compared to upstream.
- Any output format / record schema diverging in field names, types, or semantics.
- Any built-in script / detector / module not ported (mark explicitly with `[N/A — see note]` if genuinely impossible in Rust, e.g. NSE Lua scripts requiring features not in `mlua`).

## What it actually does

jadx is an Android APK / DEX / AAR / JAR / class decompiler. Given an `.apk`, `.dex`, `.aar`, `.jar`, or `.class` input, it unpacks resources + bytecode, translates DEX → Java AST → Java source, optionally re-translates Java AST → Kotlin source, emits a browsable source tree with cross-references, decodes binary resources (`AndroidManifest.xml`, `resources.arsc`, `strings.xml`), runs an optional deobfuscation pass that renames `a`/`aa`/`a$$b` style obfuscated identifiers to semantic names, and ships both a CLI (`jadx`) for batch decompilation and a Swing GUI (`jadx-gui`) for interactive RE.

Reverse engineers reach for jadx as the first stop when auditing an APK — it is the primary "what does this APK actually do" tool. It is faster than baksmali + back-and-forth source reading, it understands enough of the bytecode-level idioms to produce readable Java even on heavily-obfuscated apps, and it cross-references everything so you can pivot from a string literal to its caller to the manifest entry to the WebView bridge in seconds.

## Internal architecture

**Workspace** (`Cargo.toml`):
```
[workspace]
members = ["lancer-jadx", "jadx-core", "jadx-dex", "jadx-cli", "jadx-resources"]
```

- **`lancer-jadx`** — CLI binary (clap 4). `lancer-jadx decompile <input> --out <dir>`, `--kotlin`, `--deobfuscate`, `--ai-rename`, `--json-tree`, `--lsp`, `--mcp`.
- **`jadx-cli`** — Compatibility alias matching upstream `jadx` CLI surface so existing jadx wrappers keep working as drop-in.
- **`jadx-core`** — Orchestration: input dispatch (APK/DEX/AAR/JAR/CLASS), Java AST → source renderer, Kotlin transformer, deobfuscator, symbol table, cross-reference index, findings emitter, report formatters.
- **`jadx-dex`** — DEX bytecode parser + DEX → high-level Java IR + control-flow recovery + try/catch reconstruction + register-pair resolution. This is the hard part.
- **`jadx-resources`** — AXML (binary XML) decoder, ARSC (resources.arsc) decoder, manifest reconstructor.

**Key modules in `jadx-core/src/`:**
- `input/`
  - `apk.rs` — APK reader (zip + AndroidManifest decode via AXML parser, classes*.dex enumeration for multi-dex).
  - `dex.rs` — DEX container reader (header, string_ids, type_ids, proto_ids, field_ids, method_ids, class_defs, code_items, debug_info_items).
  - `aar.rs`, `jar.rs`, `class.rs` — JVM classfile reader (constant pool, attributes, code).
- `ir/`
  - `instruction.rs` — High-level Java IR after DEX → Java lowering. Each `InsnNode` carries opcode, args, source line, type info.
  - `block.rs` — Basic-block graph + dominator tree + post-dominator tree.
  - `ssa.rs` — SSA form for variable rename, dead-code elimination, copy propagation.
  - `tryblock.rs` — Try/catch handler reconstruction (DEX uses linear `try_item` / `catch_handler` tables — recover lexical structure).
  - `loop.rs` — Loop nesting recovery from CFG (Ramalingam/Havlak).
  - `region.rs` — Structured-control-flow region tree (if/else, while, for, switch).
- `codegen/`
  - `java/` — Java source emitter (uses a `prettyplease`-style printer with explicit indentation).
  - `kotlin/` — Kotlin source emitter (translates Java idioms to Kotlin: getters/setters → properties, `for` loops → `forEach`, anonymous-class lambdas → trailing-lambda syntax).
- `deobf/`
  - `rename.rs` — Heuristic rename (`a` → `cls0`, `b` → `cls1`; strip `$` proxies; expand inner-class names; pseudo-package collapse).
  - `ai_rename.rs` — Optional `lancer-ai` integration: feed each method body + surrounding context to LLM, accept a semantic rename suggestion.
- `xref/`
  - `index.rs` — Cross-reference table: who-calls-X, who-reads-field-X, who-extends-class-X, who-implements-interface-X.
- `report/`
  - `tree.rs` — JSON tree of the decompiled package (for Lancer GUI consumption).
  - `findings.rs` — Highlight insecure patterns (hardcoded keys, `Cipher.getInstance("DES")`, `WebView.addJavascriptInterface`, `setJavaScriptEnabled(true)`, etc.).

**How a decompile runs end-to-end:**
1. `input::apk::open` discovers all `classes*.dex` (multi-dex), `AndroidManifest.xml`, `resources.arsc`, asset blobs.
2. `jadx-dex` parses each DEX, builds a typed view of every class/method/field.
3. For each method: bytecode → linear IR → basic blocks → SSA → simplifications → region tree.
4. `codegen::java` walks the region tree per method, emits Java text.
5. If `--kotlin`, the Java AST is run through `codegen::kotlin` which pattern-rewrites.
6. `deobf` runs (heuristic + optional AI pass).
7. `xref` indexes the final source so the GUI can pivot.
8. `report::tree` emits a JSON tree to disk; `report::findings` writes a SARIF/JSON list of insecure patterns.

## Granular feature catalog

**Inputs:** `.apk`, `.aab` (Android App Bundle), `.xapk`, `.dex` (single + multi-dex `classes2.dex`, `classes3.dex` …), `.odex` (with deps), `.aar` (Android library), `.jar` (any JVM), `.class` (single class), `.zip` containing any combination.

**Outputs:** Java source tree, Kotlin source tree (`--kotlin`), Smali listing (`--export-gradle` ships smali), JSON package tree (`--json-tree`), SARIF findings report, decoded `AndroidManifest.xml`, decoded `strings.xml` / `dimens.xml` / `colors.xml` / `arrays.xml`, image assets passed through.

**CLI surface (compatibility mode):**
- `-d`, `--output-dir <dir>` — output directory.
- `-r`, `--no-res` — skip resources.
- `-s`, `--no-src` — skip sources.
- `--single-class <class>` — decompile only one class.
- `--single-class-output <file>` — write that class to one file.
- `--output-format {java,json}` — emit format.
- `--show-bad-code` — emit even failed-to-decompile fragments.
- `--no-imports` — inline fully-qualified names.
- `--no-debug-info` — drop debug line numbers.
- `--add-debug-lines` — annotate output with original DEX offsets.
- `--no-inline-anonymous` — keep anonymous inner classes as separate classes.
- `--no-inline-methods` — disable method inlining.
- `--no-replace-consts` — keep numeric constants unreplaced by named symbols.
- `--escape-unicode` — escape non-ASCII identifiers.
- `--respect-bytecode-access-modifiers` — don't widen visibility.
- `--deobf` — enable deobfuscation.
- `--deobf-min <N>`, `--deobf-max <N>` — name-length bounds for deobfuscation candidacy.
- `--deobf-rewrite-cfg` — persist deobf mapping for re-runs.
- `--deobf-use-sourcename` — pull names from DEX debug info when available.
- `--rename-flags {none,all,case,valid,printable}` — which identifiers to rewrite.
- `--fs-case-sensitive` — assume case-sensitive FS (matters on Windows).
- `--cfg`, `--raw-cfg` — emit per-method control-flow graphs (dot).
- `--threads-count <N>` — parallelism.
- `--verbose`, `--quiet`.
- `--export-gradle` — emit a buildable Gradle project skeleton with the recovered sources.
- `--use-dx` — pre-process via dx (older DEX dialects).
- `--decode-resources` / `--no-decode-resources`.
- `--plugins-options <key=val,…>` — pass plugin opts (Kotlin metadata plugin, etc.).

**Lancer-additional CLI:**
- `lancer-jadx decompile <input>     --out <dir> [--kotlin] [--deobfuscate] [--ai-rename]`
- `lancer-jadx extract-strings <apk> --out strings.json`
- `lancer-jadx extract-manifest <apk> --out AndroidManifest.xml`
- `lancer-jadx find <apk> --pattern '<regex>'   # search decompiled body`
- `lancer-jadx tree <apk> --json                # emit package tree`
- `lancer-jadx findings <apk> --sarif           # emit findings as SARIF for GitHub code scanning`
- `lancer-jadx serve --port 8081                # MCP server for Claude/Cursor`
- `lancer-jadx lsp                              # LSP server over stdio`

**Analyzers / passes (run in this order):**
1. DEX parser (header, pools, class_defs).
2. Bytecode decoder (`InsnDecoder`) — 250+ DEX opcodes.
3. Register typing (infer Java types for every virtual register).
4. Linear IR builder.
5. CFG builder.
6. SSA construction with phi insertion (Cytron et al.).
7. Try/catch table → lexical try-blocks (handler ranges → nested try regions).
8. Loop recovery (natural loops; irreducible loops handled via Havlak).
9. Switch recovery (`packed-switch-payload` / `sparse-switch-payload`).
10. Constant inlining.
11. Inline small accessor methods.
12. Anonymous class inlining (synthetic `$1` inner classes).
13. Generic-signature recovery from `Signature` attribute when present, otherwise leave erased.
14. String constant deduplication and `R.string.*` resolution against ARSC.
15. Java emit (region walk → printer).
16. Optional: Java → Kotlin transformer.
17. Optional: heuristic deobfuscator.
18. Optional: AI rename pass (LLM-suggested semantic names; user can accept/reject).
19. Optional: findings scan (regex + AST pattern matchers).

**Built-in findings rules:**
- Hardcoded high-entropy strings (Shannon entropy > 4.5 over ≥20 chars).
- Hardcoded AWS/Stripe/Slack/GitHub/Firebase keys (regex set, ~80 patterns).
- `Cipher.getInstance("DES")` / `"RC4"` / `"AES/ECB/…"` / `"AES/CBC/NoPadding"`.
- `MessageDigest.getInstance("MD5")` / `"SHA-1"`.
- `WebView.addJavascriptInterface(obj, name)` — surface the `name` + class methods.
- `WebView.getSettings().setJavaScriptEnabled(true)`.
- `WebView.getSettings().setAllowFileAccess(true)`.
- `setAllowUniversalAccessFromFileURLs(true)` / `setAllowFileAccessFromFileURLs(true)`.
- `Runtime.exec(...)` with non-constant argument.
- `loadLibrary("…")` and `System.load("…")` — native bridge entry points.
- `Intent` with `FLAG_GRANT_*` flags.
- `PendingIntent.FLAG_MUTABLE` on Android 12+ targets.
- `ContentResolver.openInputStream` on user-controlled URI.
- `SharedPreferences` with `MODE_WORLD_READABLE` / `MODE_WORLD_WRITABLE`.
- `SSLContext` with `TrustAllManager` / `HostnameVerifier` returning `true`.
- `setHostnameVerifier(ALLOW_ALL_HOSTNAME_VERIFIER)`.
- Hardcoded JWT-shaped strings, hardcoded PEM blocks.

## Engineering hard parts

- **DEX → IR lowering.** DEX is register-based (not stack-based like JVM bytecode), so every opcode mutates one of ~65k named registers per method. Mapping back to Java's stack-of-locals semantics is non-trivial. Plan: build SSA over registers first, then merge SSA versions back into "Java variables" via interference analysis. Roughly 12k LOC just for the opcode handlers.
- **Register-pair semantics for long/double.** DEX represents 64-bit values across two adjacent registers (`vN`, `vN+1`); a `move-wide v2, v6` actually moves `v6:v7` → `v2:v3`. Every opcode handler must know "is this a wide register pair?" and the pair-tracking must survive control-flow joins. Wrong here = silently corrupted decompile.
- **Try/catch reconstruction.** DEX stores try/catch as a linear table: `(start_addr, insn_count, handler_offset)`. To emit Java, you must recover lexical `try { … } catch (…) { … }` blocks — which means recognizing nested ranges, shared handlers, and the special "catch-all" handler. Worst case: irregular ranges from heavily-optimized bytecode; needs a region tree that handles overlapping handler scopes.
- **Exception handler table → lexical try-blocks.** Related to above but specifically: the handler ranges in `try_item` table may share a handler across multiple non-contiguous try regions, or split a region in the middle of a basic block. Have to splice blocks to align with the handler boundaries.
- **Generic type recovery from erased bytecode.** JVM/Dalvik bytecode is type-erased; `List<String>` is just `List` at runtime. Modern DEX files carry a `Signature` attribute on classes/methods that preserves generics; you parse it via the JLS signature grammar (`<T:Ljava/lang/Object;>(TT;)V` etc.). When `Signature` is absent (older / obfuscated DEX), you fall back to erased types.
- **Kotlin idiom detection.** Recognizing that a `getX()`/`setX()` pair plus a private field is a Kotlin `var x`, that a synthetic `Companion` class is a `companion object`, that a `Function1<…>`-implementing anonymous class is a lambda, that `Pair`/`Triple` are Kotlin builtins — all done via pattern-rewrite passes over the Java AST. The Kotlin metadata annotation (`@Metadata(mv=, k=, d1=, d2=)`) carries protobuf-encoded type info that, when present, makes this much more accurate.
- **AXML decoding.** Android's binary XML format uses a string pool + chunked tag layout. Resource references resolve via `resources.arsc`. Handling all chunk types (RES_TABLE_TYPE, RES_STRING_POOL_TYPE, RES_XML_RESOURCE_MAP_TYPE, namespace chunks) correctly is fiddly.
- **ARSC decoding.** `resources.arsc` is a binary table of all resources (strings, drawables, layouts) per configuration (locale, density, screen size). Tens of nested chunk types. Crashes if you mis-align by one byte.
- **Multi-dex and dex container format.** Apps over the 65k-method limit ship `classes.dex`, `classes2.dex`, `classes3.dex`, …, OR the new (2024+) dex container format that puts multiple DEX in a single file with a per-DEX header table. Both must be supported.
- **Obfuscation realities.** ProGuard/R8/DexGuard rename everything to `a`, `b`, `aa`, `ab`. They also flatten control flow, inline methods aggressively, and may inject opaque predicates. Heuristic deobfuscation handles the rename; control-flow flattening detection is research-grade.
- **Anonymous inner classes.** Java compiles `new Runnable() { … }` to a synthetic `Outer$1` class. jadx detects this from the synthetic flag + naming convention + single-use, and re-inlines the body as an anonymous-class expression — but only when it's safe.
- **Switch / packed-switch / sparse-switch payloads.** DEX stores switch tables as separate "payloads" at the end of the method; the `packed-switch` opcode just carries an offset to the payload. Have to read both, link them, and emit a real `switch` statement.

## Rust library mapping

| Need | Crate | Notes |
|---|---|---|
| APK reading | `zip` 0.6 | Standard zip reader. |
| AXML decoding | hand-roll on `byteorder` | No production AXML crate in Rust; ~600 LOC. |
| ARSC decoding | hand-roll on `byteorder` | Same story; ~1200 LOC. |
| DEX parsing | `dexparser` (early), or hand-roll | None production; hand-roll over `byteorder` + `nom` is safest. |
| JVM classfile parsing | `classfile-parser` or `noak` | For `.jar`/`.class` input. |
| Java source emit | `prettyplease`-style hand printer | No Java pretty-printer crate; clone the design pattern. |
| Kotlin source emit | hand-roll | No crate. |
| Graph (CFG, call graph) | `petgraph` 0.6 | Standard. |
| Bit-level reading | `byteorder` 1.5 + `nom` 7 | Standard. |
| Regex (findings, search) | `regex` 1.10 + `aho-corasick` 1.1 | Multi-pattern scan. |
| CLI | `clap` 4.5 | Standard. |
| Async runtime | `tokio` 1.40 | For LSP/MCP servers. |
| LSP server | `tower-lsp` 0.20 | Same crate Lancer/Aderyn use. |
| MCP server | `rmcp` 0.1 | Anthropic's Rust MCP SDK. |
| JS scanning (later, for Cordova/Capacitor) | `swc_ecma_parser` | Optional batch-2 work. |
| Parallelism | `rayon` 1.10 | Per-class decompile fan-out. |
| Logging | `tracing` 0.1 | Standard. |
| Errors | `eyre` 0.6 / `thiserror` 1 | Standard. |
| SARIF output | `serde-sarif` 0.4 | For findings export. |
| JSON | `serde_json` 1 | Standard. |
| String entropy / hash | `entropy` + `sha1` + `sha2` | Findings scan. |
| Protobuf decoding (Kotlin `@Metadata`) | `prost` 0.13 | For Kotlin metadata annotation parsing. |
| Demangling Kotlin names | hand-roll on JLS rules | None exists. |
| Embedded DB (xref cache) | `redb` 1 or `sled` 0.34 | For persisting xref across runs. |
| Templating (findings reports) | `askama` 0.12 | Same as Aderyn. |
| LLM client (AI rename) | reuse `lancer-ai` | In-tree. |

## Bug bounty workflows

- **Hunting hardcoded secrets.** Decompile APK → run findings → triage `report::findings::secrets` hits. AWS access key IDs, Stripe live keys, Firebase URLs with API keys, Slack webhooks, JWT-shaped strings. Each hit shows file + line + 5-line context; one click sends it to Lancer Decoder.
- **Finding WebView JS bridges.** Search for `addJavascriptInterface(obj, name)`. The `name` is what JS sees as `window.<name>`. Surface the `obj`'s declared `@JavascriptInterface`-annotated methods. Pivot to Repeater: craft an HTTP response that loads a page with `<script>window.<name>.dangerousMethod("…")</script>`.
- **Finding native-bridge methods.** Search for `System.loadLibrary("xyz")` and `native` keyword on methods. Map every Java `native` declaration to the expected JNI symbol (`Java_com_example_Foo_bar`). User can then jump straight to `lancer-ghidra` to disassemble the `.so` and look at that symbol.
- **Finding insecure crypto.** Findings catches DES/RC4/ECB-mode AES/MD5/SHA-1. Show context, propose fix (`AES/GCM/NoPadding`). Bonus: if Lancer-AI is on, ask "is this used to protect data in transit or at rest?" to upgrade severity.
- **Mapping click handlers / intent receivers.** From manifest → find `<receiver>`, `<service>`, `<activity>` declarations with `exported="true"`. Cross-ref each component class to its `onCreate` / `onReceive` / `onStartCommand` to read the actual handler. Identifies attack surface from outside the app.
- **Cordova / Capacitor / React Native bridge scanning.** Look for `wv.loadUrl("file:///android_asset/www/index.html")` patterns → app is hybrid. Pull asset HTML/JS, scan for `cordova.exec` or `Capacitor.Plugins.*` or RN `NativeModules.*` calls.
- **Deep-link surface.** Manifest `<intent-filter>` with `<data android:scheme="…">` → enumerate every deep link the app handles. Cross-ref the activity to find what params it reads. Many SSRF / open-redirect bugs hide here.
- **AndroidManifest sanity check.** `allowBackup="true"` (data exfil via adb backup), `debuggable="true"` (shipped to prod), `usesCleartextTraffic="true"`, missing `networkSecurityConfig`, `exported="true"` on internal components. All flagged.
- **Firebase / Google API key validation.** Once a key is extracted, automatically attempt `curl https://firebase-database.firebaseio.com/.json?auth=…` to confirm misconfigured rules. Wire into Lancer Repeater.
- **Resource scraping.** `strings.xml` often contains backend URLs, admin emails, debug toggles, internal usernames. Cheap pivot.

## 2024-2026 state

- **jadx 1.4.x (2023):** stable Java emit; Kotlin support landed but rough; plugin system introduced (`jadx-plugins-api`); APK signature scheme v3/v4 read-only.
- **jadx 1.5.x (2024-2025):** dex container format support (new Android 14+ multi-dex packaging that puts several DEX in one file with an index); improved Kotlin metadata parsing (handles `@Metadata` k=1/2/3/4/5 variants); refined deobfuscator with sourcename-driven naming when DEX debug info preserved (`--deobf-use-sourcename`); instant-app support (decoding `.zip` bundles with feature modules); GUI rewrite parts; better R8 control-flow-flattening detection (still partial).
- **jadx 1.5.x late-2025 → 2026:** experimental MCP-style integration so Claude / Cursor can call jadx as a tool; experimental Kotlin coroutine state-machine recognition (an `Object` field tracking suspension state → a `suspend fun`); improved smali emit; plugin system supports loading external decompilers (so you could drop in CFR for the JVM bytecode path).
- **Ecosystem (2024-2026):** APKLab (VS Code extension) wraps jadx; MobSF uses jadx as one of its decompile backends; bug bounty methodology guides standardize on "run jadx, grep, look at manifest, look at WebView" as step 1.

### Research note — 2026-05-31 (deep-research pass)

Direct verification against `skylot/jadx` releases page + 2026 community discussion. Items to capture:

- **Latest stable: v1.5.5** (verified May 2026). Plan correctly tracks 1.5.x line; pin to 1.5.5 as parity baseline.
- **Kotlin 2.2 metadata library upgrade.** jadx bumped to `kotlinx-metadata-jvm` 2.2 (Kotlin 2.2 compiler emits metadata bytecode rev 5/6 with new fields for data-class component-N synthesis hints, value-class inline fingerprints, and context-receiver markers). Our `jadx-core/kotlin_metadata.rs` must support metadata rev 1-6.
- **Kotlin coroutine state-machine reconstruction — still EXPERIMENTAL upstream as of v1.5.5.** Plan correctly flags as experimental. Open issue #2536 confirms full coroutine restoration (suspend fun, async/await idiom) is **not** in upstream — Lancer net-new opportunity. We can ship it ahead of upstream since `kotlinx.coroutines` IR is documented.
- **Data class / smart cast / sealed-when restoration.** Same open feature request — upstream emits Java-like code; idiomatic Kotlin not restored. Our `codegen::kotlin` module's roadmap includes these as Lancer differentiators (mark explicitly in "What's allowed to diverge").
- **Plugin system supports external decompilers (v1.5.x).** Confirmed — `jadx-plugins-api` lets you swap the Java-bytecode path to CFR or Vineflower. Our `jadx-cli` accepts `--plugin-decompiler vineflower|cfr|jadx` to mirror.
- **GUI integration ecosystem (verified May 2026):** APKLab VS Code extension wraps jadx; MobSF v4.x uses jadx as one of its static-decompile backends; Frida + jadx is the standard reverse-engineering chain (jadx for static, Frida for dynamic).
- **DEX container format** (Android 14+ multi-dex single-file packaging) — confirmed in v1.5.x. Our `jadx-dex` parser must accept both classic `classes.dex`+`classes2.dex`+`…` and the new single-container format.
- **APK signature scheme v4** — read-only (verification only, no signing). Confirmed.
- **Quark engine ↔ jadx integration.** Quark (malware-behavior rules) can consume jadx output for rule matching. Not a jadx feature per se but a parity surface to be aware of when wiring our findings emitter — Quark-format JSON output as `--export-quark-rules` is a Lancer net-new.

Sources: [skylot/jadx](https://github.com/skylot/jadx), [skylot/jadx releases](https://github.com/skylot/jadx/releases), [jadx issue #2536 — Kotlin decompiler plugin](https://github.com/skylot/jadx/issues/2536), [Jadx 2026 review](https://appsecsanta.com/jadx), [Reverse engineering with JADX + Frida](https://httptoolkit.com/blog/android-reverse-engineering/).

## AI augmentation ideas

- **Rename obfuscated symbols.** For each class/method/field with a name like `a`/`bb`/`a$$c`, send Claude a window: (the symbol's containing class skeleton + the symbol's body + its call sites). Ask for a semantic name + a one-line docstring. Apply rename across the whole project (xref-driven). Batch-rate-limited so a 50k-method APK doesn't hammer the API.
- **Summarize each class.** Per top-level class, generate a 3-line summary used in the GUI tree-view tooltip ("This class manages OAuth token refresh; uses Retrofit; reads from SharedPreferences 'auth_prefs'").
- **Flag suspicious patterns.** Beyond the static findings list, feed each method to the LLM and ask "is there anything security-relevant here? auth, crypto, network, IPC, file system?" Gate by entropy / size to avoid blowing up on tiny accessors.
- **Suggest fix.** For each finding, ask LLM to propose a minimal fix snippet (e.g., `Cipher.getInstance("DES")` → `Cipher.getInstance("AES/GCM/NoPadding")` with key/IV note).
- **Pivot guidance.** "I found `addJavascriptInterface`. What's my next test?" → returns a checklist (load attacker page in WebView, call exposed method, check for XSS reflecting into native).
- **Decompile cleanup.** When jadx fails on a method and emits `// jadx: failed to decompile`, send the disassembly to an LLM with the request "produce best-effort Java." Mark such methods as AI-decompiled in the UI.
- **Kotlin coercion.** When the Java→Kotlin transformer leaves stilted code, ask the LLM to rewrite into idiomatic Kotlin; run a behavioral-equivalence check (compile both, compare bytecode).
- **From natural-language to search.** "Find every place this app talks to Firebase" → LLM emits a regex / AST query that runs over the decompiled tree.
- **Vulnerability chain proposal.** Given an APK + a list of findings, LLM proposes an exploit chain (e.g., "exported activity → deep link param → SQLi in inner Room query").

## Implementation phases (12-week clone)

**Week 1 — Workspace & APK input.** Cargo workspace (`lancer-jadx`, `jadx-core`, `jadx-dex`, `jadx-cli`, `jadx-resources`). APK reader via `zip`. Enumerate `classes*.dex`. Decode `AndroidManifest.xml` via hand-rolled AXML parser (round-trip a known APK).

**Week 2 — DEX parser.** Header, string_ids, type_ids, proto_ids, field_ids, method_ids, class_defs, code_items. Build typed view: `DexClass`, `DexMethod`, `DexField`. Read debug_info_items so we get source line numbers when present. Test against the AOSP-shipped `framework.dex` and a small open-source app.

**Week 3 — DEX opcode decoder.** All 250+ opcodes via a generated table. Each opcode → `InsnNode` with typed args. Handle register-pair semantics for long/double explicitly. Unit-test against a hand-crafted DEX with every opcode at least once.

**Week 4 — IR + CFG + SSA.** Linear IR → basic blocks → dominator tree → SSA construction (Cytron). Phi insertion at joins. Simple constant propagation. Dead-code elimination.

**Week 5 — Try/catch & region tree.** Try-table → handler ranges → lexical try-block recovery. Loop recovery (natural loops + Havlak for irreducible). Region tree (if/else/while/for/switch).

**Week 6 — Java emitter.** Walk region tree → emit Java text via a hand-rolled printer. Handle field decl, method decl, anonymous-class inlining, generics from `Signature` attr. Round-trip: decompiled Java must `javac` back to bytecode that re-decompiles to itself.

**Week 7 — Resource decoder.** ARSC reader. Resource ID → name + value resolution. Decode `strings.xml`, `colors.xml`, etc. `R.string.foo` substitution in decompiled code. Manifest pretty-print.

**Week 8 — Heuristic deobfuscation + xref index.** Rename `a`/`aa` to `cls0`/`cls1`. Strip `$` proxies. Pseudo-package collapse. Cross-reference table (who-calls-X, who-reads-field-X, who-extends-X). Persist xref to `redb` for incremental runs.

**Week 9 — Kotlin transformer.** Pattern-rewrites: getters/setters → properties, `Function1<…>` → lambda, `Companion` → `companion object`, `Pair`/`Triple` recognition. Parse `@Metadata` protobuf for accuracy. Optional: rough coroutine state-machine recognition.

**Week 10 — Findings scanner.** Regex bank (~80 secret patterns) + AST matchers (WebView, crypto, exec, intents, manifest red flags). Emit SARIF + Lancer-native JSON. Wire into Lancer Findings tab.

**Week 11 — LSP + MCP servers.** `tower-lsp` 0.20 over stdio: hover (show decompiled source), goto-definition (xref), find-references (xref). `rmcp` MCP server: tools `decompile_apk`, `extract_strings`, `extract_manifest`, `find_pattern`, `tree`, `findings`.

**Week 12 — AI rename + polish.** `lancer-ai`-driven symbol rename, batched and rate-limited. CLI flags compatibility pass against upstream `jadx --help`. README, examples, performance pass (rayon parallelism over per-class decompile). Validate against a corpus of 50+ public APKs (top apps + known CTF samples).

**Defer to phase 2:** GUI parity with `jadx-gui` (use Lancer's Mobile Assistant tab instead), R8 control-flow-flattening defeat, plugin system, smali emit, AAB feature-module split awareness, Dex2Oat profile usage.

---

## GUI (Lancer-standard pattern)

`lancer-jadx` ships as a **native GUI application** by default. The CLI surface listed in `## Granular feature catalog` is still available behind a `--cli` flag (or via the `lancer-jadx-cli` companion binary), but the **plain `lancer-jadx` invocation opens a native desktop window**, matching every other tool in the Lancer ecosystem. No terminal-only mode.

### Framework

Pure-Rust GUI stack — no JavaScript, no Node, single static binary:

| Crate | Role |
|-------|------|
| `eframe` | Cross-platform window + event loop wrapper around `egui` |
| `egui` | Immediate-mode UI widgets (panels, tables, forms, menus, drag-and-drop) |
| `egui_extras` | Sortable tables, image loaders, syntax highlighting, date pickers |
| `egui_plot` | Charts, graphs, timelines (histograms, activity meters, progress) |
| `rfd` | Native file/folder pickers (open file, save dialog) |
| `directories` | Per-OS config dir (`~/.config/lancer-jadx/`, `%APPDATA%\lancer-jadx\`, etc.) |
| `image` | Screenshot / preview rendering inside egui |
| `arboard` | Clipboard read/write for "copy result" actions |
| `muda` | Native menu bar (Linux / macOS / Windows) |
| `egui-notify` | Toast notifications |

Optional dark/light theme persisted to `lancer-jadx-config.json` via `serde_json`.

### Window layout

Three-pane layout matching the Lancer mothership GUI:

```
┌─────────────────────────────────────────────────────────────────────┐
│  File   Tools   Settings   Help                              [≡]    │
├──────────┬────────────────────────────────────────┬─────────────────┤
│          │                                        │                 │
│  Inputs  │           Main view                    │  Detail pane    │
│  / jobs  │  (table of results / source tree /     │  (full record / │
│  / scope │   findings list / packet list / etc.)  │   bytes / src / │
│          │                                        │   remediation)  │
│          │                                        │                 │
├──────────┴────────────────────────────────────────┴─────────────────┤
│  Status: idle           Items: 0          [Open]  [Run]  [Export]   │
└─────────────────────────────────────────────────────────────────────┘
```

- **Left sidebar (200-300px)** — inputs / queued jobs / scope / target list. Drag-and-drop accepted.
- **Center pane (flexible)** — primary result view appropriate to the tool (table for findings, tree for hierarchical data, code editor for source).
- **Right pane (300-400px, collapsible)** — full detail of the currently-selected item.
- **Top menu bar** — File (Open / Save / Export / Recent / Quit), Tools (per-tool actions), Settings (theme, fonts, integrations), Help (About / Docs).
- **Bottom status bar** — current activity, item counts, primary action buttons.

### Cross-tool integration with Lancer + the other 29 clones

Every Lancer-clone GUI exposes a small local HTTP server on a port auto-allocated at launch (`127.0.0.1:<port>`, written to `%TEMP%/lancer-jadx.port`):

- The main Lancer GUI discovers running tools by scanning `%TEMP%/lancer-*.port` and lists them in its sidebar.
- Right-clicking any item in any tool can "Send to <other Lancer tool>" — the receiving tool fetches the payload via its own HTTP endpoint.
- A future "Lancer Hub" tray shell can launch / focus any of the 30 GUIs from one menu.
- HTTP endpoints exposed:
  - `GET  /v1/state` — current jobs / progress
  - `POST /v1/import` — accept a target / file / record from another Lancer tool
  - `GET  /v1/export?format=json|csv|sarif|markdown` — pull the current result set in a portable format

### Async work + responsiveness

- Long-running scans run on a Tokio task pool; the GUI thread only renders.
- Progress propagates via `crossbeam::channel` from worker → UI.
- A `Stop` button cancels in-flight work via a `CancellationToken`.
- All file I/O / network I/O / subprocess work goes through async channels — the egui thread never blocks.

### Build output

The existing `build.bat` / `build-windows.bat` / `build-linux.sh` already produce a single binary. With `eframe` linked, the same binary is the GUI app.

- Windows: `build\lancer-jadx.exe` (double-click opens the GUI window).
- Linux: `build/lancer-jadx` (also installable as a `.desktop` entry via `build-linux.sh --install`).
- macOS: `build/lancer-jadx` (bundled into `lancer-jadx.app` via `cargo-bundle` in the `build-mac.sh` companion).

For CI / headless / scripting, pass `--cli` to fall through to the CLI surface from `## Granular feature catalog`.

## Build Setup (Lancer-standard pattern)

This clone follows the same build pattern as the main Lancer project — single `.exe` output via `build.bat` on Windows, `.so/elf` via `build-linux.sh` on Linux.

### Project layout

```
lancer-jadx/
├── Cargo.toml              # single-crate Rust project
├── Cargo.lock              # committed (binary, not library)
├── src/
│   └── main.rs             # entry point (scaffold)
├── build.bat               # Windows build → build/lancer-jadx.exe
├── build-windows.bat       # Windows packaged dist build → dist/lancer-jadx-windows-x86_64/
├── build-linux.sh          # Linux build → build/lancer-jadx
├── .gitignore              # plan.md (local-only) + target/ + build/ + dist/
├── README.md               # public-facing (pushed to GitHub)
└── plan.md                 # this file (gitignored — local blueprint, never pushed)
```

### Build commands

**Windows (double-click `build.bat`):**
```
build.bat
```
Produces `build\lancer-jadx.exe`. Pauses at end so the window stays open.

**Windows (packaged dist):**
```
build-windows.bat
```
Produces `dist\lancer-jadx-windows-x86_64\bin\lancer-jadx.exe` plus LICENSE/README — ready to zip.

**Linux / macOS:**
```bash
./build-linux.sh
```
Produces `build/lancer-jadx`.

### Requirements
- Rust toolchain (https://rustup.rs)
- Windows: Visual C++ Build Tools 2019/2022 (needed by some crates)

### CI

The build pattern is intentionally identical across Lancer and all 19 clones, so a single Jenkins/GitHub Actions matrix can build everything by calling `build-windows.bat` or `build-linux.sh` per repo.
