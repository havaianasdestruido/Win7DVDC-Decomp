# Consolidated API map

## Observed project interfaces

No imports, exports, public symbols, COM interfaces, callbacks, dynamically resolved symbols, or cross-module calls could be enumerated: the checkout contains no files under `bin/`. Therefore, **zero APIs are observed**, while the target API surface is **unknown**. This must not be read as evidence that the original application exports or imports no functions.

| Module | Direction | Name / ordinal | Address / evidence | Calling convention / types | Status |
|---|---|---|---|---|---|
| *No target modules available* | — | — | — | — | `blocked_no_input` |

## Inter-module dependencies

No project module dependency edge can be established without binaries. There are no import tables, delay imports, export-forwarder records, manifests, runtime configuration files, or loader traces in the checkout. Do not infer dependency edges from the project name, anticipated Windows version, or extension of absent files.

## Tool interfaces confirmed (not target APIs)

The following are analysis-tool interfaces, included only to make the workflow reproducible; they are not APIs recovered from the target:

- REA `inspect-pe-resources` — static PE32/PE32+ resource inventory. It does not enumerate executable-code imports/exports or decompile functions.
- REA `inspect-with-objdump` — delegates selected operations to caller-supplied GNU `objdump` and preserves provider output as Evidence.
- GNU Binutils `objdump`, `readelf`, `nm`, and `strings` are installed; no target artifact was available to query.

Synthetic fixture results are recorded separately in `analysis/report/rea-smoke-test.md`; they are not included as application API entries.

## API recovery plan for supplied targets

1. Hash and identify each actual binary. Extract PE imports/delay imports/exports/forwarders and COFF symbols with a PE-aware parser or `objdump` where supported; use `readelf`/`nm` for ELF when applicable.
2. Cross-check any available symbols against disassembly and call/reference evidence. Record ordinals, exact module names, decorated names, forwarded exports, and address ranges.
3. For dynamically resolved APIs, locate lookup strings and call sites; report the resolver path and unresolved cases rather than assuming a string reference proves a successful load.
4. Recover calling conventions and parameter/return types from ABI rules, call sites, and data flow. Mark types inferred unless corroborated by independent evidence.
5. Record inter-module edges only when an import, loader reference, or observed resolution supports them. Keep unresolved names and unobserved dependencies explicit.

No API signatures or declarations are supplied in this report because none can currently be tied to target bytes.
