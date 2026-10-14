# Dependency map and tool prerequisites

## Original software dependencies

No project executable or DLL was present, so no import-table, delay-load, export-forwarder, manifest, CLR metadata, runtime-library, registry, or loader dependency was measured. There are **no observed target dependency edges**. This is unknown, not a conclusion that the original software is self-contained.

| Source module | Dependency | Evidence | Status |
|---|---|---|---|
| *No target modules observed* | — | `bin/` absent; 0 inventory entries | `blocked_no_input` |

The operating-system baseline, Windows API level, Visual C++ runtime, .NET version, side-by-side assemblies, COM registrations, optional codecs, and dynamically loaded modules therefore remain unresolved.

## Reverse-engineering environment

| Tool/component | Observed state | Role / constraint |
|---|---|---|
| Python `3.11.2` | Available | Standard-library inventory, wrappers, and tests |
| Node.js `v22.22.3`, npm `10.9.8` | Available | Meets REA 6.5.0's documented Node `^22.19.0 || ^24.11.0 || >=26.0.0` runtime requirement |
| REA `rea-agents@6.5.0` | Invoked with `npx --yes --package=rea-agents@6.5.0` | PE resource static inspection and documented analysis workflows; no global install or project dependency changes |
| GNU Binutils `2.40` (`objdump`, `readelf`, `nm`, `strings`) | Available | Independent structural inspection and caller-supplied REA `objdump` adapter |
| GCC `12.2.0` / G++ | Available | Could compile future reconstructions, but no module exists to build |
| `file`, CMake, Clang | Not found | No `file`-based identification or CMake build performed |
| Java / Ghidra | Not found / REA reports Ghidra not configured | Native decompilation cannot currently be run through REA's Ghidra provider |
| Hopper | REA reports launcher missing at `/opt/hopper/bin/Hopper` | Native provider unavailable |
| IDA | REA reports no `REA_IDA_MCP_CONFIG` registration | Native adapter not configured |
| Rizin, Radare2, `rabin2`, GDB, LLDB | Not found | No corresponding dynamic or alternate-disassembler analysis performed |

REA's current `capabilities --json` / `providers --json` output identified Ghidra as `not_configured`, Hopper as `executable_missing`, and IDA as `not_configured`. The inspected REA installation guide accepts Ghidra 12.1.x, the 64-bit full JDK declared by that installation (current 12.1 releases require JDK 21 or newer), and a matching host-native decompiler. It documents `GHIDRA_INSTALL_DIR` and optional `JAVA_HOME`, followed by `rea doctor --json`; REA setup does not install Ghidra or Java. This host has neither Java nor Ghidra configured, so those components were not downloaded or fabricated as dependencies. The read-only PE resource parser has no active engine prerequisite. The GNU objdump operation depends on the caller's `objdump`; the available version is 2.40. REA's inspected README also lists offline ELF-layout analysis with caller-supplied `pwntools`; that path was not used and its dependency is not configured/verified here.

## Dependency structure of project code

There is no `src/<module>/` target and no compatibility library. Consequently there is no CMake dependency graph or link closure to report. A build system will be added only after a concrete reconstruction and compiler/platform requirements have been recovered. See `analysis/report/methodology.md` for exact version and reproducibility details.
