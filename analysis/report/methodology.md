# Methodology and reproducibility

## Scope and evidence rules

The working checkout was inspected first, without changing or creating anything under `bin/`. The checkout at the start of this work was commit `17d4883a6050e4dbc184f76010f3b0ea176f0abd`; `git ls-tree -r HEAD` contained only `LICENSE` and `README.md`. There is no `bin/` directory and no original executable, DLL, archive, or other target artifact in the working tree. The inventory result is therefore **zero observed target files**, not a claim that unknown files were successfully parsed.

Analysis statements in this project are separated into:

- **Verified target fact:** directly measured from a project input with its SHA-256 and a recorded tool operation. There are none yet.
- **Verified tool/environment fact:** directly reported by the installed toolchain or inspected source/documentation. These are recorded below.
- **Synthetic-fixture result:** a tool smoke-test result on a generated, non-project PE file. It verifies the tool interface only and is not evidence about the target software.
- **Unassessed:** unavailable because the original artifact is absent or an analysis engine is not configured. Unknown is not treated as absent.

Original binaries, when supplied, are inputs only. The inventory tool opens regular files read-only, does not follow symlinks, hashes bytes, and does not write into the input directory. No target binary was executed in this run.

## Repository and input inventory procedure

The initial checks were:

```sh
git status --short --branch
git rev-parse HEAD
git ls-tree -r --long HEAD
find bin -type f -printf '%p\t%s bytes\n'  # bin/ was absent
```

The reusable inventory implementation is `analysis/tools/inventory.py` (Python standard library only). From the repository root, run:

```sh
python3 analysis/tools/inventory.py
python3 -m unittest discover -s analysis/tools -p 'test_*.py' -v
```

The first command writes `analysis/report/inventory.md` and `analysis/report/inventory.json`. It hashes regular files with SHA-256 and performs limited, signature-based format/architecture recognition (including basic PE/COFF, ELF, and Mach-O headers); it does not replace format-specific parsers. Exit code `2` means the root is missing or the scan is partial. The actual run returned `root_missing`, 0 entries, 0 regular files, and exit code 2. Six synthetic unit tests for hashing, duplicate detection, symlink policy, missing roots, and basic PE/ELF identification passed.

## REA assessment and actual use

REA was inspected from the official repository [`morluto/rea`](https://github.com/morluto/rea) at source commit [`fffb0741936067530d1ce9777461cd53e87398c2`](https://github.com/morluto/rea/tree/fffb0741936067530d1ce9777461cd53e87398c2). The inspected [`package.json`](https://github.com/morluto/rea/blob/fffb0741936067530d1ce9777461cd53e87398c2/package.json) identifies `rea-agents` version `6.5.0`, Node requirements `^22.19.0 || ^24.11.0 || >=26.0.0`, executable names `rea` / `rea-agents`, and repository package-manager metadata `npm@11.16.0`. Its direct dependencies include MCP client/server SDK `2.3.1` and Zod `4.4.3`; optional Frida is `17.23.2`. The current environment's Node.js `v22.22.3` satisfies the runtime requirement; npm `10.9.8` successfully ran the pinned published package via npx. These are REA's own dependencies, not dependencies observed in target binaries. No REA dependency or build output was added to this project.

Inspected documentation/source included:

- [`README.md`](https://github.com/morluto/rea/blob/fffb0741936067530d1ce9777461cd53e87398c2/README.md) and [`docs/cli.md`](https://github.com/morluto/rea/blob/fffb0741936067530d1ce9777461cd53e87398c2/docs/cli.md) for the CLI and target categories.
- [`docs/binary-diagnostics.md`](https://github.com/morluto/rea/blob/fffb0741936067530d1ce9777461cd53e87398c2/docs/binary-diagnostics.md) and `src/native/pe/PeResourcesProvider.ts`, `src/native/pe/PeResourceParser.ts`, `src/application/binaryDiagnostics/PeResourcesService.ts`, plus `tests/acceptance/applications/peResources.test.ts` for PE resource behavior and test coverage.
- [`docs/native-investigation.md`](https://github.com/morluto/rea/blob/fffb0741936067530d1ce9777461cd53e87398c2/docs/native-investigation.md), [`docs/reverse-engineering-tools.md`](https://github.com/morluto/rea/blob/fffb0741936067530d1ce9777461cd53e87398c2/docs/reverse-engineering-tools.md), and [`docs/installation.md`](https://github.com/morluto/rea/blob/fffb0741936067530d1ce9777461cd53e87398c2/docs/installation.md) for providers, requirements, and limitations.

Verified REA interfaces used in the smoke test:

- `rea inspect-pe-resources PATH --format json` accepts PE32/PE32+ and statically inventories the conventional type/name/language resource tree, exact payload ranges and payload hashes, and RT_GROUP_ICON references. It requires no active disassembler and does not execute code. It is **not** a native-code decompiler; non-icon payloads remain opaque.
- `rea inspect-with-objdump PATH file_headers --format json` captures output from a caller-supplied GNU `objdump`. The supported operation names and raw-output semantics are documented in REA's reverse-engineering tools guide. REA does not install `objdump`.
- REA's README also documents static Go/Rust build-metadata inspection for ELF/PE/thin Mach-O inputs, static PE/CLI metadata and CIL inspection for managed assemblies, and ELF layout inspection with caller-supplied `pwntools` on Linux x64. Other workflows have feature-specific prerequisites (for example, WABT for WASM and JADX/JDK for Android). These lanes were inspected for suitability but not run because no target format is known.
- The REA README documents native pseudocode/instructions/references through Hopper, Ghidra, or IDA. REA's current capability/provider inspection found Ghidra `not_configured`, Hopper `executable_missing` at `/opt/hopper/bin/Hopper`, and IDA `not_configured`. These engines were not available for a target analysis.

Commands actually run included:

```sh
npx --yes --package=rea-agents@6.5.0 rea --version
npx --yes --package=rea-agents@6.5.0 rea --help
npx --yes --package=rea-agents@6.5.0 rea capabilities --json
npx --yes --package=rea-agents@6.5.0 rea providers --json
python3 analysis/tools/rea_smoke_test.py
```

The smoke-test script creates temporary, hand-authored PE32/i386 and PE32+/x86-64 fixtures, each with one resource leaf using numeric type ID 6 and an opaque marker payload (the payload is not decoded as a valid RT_STRING block). It then calls the two verified REA CLI operations above; GNU `objdump`'s BFD format (`pei-i386` / `pei-x86-64`) and the local header classifier independently cross-check the architecture lane. Both resource parses reported complete coverage and one resource, the known payload SHA-256 matched, and the file hashes were unchanged before/after. Raw REA Evidence and a summary are under `analysis/report/rea-smoke/` and `analysis/report/rea-smoke-test.md`. These files explicitly identify the inputs as generated fixtures; they are not target analysis results.

The generic wrapper for future inputs is `analysis/tools/rea_inspect.py`. By default it pins REA through `npx --yes --package=rea-agents@6.5.0`, verifies the package version, invokes the operation with `--format json`, hashes the input before/after, and saves the unmodified REA JSON under `analysis/report/rea/`. An explicitly installed CLI may be selected using `REA_COMMAND`; the wrapper still requires version `6.5.0`.

## Toolchain observed on this host

Observed versions: Python `3.11.2`; Node.js `v22.22.3`; npm `10.9.8`; GNU Binutils `2.40` (`objdump`, `readelf`, `nm`, `strings`); GCC `12.2.0`; Git `2.39.5`. Available local structural tools include `objdump`, `readelf`, `nm`, and `strings`.

Not found on `PATH`: `file`, CMake, Clang, Java, Ghidra launchers, Rizin, Radare2, `rabin2`, GDB, and LLDB. REA's capability output independently confirmed that its native decompilation providers are not configured/available. No Windows execution/debugging environment was established. A C compiler alone is not a reason to create a compatibility target when no module interface or behavior has been observed.

## Reproducible next-stage workflow once inputs are present

1. Place the authorized, unmodified target files under `bin/`; record their exact filenames and preserve module boundaries. Do not put generated output there.
2. Run the inventory and tests above. For every target, record size, stable SHA-256, signature/header-derived format and architecture. Review scan errors and duplicates before proceeding.
3. Select tools by observed format. Use `readelf` for ELF, `objdump` for supported COFF/PE/ELF structures, and the REA wrapper for PE resources / captured GNU `objdump` operations. Do not infer that a filename extension proves a format.
4. For native function pseudocode, install/configure a supported engine (for example, Ghidra 12.1.x plus its required full JDK and matching native decompiler, as required by the inspected REA guide) or another suitable licensed disassembler. Verify it with REA's doctor/capability output before analysis. Record provider/version/configuration and exact addresses for every function.
5. Extract imports/exports, symbols, strings, resources, sections, relocations, debug data, and runtime dependencies; retain the source file hash and offset/address provenance. Keep decompiler output labeled as tool-generated pseudocode, and label manual type/algorithm recovery as inferred until independently validated.
6. Only consider controlled dynamic analysis after file format, architecture, runtime requirements, and side effects are understood. Record environment, command, input hash, exit status, and observations. Do not execute a target merely to make progress.
7. Add each target under `src/<module>/` only when evidence supports meaningful reconstructed pseudocode, declarations, API notes, or a compatibility implementation. Add CMake only where there is an actual buildable reconstruction. Validate it and record discrepancies in `analysis/report/validation.md`.

## Known methodological limits

There is no target to parse, so file-format-specific structural analysis, symbol extraction, decompilation, resources, dynamic loading, call graphs, function coverage, runtime behavior, and compatibility validation remain unassessed. The signature inventory script's supported signatures are intentionally limited. The PE smoke test validates REA's selected APIs, not every REA feature, engine, platform, PE variant, or the proprietary target. Native pseudocode and behavioral conclusions must wait for actual inputs and an available native analysis provider.
