# Analysis tooling

All custom analysis tooling for this project lives in `analysis/tools/`. The tools do not write into `bin/` and produce reports only below `analysis/report/`.

## `inventory.py`

Purpose: recursively enumerate the input tree, record regular-file byte size and stable SHA-256, identify selected common formats from headers, and report duplicate content. It uses only Python's standard library and does not follow symlinks. Header recognition is intentionally limited; this is a triage inventory, not a full PE/ELF/Mach-O parser.

```sh
python3 analysis/tools/inventory.py
python3 analysis/tools/inventory.py --root bin --markdown-out analysis/report/inventory.md --json-out analysis/report/inventory.json
```

- Input: `bin/` by default; `--root` can select another directory for testing.
- Outputs: `analysis/report/inventory.md` and `analysis/report/inventory.json` by default. Explicit report paths must remain under `analysis/report/`.
- Exit: `0` for a complete scan; `2` when the root is missing/rejected or traversal/hashing is partial. Reports are still written for these conditions.
- Limitations: no symbol/import/export/resource extraction, compiler fingerprinting, packing detection, overlay analysis, or dynamic behavior. Files changing during hashing are marked unstable; symlink targets are not opened or hashed.

## `rea_inspect.py`

Purpose: a deliberately narrow, verified wrapper around REA 6.5.0. It pins the package through npm by default, verifies `rea --version`, passes argument vectors without a shell, hashes the input before/after, and saves the raw JSON Evidence without rewriting it.

```sh
# PE32/PE32+ resource identity, ranges, payload hashes and icon-group relationships
python3 analysis/tools/rea_inspect.py pe-resources /absolute/path/to/module.exe

# Caller-supplied GNU objdump operations captured through REA
python3 analysis/tools/rea_inspect.py objdump /absolute/path/to/module.exe file_headers
python3 analysis/tools/rea_inspect.py objdump /absolute/path/to/module.exe section_headers
python3 analysis/tools/rea_inspect.py objdump /absolute/path/to/module.exe symbols
python3 analysis/tools/rea_inspect.py objdump /absolute/path/to/module.exe disassemble
```

Supported objdump operation names are exactly `file_headers`, `section_headers`, `symbols`, `relocations`, `dwarf`, `disassemble`, and `disassemble_all`, as verified from REA 6.5.0's CLI help and documentation. The PE resource operation is limited to PE32/PE32+ resource trees and is **not** a code decompiler. REA's native pseudocode workflows require a configured native provider; this wrapper does not configure one.

- Inputs: a regular file; the selected file itself may not be a symlink. PE resource admission is enforced by REA.
- Output: `analysis/report/rea/<filename>.<sha256-prefix>.<operation>.json` by default. `--output PATH` selects a different path beneath `analysis/report/`.
- Dependencies: Node/npm and `npx`; GNU `objdump` for the objdump mode. The default invocation is `npx --yes --package=rea-agents@6.5.0 rea ... --format json`.
- Override: set `REA_COMMAND` to a command line for an installed REA CLI; the wrapper still requires version 6.5.0. Use shell-style quoting in `REA_COMMAND` only; artifact paths are passed as discrete arguments.
- Limitations: no target execution; before/after hashes detect observed changes but do not lock the file against concurrent writers. The captured Evidence retains REA's own scope/coverage limitations.

## `rea_smoke_test.py`

Purpose: reproducibly exercise REA's PE resource parser and GNU objdump adapter using two generated, non-proprietary synthetic images (one PE32 and one PE32+), each with a resource leaf whose numeric type ID is 6 and whose payload is an opaque smoke-test marker (not decoded as an RT_STRING block). It then cross-checks machine/format with direct GNU `objdump -f` and `inventory.py`'s independent header classifier.

```sh
python3 analysis/tools/rea_smoke_test.py
```

- Inputs: generated in a temporary directory and removed when the command exits; no fixture is placed in `bin/` or executed.
- Outputs: raw REA Evidence and direct objdump output beneath `analysis/report/rea-smoke/`, plus `analysis/report/rea-smoke-test.md` and `.json`.
- Dependencies: Python standard library, the wrapper dependencies above, and GNU `objdump`.
- Limitations: validates tool interfaces against synthetic inputs only. It is not evidence of target format or behavior and does not test Ghidra/Hopper/IDA decompilation.

## Tests

```sh
python3 -m py_compile analysis/tools/*.py
python3 -m unittest discover -s analysis/tools -p 'test_*.py' -v
```

Tests generate temporary fixtures and do not need or touch original binaries. Six inventory tests currently pass. There is intentionally no CMake target or reconstructed-module test suite because no target module has been supplied.
