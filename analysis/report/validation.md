# Validation results

## Target-module validation

There are no original binaries in this checkout (`bin/` is absent), and no reconstructed module exists. Consequently, target disassembly/decompilation, import/export checks, runtime comparisons, compatibility tests, module compilation, and CMake builds are **not run**. There is no basis for claiming a target builds, runs, or matches original behavior. No original input bytes were available to modify.

## Analysis tooling validation

| Validation | Command / evidence | Result |
|---|---|---|
| Inventory tool syntax | `python3 -m py_compile analysis/tools/inventory.py` | Passed |
| REA wrapper and smoke test syntax | `python3 -m py_compile analysis/tools/rea_inspect.py analysis/tools/rea_smoke_test.py` | Passed |
| Inventory unit tests | `python3 -m unittest discover -s analysis/tools -p 'test_*.py' -v` | **6 passed**: PE32, PE32+, ELF64, unknown-file classification, missing-root handling, recursive hashes/duplicates/symlink handling |
| Input inventory | `python3 analysis/tools/inventory.py` | Wrote inventory reports; reported `root_missing`, 0 files, exit code 2 (expected for absent `bin/`) |
| REA version / CLI surface | `npx --yes --package=rea-agents@6.5.0 rea --version`; `... rea --help` | REA reported `6.5.0`; `inspect-pe-resources` and `inspect-with-objdump` command forms were confirmed |
| REA provider readiness | `... rea capabilities --json`; `... rea providers --json` | Ghidra `not_configured`, Hopper `executable_missing`, IDA `not_configured`; no native decompiler session was available |

## REA synthetic-fixture validation

Reproduced by `python3 analysis/tools/rea_smoke_test.py`. Six checks passed against temporary generated PE files (not target binaries):

1. REA parsed one PE32/i386 resource-tree leaf with numeric type ID 6 and reported complete coverage, expected type/name/language IDs, payload size, and payload SHA-256. The marker payload was treated as opaque, not decoded as an RT_STRING block.
2. REA's `inspect-with-objdump` captured the PE32 GNU BFD format `pei-i386`.
3. Direct `objdump -f` independently returned `pei-i386`, and the project's header classifier independently identified PE32/x86.
4. REA parsed the known resource from PE32+/x86-64 and reported complete coverage.
5. REA's `inspect-with-objdump` captured the PE32+ GNU BFD format `pei-x86-64`.
6. Direct `objdump -f` independently returned `pei-x86-64`, and the project's header classifier independently identified PE32+/x86-64.

The known payload SHA-256 matched in both parses. The wrapper's before/after artifact digests matched for all inspections, and the fixtures were not executed.

Raw REA JSON Evidence and direct objdump outputs are in `analysis/report/rea-smoke/`; summary and fixture hashes are in `analysis/report/rea-smoke-test.md` and `.json`. All results are explicitly scoped to the test fixtures. They do not establish target format or application behavior.

## Known discrepancies / unresolved validation

- No target-level observations exist for comparison, so behavior discrepancies cannot be measured.
- No native provider is configured; function signatures, calling conventions, data types, entry points, initialization, and control flow remain unvalidated.
- No compile-time check is meaningful until a supported compatibility implementation and module interface exist. CMake is not installed in the current environment.
- The inventory signature detector is deliberately limited and unit-tested only on simple fixtures; format-specific analysis must use suitable parsers and independent evidence after real inputs arrive.
