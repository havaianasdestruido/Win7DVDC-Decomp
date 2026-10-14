# Data-format findings

## Project input formats

No file-format structure is recoverable from the current project state because there are no files in `bin/`. No project magic value, container header, GUID, chunk, offset, size, flag, checksum, encoding, version, resource, or format variant has been observed. All project formats remain **unknown / unassessed**; none should be inferred from the repository name or README.

| Artifact | Format | Evidence | Status |
|---|---|---|---|
| *No project input files observed* | Unknown | `bin/` does not exist; inventory contains 0 entries | `blocked_no_input` |

## REA format support verified for workflow selection

Source and documentation inspection of REA `6.5.0` verified a portable `inspect-pe-resources` workflow for explicit PE32 and PE32+ files. It reports PE machine/format, resource directory and directory-entry ranges, type/name/language identities, data-entry and payload ranges, per-payload SHA-256, and RT_GROUP_ICON relationships. It requires no active native-analysis provider and does not execute the selected file. The supported tree shape is the conventional three-level type/name/language form; arbitrary resource payloads other than icon-group structures are opaque. Malformed or unsupported trees fail closed rather than being silently returned as complete. Documented defaults are a 64 MiB input cap and 16,384 directory-entry cap; documented maxima are 512 MiB and 65,536 entries, with an 8 MiB metadata budget. These are tool capabilities, not facts about any project artifact.

REA also offers a GNU `objdump` adapter for selected operations (`file_headers`, `section_headers`, `symbols`, `relocations`, `dwarf`, `disassemble`, `disassemble_all`) when a compatible caller-supplied `objdump` is available. Its captured provider output is authoritative; REA documents that it is not normalized into a version-independent disassembly schema.

## Synthetic smoke fixture (not a project file specification)

The REA interface test created two temporary 1,024-byte PE images:

| Synthetic fixture | PE identity | Fixture SHA-256 | Test resource |
|---|---|---|---|
| `synthetic-pe32.exe` | PE32 / COFF machine `0x014c` (i386) | `40961a14162757677d5ef52a623e1230d895658226df66309bccba7453ba9bc4` | Numeric type ID 6, name ID 1, language ID 1033; 12-byte opaque marker payload |
| `synthetic-pe64.exe` | PE32+ / COFF machine `0x8664` (x86-64) | `cdabff8d79bc6ad73fb58b652665dc46afc137e75bee67888e6e7a27c1609219` | Same generated resource tree and opaque payload |

Type ID 6 is the conventional RT_STRING resource identifier, but the smoke marker payload is not a Windows string-table block and was not decoded as one; the test exercises only the directory parser and payload hashing. For both, REA reported complete resource coverage and the expected payload SHA-256 `21defa1ecdeef1ced721bb3875ea91c0d95e0920849c7388a665c4e59fc53250`. REA/objdump, direct GNU `objdump`, and the inventory header classifier agreed on `pei-i386` / x86 and `pei-x86-64` / x86-64. Raw Evidence is retained under `analysis/report/rea-smoke/`; the reproducible generator/test is `analysis/tools/rea_smoke_test.py`.

These fixtures are generated test inputs, were stored only in a temporary directory, and were never executed or placed in `bin/`. Their bytes and resource tree validate the parser invocation only; they do **not** describe a project binary or imply the target is PE.

## Structural recovery status

No target header or format parser was run. PE resources, manifests, icons, dialogs, strings, configuration, embedded archives, overlays, nested executables, and checksums are all unassessed. Once originals are supplied, retain exact file hashes and file offsets for each recovered field; state whether a range is a raw observation, a derived mapping, or an inference. Keep format payloads opaque unless their internal encoding is independently identified and validated.
