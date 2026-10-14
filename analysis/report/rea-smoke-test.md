# REA integration smoke test

- Status: **passed**
- Run time (UTC): `2026-10-14T22:34:42+00:00`
- REA: `rea-agents@6.5.0`
- Launcher: `/usr/local/bin/npx --yes --package=rea-agents@6.5.0 rea`
- Fixtures: two generated synthetic images (PE32/i386 and PE32+/x86-64), each with one numeric type-ID-6 resource leaf and an opaque marker payload (not decoded as an RT_STRING block).
- Fixture execution: **not performed**; inputs were only read by static inspections.

## Checks

| Check | Status | Observed result | Evidence / raw output |
|---|---|---|---|
| PE32 resource parsing | passed | pe32; 1 resource; payload SHA-256 `21defa1ecdeef1ced721bb3875ea91c0d95e0920849c7388a665c4e59fc53250` | `analysis/report/rea-smoke/pe32-resources.json` |
| PE32 REA/objdump file-header capture | passed | REA/objdump BFD `pei-i386`; exit 0 | `analysis/report/rea-smoke/pe32-objdump-file-headers.json` |
| PE32 independent header cross-check | passed | inventory `PE32 image` / `x86`; direct objdump BFD `pei-i386` | `analysis/report/rea-smoke/pe32-direct-objdump.txt` |
| PE32+ resource parsing | passed | pe32-plus; 1 resource; payload SHA-256 `21defa1ecdeef1ced721bb3875ea91c0d95e0920849c7388a665c4e59fc53250` | `analysis/report/rea-smoke/pe64-resources.json` |
| PE32+ REA/objdump file-header capture | passed | REA/objdump BFD `pei-x86-64`; exit 0 | `analysis/report/rea-smoke/pe64-objdump-file-headers.json` |
| PE32+ independent header cross-check | passed | inventory `PE32+ image` / `x86-64`; direct objdump BFD `pei-x86-64` | `analysis/report/rea-smoke/pe64-direct-objdump.txt` |

## Scope

- This test validates REA CLI behavior and the supplied GNU objdump adapter against generated, non-proprietary PE fixtures only.
- It does not inspect any project target; bin/ is absent at the time of this run.
- The PE resource operation inventories metadata and opaque payload byte ranges; it does not decompile PE code.
- Native decompilation still requires a configured Ghidra, Hopper, or IDA provider and an actual target binary.

Reproduce from the repository root with `python3 analysis/tools/rea_smoke_test.py`. The script creates fixtures in a temporary directory and stores the raw REA JSON Evidence beneath `analysis/report/rea-smoke/`.
