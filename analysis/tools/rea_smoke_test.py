#!/usr/bin/env python3
"""Exercise REA PE-resource and GNU-objdump CLI lanes on synthetic PEs.

The fixture has one type-ID-6 resource leaf with an opaque marker payload; the
payload is not decoded as a Windows RT_STRING block. This is a toolchain test,
not project-binary analysis, and no fixture is written to bin/ or executed.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import struct
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
REPORT_ROOT = ROOT / "analysis" / "report"
sys.path.insert(0, str(Path(__file__).resolve().parent))
from inventory import detect_format  # noqa: E402
from rea_inspect import inspect_artifact, rea_version  # noqa: E402

PAYLOAD = b"REA-RESOURCE"
RESOURCE_RVA = 0x2000
RESOURCE_FILE_OFFSET = 0x200
RESOURCE_TREE_SIZE = 88 + len(PAYLOAD)
RAW_SECTION_SIZE = 0x200


def make_pe(plus: bool) -> bytes:
    """Build one small PE32/PE32+ image with a single numeric RT_STRING leaf."""
    machine = 0x8664 if plus else 0x014C
    optional_size = 240 if plus else 224
    data = bytearray(RESOURCE_FILE_OFFSET + RAW_SECTION_SIZE)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 60, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into(
        "<HHIIIHH",
        data,
        0x84,
        machine,
        1,
        0,
        0,
        0,
        optional_size,
        0x0102,
    )
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x020B if plus else 0x010B)
    struct.pack_into("<I", data, optional + 32, 0x1000)  # SectionAlignment
    struct.pack_into("<I", data, optional + 36, 0x0200)  # FileAlignment
    struct.pack_into("<I", data, optional + 56, 0x3000)  # SizeOfImage
    struct.pack_into("<I", data, optional + 60, 0x0200)  # SizeOfHeaders
    count_offset = 108 if plus else 92
    directories_offset = 112 if plus else 96
    struct.pack_into("<I", data, optional + count_offset, 16)
    resource_directory_at = optional + directories_offset + 16
    struct.pack_into("<II", data, resource_directory_at, RESOURCE_RVA, RESOURCE_TREE_SIZE)

    # One resource leaf: numeric type ID 6 -> name ID 1 -> language 1033.
    # Its marker payload is opaque and is not encoded as a string-table block.
    section = memoryview(data)[RESOURCE_FILE_OFFSET:]
    struct.pack_into("<HH", section, 12, 0, 1)  # root named/id counts
    struct.pack_into("<II", section, 16, 6, 0x80000018)
    struct.pack_into("<HH", section, 24 + 12, 0, 1)
    struct.pack_into("<II", section, 24 + 16, 1, 0x80000030)
    struct.pack_into("<HH", section, 48 + 12, 0, 1)
    struct.pack_into("<II", section, 48 + 16, 1033, 72)
    struct.pack_into("<IIII", section, 72, RESOURCE_RVA + 88, len(PAYLOAD), 65001, 0)
    section[88 : 88 + len(PAYLOAD)] = PAYLOAD

    section_header = optional + optional_size
    data[section_header : section_header + 8] = b".rsrc\0\0\0"
    struct.pack_into("<IIII", data, section_header + 8, RESOURCE_TREE_SIZE, RESOURCE_RVA, RAW_SECTION_SIZE, RESOURCE_FILE_OFFSET)
    struct.pack_into("<I", data, section_header + 36, 0x40000040)
    return bytes(data)


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def run() -> dict[str, Any]:
    launcher, version = rea_version()
    evidence_dir = REPORT_ROOT / "rea-smoke"
    results: list[dict[str, Any]] = []
    fixture_facts: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="win7dvdc-rea-smoke-") as temporary:
        temporary_root = Path(temporary)
        for plus in (False, True):
            bits = 64 if plus else 32
            label = "PE32+" if plus else "PE32"
            fixture = make_pe(plus)
            path = temporary_root / f"synthetic-pe{bits}.exe"
            path.write_bytes(fixture)
            fixture_hash = hashlib.sha256(fixture).hexdigest()
            fixture_facts.append({
                "name": path.name,
                "kind": "generated synthetic PE with one type-ID-6 resource leaf and opaque marker payload",
                "bytes": len(fixture),
                "sha256": fixture_hash,
                "expected_resource_payload_sha256": hashlib.sha256(PAYLOAD).hexdigest(),
                "stored_in_bin": False,
                "executed": False,
            })

            resource_output = evidence_dir / f"pe{bits}-resources.json"
            resource_run = inspect_artifact(
                "pe-resources",
                path,
                output=resource_output,
            )
            resource_evidence = resource_run["evidence"]
            resource_report = resource_evidence["normalized_result"]
            _expect(resource_run["input_unchanged"], f"PE{bits} changed during resource inspection")
            _expect(resource_evidence["subject"]["digest"]["sha256"] == fixture_hash, f"PE{bits} Evidence hash mismatch")
            _expect(resource_report["format"] == ("pe32-plus" if plus else "pe32"), f"REA did not identify PE{bits}")
            _expect(resource_report["coverage"]["status"] == "complete", f"PE{bits} resource inventory was not complete")
            _expect(resource_report["coverage"]["resources"] == 1, f"PE{bits} expected one resource")
            resource = resource_report["resources"][0]
            _expect(resource["type"] == {"kind": "id", "id": 6}, f"{label} numeric resource type ID mismatch")
            _expect(resource["name"] == {"kind": "id", "id": 1}, f"PE{bits} resource name mismatch")
            _expect(resource["language"] == {"kind": "id", "id": 1033}, f"PE{bits} language ID mismatch")
            _expect(resource["payload"]["sha256"] == hashlib.sha256(PAYLOAD).hexdigest(), f"PE{bits} payload hash mismatch")
            results.append({
                "check": f"{label} resource parsing",
                "status": "passed",
                "evidence_file": str(resource_output.relative_to(ROOT)),
                "format": resource_report["format"],
                "coverage": resource_report["coverage"],
                "resource": {
                    "type": resource["type"],
                    "name": resource["name"],
                    "language": resource["language"],
                    "payload_sha256": resource["payload"]["sha256"],
                    "payload_bytes": resource["payload"]["location"]["bytes"],
                },
                "artifact_sha256": fixture_hash,
                "input_unchanged": resource_run["input_unchanged"],
            })

            objdump_output = evidence_dir / f"pe{bits}-objdump-file-headers.json"
            objdump_run = inspect_artifact(
                "objdump",
                path,
                objdump_operation="file_headers",
                output=objdump_output,
            )
            objdump_evidence = objdump_run["evidence"]
            objdump_result = objdump_evidence["normalized_result"]
            _expect(objdump_run["input_unchanged"], f"PE{bits} changed during objdump inspection")
            _expect(objdump_result["exit_code"] == 0, f"GNU objdump failed for PE{bits}")
            expected_bfd = "pei-x86-64" if plus else "pei-i386"
            _expect(expected_bfd in objdump_result["stdout"], f"GNU objdump did not recognize {expected_bfd}")
            results.append({
                "check": f"{label} REA/objdump file-header capture",
                "status": "passed",
                "evidence_file": str(objdump_output.relative_to(ROOT)),
                "bfd_format_observed": expected_bfd,
                "provider_exit_code": objdump_result["exit_code"],
                "artifact_sha256": fixture_hash,
                "input_unchanged": objdump_run["input_unchanged"],
            })

            objdump_binary = shutil.which("objdump")
            _expect(objdump_binary is not None, "GNU objdump is required for the independent cross-check")
            direct = subprocess.run(
                [objdump_binary, "-f", str(path)],
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
            )
            _expect(direct.returncode == 0, f"Direct GNU objdump exited {direct.returncode}")
            _expect(expected_bfd in direct.stdout, f"Direct GNU objdump did not report {expected_bfd}")
            direct_output = evidence_dir / f"pe{bits}-direct-objdump.txt"
            direct_output.parent.mkdir(parents=True, exist_ok=True)
            direct_output.write_text(direct.stdout.rstrip("\n") + "\n" + direct.stderr.rstrip("\n"), encoding="utf-8")
            with path.open("rb") as stream:
                inventory_result = detect_format(stream, path.stat().st_size)
            expected_arch = "x86-64" if plus else "x86"
            expected_format = "PE32+ image" if plus else "PE32 image"
            _expect(inventory_result["architecture"] == expected_arch, f"Inventory parser disagrees on {label} architecture")
            _expect(inventory_result["format"] == expected_format, f"Inventory parser disagrees on {label} format")
            _expect(hashlib.sha256(path.read_bytes()).hexdigest() == fixture_hash, f"{label} changed during cross-check")
            results.append({
                "check": f"{label} independent header cross-check",
                "status": "passed",
                "inventory_format": inventory_result["format"],
                "inventory_architecture": inventory_result["architecture"],
                "direct_objdump_bfd_format": expected_bfd,
                "direct_objdump_output": str(direct_output.relative_to(ROOT)),
                "artifact_sha256": fixture_hash,
                "input_unchanged": True,
            })

    return {
        "schema_version": 1,
        "status": "passed",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "rea": {
            "package": "rea-agents",
            "version": version,
            "launcher": launcher,
            "command_family": "npx --yes --package=rea-agents@6.5.0 rea",
            "resource_command": "inspect-pe-resources PATH --format json",
            "objdump_command": "inspect-with-objdump PATH file_headers --format json",
        },
        "fixtures": fixture_facts,
        "checks": results,
        "scope_and_limitations": [
            "This test validates REA CLI behavior and the supplied GNU objdump adapter against generated, non-proprietary PE fixtures only.",
            "It does not inspect any project target; bin/ is absent at the time of this run.",
            "The PE resource operation inventories metadata and opaque payload byte ranges; it does not decompile PE code.",
            "Native decompilation still requires a configured Ghidra, Hopper, or IDA provider and an actual target binary.",
        ],
    }


def _markdown(report: dict[str, Any]) -> str:
    lines = [
        "# REA integration smoke test",
        "",
        f"- Status: **{report['status']}**",
        f"- Run time (UTC): `{report['generated_at_utc']}`",
        f"- REA: `{report['rea']['package']}@{report['rea']['version']}`",
        f"- Launcher: `{ ' '.join(report['rea']['launcher']) }`",
        "- Fixtures: two generated synthetic images (PE32/i386 and PE32+/x86-64), each with one numeric type-ID-6 resource leaf and an opaque marker payload (not decoded as an RT_STRING block).",
        "- Fixture execution: **not performed**; inputs were only read by static inspections.",
        "",
        "## Checks",
        "",
        "| Check | Status | Observed result | Evidence / raw output |",
        "|---|---|---|---|",
    ]
    for check in report["checks"]:
        if "coverage" in check:
            observed = (
                f"{check['format']}; {check['coverage']['resources']} resource; "
                f"payload SHA-256 `{check['resource']['payload_sha256']}`"
            )
        elif "bfd_format_observed" in check:
            observed = f"REA/objdump BFD `{check['bfd_format_observed']}`; exit {check['provider_exit_code']}"
        else:
            observed = (
                f"inventory `{check['inventory_format']}` / `{check['inventory_architecture']}`; "
                f"direct objdump BFD `{check['direct_objdump_bfd_format']}`"
            )
        evidence_ref = check.get("evidence_file", check.get("direct_objdump_output", "—"))
        lines.append(
            f"| {check['check']} | {check['status']} | {observed} | `{evidence_ref}` |"
        )
    lines.extend(["", "## Scope", ""])
    for item in report["scope_and_limitations"]:
        lines.append(f"- {item}")
    lines.extend([
        "",
        "Reproduce from the repository root with `python3 analysis/tools/rea_smoke_test.py`. "
        "The script creates fixtures in a temporary directory and stores the raw REA JSON "
        "Evidence beneath `analysis/report/rea-smoke/`.",
        "",
    ])
    return "\n".join(lines)


def main() -> int:
    try:
        report = run()
    except Exception as exc:
        print(f"REA smoke test failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    _write_json(REPORT_ROOT / "rea-smoke-test.json", report)
    (REPORT_ROOT / "rea-smoke-test.md").write_text(_markdown(report), encoding="utf-8")
    for check in report["checks"]:
        print(f"{check['status']}: {check['check']}")
    print(f"REA smoke report: {REPORT_ROOT / 'rea-smoke-test.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
