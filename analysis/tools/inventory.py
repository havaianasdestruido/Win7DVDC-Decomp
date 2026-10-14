#!/usr/bin/env python3
"""Read-only recursive artifact inventory for bin/ (Python standard library only).

This is a signature-and-hash inventory, not a substitute for a format-specific
parser. It never follows symlinks or writes into the input tree. The default
reports are written beneath analysis/report/.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import struct
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ROOT = REPO_ROOT / "bin"
REPORT_ROOT = REPO_ROOT / "analysis" / "report"
CHUNK_BYTES = 1024 * 1024

PE_MACHINES = {
    0x014C: "x86",
    0x0166: "MIPS R4000",
    0x01C0: "ARM",
    0x01C2: "Thumb",
    0x01C4: "ARMv7",
    0x01D3: "MIPS16",
    0x0200: "Itanium",
    0x8664: "x86-64",
    0x9041: "M32R",
    0xAA64: "ARM64",
    0x5032: "RISC-V 32-bit",
    0x5064: "RISC-V 64-bit",
    0x5128: "RISC-V 128-bit",
    0x6232: "LoongArch 32-bit",
    0x6264: "LoongArch 64-bit",
}

ELF_MACHINES = {
    2: "SPARC",
    3: "x86",
    8: "MIPS",
    20: "PowerPC",
    21: "PowerPC64",
    22: "IBM S/390",
    40: "ARM",
    42: "SuperH",
    43: "SPARC V9",
    62: "x86-64",
    83: "AVR",
    183: "AArch64",
    243: "RISC-V",
    247: "BPF",
    258: "LoongArch",
}


def _unknown(format_name: str, *, note: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "format": format_name,
        "architecture": None,
        "bits": None,
        "endianness": None,
        "metadata": {},
        "detection": "header signature",
    }
    if note:
        result["note"] = note
    return result


def _pe_details(stream: BinaryIO, size: int) -> dict[str, Any]:
    if size < 64:
        return _unknown("DOS MZ (truncated header)")
    stream.seek(60)
    pointer = stream.read(4)
    if len(pointer) != 4:
        return _unknown("DOS MZ (truncated header)")
    pe_offset = struct.unpack("<I", pointer)[0]
    if pe_offset > size - 4:
        return _unknown("DOS MZ (invalid PE-header offset)")
    stream.seek(pe_offset)
    signature = stream.read(4)
    if signature != b"PE\0\0":
        return _unknown("DOS MZ (PE signature not found)")
    coff = stream.read(20)
    if len(coff) != 20:
        return _unknown("PE/COFF (truncated COFF header)")
    machine, section_count, timestamp, symbol_offset, symbol_count, optional_size, characteristics = struct.unpack(
        "<HHIIIHH", coff
    )
    optional_offset = pe_offset + 24
    stream.seek(optional_offset)
    optional = stream.read(optional_size)
    if len(optional) < min(optional_size, 2):
        return _unknown("PE/COFF (truncated optional header)")

    optional_magic = struct.unpack_from("<H", optional)[0] if len(optional) >= 2 else 0
    bitness = {0x10B: 32, 0x20B: 64}.get(optional_magic)
    machine_name = PE_MACHINES.get(machine, f"unknown COFF machine 0x{machine:04x}")
    is_dll = bool(characteristics & 0x2000)
    pe_kind = "PE32+" if optional_magic == 0x20B else "PE32" if optional_magic == 0x10B else "PE/COFF"
    label = "DLL" if is_dll else "image"
    result = {
        "format": f"{pe_kind} {label}",
        "architecture": machine_name,
        "bits": bitness,
        "endianness": "little",
        "metadata": {
            "machine": f"0x{machine:04x}",
            "section_count": section_count,
            "coff_timestamp_raw": timestamp,
            "coff_symbol_table_offset": symbol_offset,
            "coff_symbol_count": symbol_count,
            "optional_header_magic": f"0x{optional_magic:04x}",
            "optional_header_size": optional_size,
            "characteristics": f"0x{characteristics:04x}",
            "is_dll": is_dll,
            "entry_point_rva": struct.unpack_from("<I", optional, 16)[0]
            if len(optional) >= 20
            else None,
            "subsystem": struct.unpack_from("<H", optional, 68)[0]
            if len(optional) >= 70
            else None,
        },
        "detection": "MZ header, PE signature, COFF machine and optional-header magic",
    }
    if optional_magic not in (0x10B, 0x20B):
        result["note"] = "The PE optional-header magic is not PE32 or PE32+; bitness is unknown."
    return result


def detect_format(stream: BinaryIO, size: int) -> dict[str, Any]:
    """Classify common executable/container signatures and extract basic ABI facts."""
    stream.seek(0)
    head = stream.read(4096)
    if head.startswith(b"\x7fELF"):
        if len(head) < 20:
            return _unknown("ELF (truncated header)")
        elf_class, data_encoding = head[4], head[5]
        bits = {1: 32, 2: 64}.get(elf_class)
        endian = {1: "little", 2: "big"}.get(data_encoding)
        if endian is None:
            return _unknown("ELF (invalid EI_DATA)")
        machine = int.from_bytes(head[18:20], endian)
        elf_type = int.from_bytes(head[16:18], endian)
        architecture = ELF_MACHINES.get(machine, f"unknown ELF machine {machine}")
        return {
            "format": "ELF",
            "architecture": architecture,
            "bits": bits,
            "endianness": endian,
            "metadata": {
                "elf_class": elf_class,
                "ei_data": data_encoding,
                "machine": machine,
                "object_type": elf_type,
                "entry_point": int.from_bytes(
                    head[24:32] if bits == 64 else head[24:28], endian
                )
                if len(head) >= (32 if bits == 64 else 28)
                else None,
            },
            "detection": "ELF identification bytes and ELF header",
        }

    if head.startswith(b"MZ"):
        return _pe_details(stream, size)

    macho = {
        b"\xce\xfa\xed\xfe": (32, "little"),
        b"\xfe\xed\xfa\xce": (32, "big"),
        b"\xcf\xfa\xed\xfe": (64, "little"),
        b"\xfe\xed\xfa\xcf": (64, "big"),
    }
    if head[:4] in macho:
        bits, endian = macho[head[:4]]
        if len(head) < 12:
            return _unknown(f"Mach-O {bits}-bit (truncated header)")
        cpu = int.from_bytes(head[4:8], endian)
        cpu_base = cpu & 0x00FFFFFF
        cpu_arch = {
            7: "x86",
            12: "ARM",
            18: "PowerPC",
        }.get(cpu_base, f"unknown Mach-O CPU 0x{cpu:08x}")
        if cpu & 0x01000000:
            cpu_arch = {"x86": "x86-64", "ARM": "ARM64", "PowerPC": "PowerPC64"}.get(
                cpu_arch, cpu_arch
            )
        return {
            "format": "Mach-O",
            "architecture": cpu_arch,
            "bits": bits,
            "endianness": endian,
            "metadata": {"cpu_type": f"0x{cpu:08x}"},
            "detection": "Mach-O magic and mach_header CPU type",
        }
    if head[:4] in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"):
        return _unknown(
            "Mach-O universal / Java class (CAFEBABE family)",
            note="The leading bytes are ambiguous without a format-specific parser.",
        )

    signatures: tuple[tuple[bytes, str], ...] = (
        (b"!<arch>\n", "ar archive"),
        (b"\x00asm", "WebAssembly"),
        (b"SQLite format 3\x00", "SQLite database"),
        (b"PK\x03\x04", "ZIP archive"),
        (b"PK\x05\x06", "ZIP archive (empty)"),
        (b"PK\x07\x08", "ZIP archive (spanned)"),
        (b"\x1f\x8b", "gzip stream"),
        (b"BZh", "bzip2 stream"),
        (b"\xfd7zXZ\x00", "XZ stream"),
        (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
        (b"Rar!\x1a\x07", "RAR archive"),
        (b"MSCF", "Microsoft Cabinet"),
        (b"%PDF-", "PDF document"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "Compound File Binary"),
    )
    for signature, name in signatures:
        if head.startswith(signature):
            return _unknown(name)
    if head.startswith(b"#!"):
        return _unknown("script (shebang)")
    if not head:
        return _unknown("empty file")
    return _unknown("unrecognized data")


def _file_record(path: Path, root: Path, *, symlink: bool = False) -> dict[str, Any]:
    relative = path.relative_to(root).as_posix()
    if symlink:
        try:
            link_target = os.readlink(path)
            link_stat = path.lstat()
            return {
                "path": relative,
                "kind": "symlink",
                "size_bytes": link_stat.st_size,
                "sha256": None,
                "hash_stable": None,
                "format": "symbolic link (target not followed)",
                "architecture": None,
                "bits": None,
                "endianness": None,
                "metadata": {"link_target": link_target},
                "status": "not_hashed_by_policy",
            }
        except OSError as exc:
            return {
                "path": relative,
                "kind": "symlink",
                "size_bytes": None,
                "sha256": None,
                "hash_stable": None,
                "format": "symbolic link (target not followed)",
                "architecture": None,
                "bits": None,
                "endianness": None,
                "metadata": {},
                "status": "read_error",
                "error": f"{type(exc).__name__}: {exc}",
            }

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd: int | None = None
    try:
        fd = os.open(path, flags)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            return {
                "path": relative,
                "kind": "non_regular",
                "size_bytes": before.st_size,
                "sha256": None,
                "hash_stable": None,
                "format": "non-regular filesystem object",
                "architecture": None,
                "bits": None,
                "endianness": None,
                "metadata": {},
                "status": "not_hashed_by_policy",
            }
        with os.fdopen(fd, "rb", closefd=False) as stream:
            detected = detect_format(stream, before.st_size)
            stream.seek(0)
            digest = hashlib.sha256()
            bytes_read = 0
            while True:
                block = stream.read(CHUNK_BYTES)
                if not block:
                    break
                bytes_read += len(block)
                digest.update(block)
            after = os.fstat(stream.fileno())
        stable = (
            before.st_size == after.st_size
            and before.st_mtime_ns == after.st_mtime_ns
            and before.st_ctime_ns == after.st_ctime_ns
            and bytes_read == before.st_size
        )
        return {
            "path": relative,
            "kind": "regular_file",
            "size_bytes": before.st_size,
            "sha256": digest.hexdigest(),
            "hash_stable": stable,
            **detected,
            "status": "ok" if stable else "changed_during_scan",
        }
    except OSError as exc:
        return {
            "path": relative,
            "kind": "regular_file",
            "size_bytes": None,
            "sha256": None,
            "hash_stable": False,
            "format": "unknown (read error)",
            "architecture": None,
            "bits": None,
            "endianness": None,
            "metadata": {},
            "detection": "not completed",
            "status": "read_error",
            "error": f"{type(exc).__name__}: {exc}",
        }
    finally:
        if fd is not None:
            os.close(fd)


def scan_root(root: Path) -> dict[str, Any]:
    """Recursively inventory one directory without following links or changing inputs."""
    root = root.absolute()
    scan_started = datetime.now(timezone.utc).isoformat(timespec="seconds")
    files: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    if not root.exists():
        return {
            "schema_version": 1,
            "scanned_at_utc": scan_started,
            "root": str(root),
            "root_exists": False,
            "status": "root_missing",
            "files": [],
            "errors": [{"path": str(root), "error": "input directory does not exist"}],
            "summary": {
                "entries": 0,
                "regular_files": 0,
                "symlinks": 0,
                "total_regular_file_bytes": 0,
                "stable_hashes": 0,
                "unstable_or_failed_hashes": 0,
                "duplicate_hash_groups": 0,
            },
            "duplicate_hashes": [],
        }
    if root.is_symlink() or not root.is_dir():
        reason = "input root is a symlink" if root.is_symlink() else "input root is not a directory"
        return {
            "schema_version": 1,
            "scanned_at_utc": scan_started,
            "root": str(root),
            "root_exists": True,
            "status": "root_rejected",
            "files": [],
            "errors": [{"path": str(root), "error": reason}],
            "summary": {
                "entries": 0,
                "regular_files": 0,
                "symlinks": 0,
                "total_regular_file_bytes": 0,
                "stable_hashes": 0,
                "unstable_or_failed_hashes": 0,
                "duplicate_hash_groups": 0,
            },
            "duplicate_hashes": [],
        }

    stack = [root]
    while stack:
        directory = stack.pop()
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda item: item.name, reverse=True)
        except OSError as exc:
            errors.append({
                "path": directory.relative_to(root).as_posix() or ".",
                "error": f"{type(exc).__name__}: {exc}",
            })
            continue
        for entry in entries:
            path = Path(entry.path)
            try:
                if entry.is_symlink():
                    files.append(_file_record(path, root, symlink=True))
                elif entry.is_dir(follow_symlinks=False):
                    stack.append(path)
                elif entry.is_file(follow_symlinks=False):
                    files.append(_file_record(path, root))
                else:
                    info = entry.stat(follow_symlinks=False)
                    files.append({
                        "path": path.relative_to(root).as_posix(),
                        "kind": "non_regular",
                        "size_bytes": info.st_size,
                        "sha256": None,
                        "hash_stable": None,
                        "format": "non-regular filesystem object",
                        "architecture": None,
                        "bits": None,
                        "endianness": None,
                        "metadata": {},
                        "status": "not_hashed_by_policy",
                    })
            except OSError as exc:
                errors.append({
                    "path": path.relative_to(root).as_posix(),
                    "error": f"{type(exc).__name__}: {exc}",
                })
    files.sort(key=lambda item: item["path"])
    hash_paths: dict[str, list[str]] = {}
    for item in files:
        digest = item.get("sha256")
        if digest:
            hash_paths.setdefault(digest, []).append(item["path"])
    duplicates = [
        {"sha256": digest, "paths": paths}
        for digest, paths in sorted(hash_paths.items())
        if len(paths) > 1
    ]
    regular = [item for item in files if item["kind"] == "regular_file"]
    status = "complete" if not errors and all(item["status"] == "ok" for item in regular) else "partial"
    return {
        "schema_version": 1,
        "scanned_at_utc": scan_started,
        "root": str(root),
        "root_exists": True,
        "status": status,
        "files": files,
        "errors": errors,
        "summary": {
            "entries": len(files),
            "regular_files": len(regular),
            "symlinks": sum(item["kind"] == "symlink" for item in files),
            "total_regular_file_bytes": sum(item["size_bytes"] or 0 for item in regular),
            "stable_hashes": sum(item["status"] == "ok" for item in regular),
            "unstable_or_failed_hashes": sum(item["status"] != "ok" for item in regular),
            "duplicate_hash_groups": len(duplicates),
        },
        "duplicate_hashes": duplicates,
    }


def _markdown(inventory: dict[str, Any]) -> str:
    summary = inventory["summary"]
    exists = "yes" if inventory["root_exists"] else "no"
    lines = [
        "# Binary inventory",
        "",
        f"- Inventory time (UTC): `{inventory['scanned_at_utc']}`",
        f"- Input root: `{inventory['root']}`",
        f"- Input directory exists: **{exists}**",
        f"- Scan status: **{inventory['status']}**",
        f"- Enumerated entries: **{summary['entries']}**",
        f"- Regular files / total bytes: **{summary['regular_files']} / {summary['total_regular_file_bytes']}**",
        f"- Stable SHA-256 digests: **{summary['stable_hashes']}**",
        f"- Duplicate digest groups: **{summary['duplicate_hash_groups']}**",
        "",
        "## Files",
        "",
        "| Path | Size (bytes) | SHA-256 | Detected format | Architecture / bitness | Status |",
        "|---|---:|---|---|---|---|",
    ]
    if inventory["files"]:
        for item in inventory["files"]:
            architecture = item.get("architecture") or "unknown"
            bits = item.get("bits")
            if bits:
                architecture += f" / {bits}-bit"
            lines.append(
                "| `{path}` | {size} | `{digest}` | {format} | {architecture} | {status} |".format(
                    path=item["path"].replace("|", "\\|"),
                    size=item.get("size_bytes") if item.get("size_bytes") is not None else "unknown",
                    digest=item.get("sha256") or "not computed",
                    format=str(item.get("format", "unknown")).replace("|", "\\|"),
                    architecture=architecture.replace("|", "\\|"),
                    status=item.get("status", "unknown"),
                )
            )
    else:
        lines.append("| *No files enumerated.* | — | — | — | — | — |")
    lines.extend(["", "## Scan errors and caveats", ""])
    if inventory["errors"]:
        for error in inventory["errors"]:
            lines.append(f"- `{error['path']}`: {error['error']}")
    else:
        lines.append("- No traversal or read errors were observed.")
    if inventory["status"] == "root_missing":
        lines.append("- `bin/` is absent; no target binary was available for format, architecture, section, symbol, resource, duplicate, packing, or overlay analysis.")
    else:
        lines.append("- Detection is based on a small set of file signatures and basic headers; it is not a complete parser and does not establish whether an artifact is packed, has an overlay, or contains nested executable content.")
    if inventory["duplicate_hashes"]:
        lines.extend(["", "## Duplicate content", ""])
        for item in inventory["duplicate_hashes"]:
            lines.append(f"- SHA-256 `{item['sha256']}`: " + ", ".join(f"`{path}`" for path in item["paths"]))
    return "\n".join(lines) + "\n"


def _write_report(path: Path, content: str) -> None:
    path = path.absolute()
    try:
        path.relative_to(REPORT_ROOT)
    except ValueError as exc:
        raise ValueError(f"report output must be beneath {REPORT_ROOT}") from exc
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT, help="Input root to inventory (default: repository bin/).")
    parser.add_argument("--markdown-out", type=Path, default=REPORT_ROOT / "inventory.md", help="Markdown report path (must be under analysis/report/).")
    parser.add_argument("--json-out", type=Path, default=REPORT_ROOT / "inventory.json", help="Machine-readable report path (must be under analysis/report/).")
    args = parser.parse_args(argv)
    inventory = scan_root(args.root)
    _write_report(args.json_out, json.dumps(inventory, indent=2, sort_keys=True) + "\n")
    _write_report(args.markdown_out, _markdown(inventory))
    print(f"status={inventory['status']} entries={inventory['summary']['entries']} regular_files={inventory['summary']['regular_files']}")
    print(f"markdown={args.markdown_out.absolute()}")
    print(f"json={args.json_out.absolute()}")
    return 0 if inventory["status"] == "complete" else 2


if __name__ == "__main__":
    raise SystemExit(main())
