"""Unit tests for inventory.py; all fixtures are synthetic and temporary."""
from __future__ import annotations

import io
import struct
import tempfile
import unittest
from pathlib import Path

from inventory import detect_format, scan_root


def make_pe(machine: int = 0x014C, magic: int = 0x010B) -> bytes:
    optional_size = 224 if magic == 0x010B else 240
    data = bytearray(0x200)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 60, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into(
        "<HHIIIHH",
        data,
        0x84,
        machine,
        0,
        0x12345678,
        0,
        0,
        optional_size,
        0x0102,
    )
    optional = 0x98
    struct.pack_into("<H", data, optional, magic)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<I", data, optional + 60, 0x200)
    struct.pack_into("<I", data, optional + (92 if magic == 0x010B else 108), 16)
    return bytes(data)


class DetectFormatTests(unittest.TestCase):
    def test_pe32_x86_header_facts(self) -> None:
        data = make_pe()
        result = detect_format(io.BytesIO(data), len(data))
        self.assertEqual(result["format"], "PE32 image")
        self.assertEqual(result["architecture"], "x86")
        self.assertEqual(result["bits"], 32)
        self.assertEqual(result["endianness"], "little")
        self.assertEqual(result["metadata"]["coff_timestamp_raw"], 0x12345678)
        self.assertEqual(result["metadata"]["entry_point_rva"], 0x1000)

    def test_pe32_plus_x64_dll(self) -> None:
        data = bytearray(make_pe(0x8664, 0x020B))
        struct.pack_into("<H", data, 0x84 + 18, 0x2102)
        result = detect_format(io.BytesIO(data), len(data))
        self.assertEqual(result["format"], "PE32+ DLL")
        self.assertEqual(result["architecture"], "x86-64")
        self.assertEqual(result["bits"], 64)
        self.assertTrue(result["metadata"]["is_dll"])

    def test_elf64_little_endian(self) -> None:
        data = bytearray(64)
        data[:4] = b"\x7fELF"
        data[4:7] = bytes((2, 1, 1))
        struct.pack_into("<HHI", data, 16, 2, 62, 1)
        struct.pack_into("<Q", data, 24, 0x401000)
        result = detect_format(io.BytesIO(data), len(data))
        self.assertEqual(result["format"], "ELF")
        self.assertEqual(result["architecture"], "x86-64")
        self.assertEqual(result["bits"], 64)
        self.assertEqual(result["endianness"], "little")
        self.assertEqual(result["metadata"]["entry_point"], 0x401000)

    def test_unknown_data_is_not_guessed_from_extension(self) -> None:
        data = b"opaque data, not an executable"
        result = detect_format(io.BytesIO(data), len(data))
        self.assertEqual(result["format"], "unrecognized data")
        self.assertIsNone(result["architecture"])


class ScanRootTests(unittest.TestCase):
    def test_missing_root_is_reported_without_fabricated_entries(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            result = scan_root(Path(temp) / "absent")
        self.assertEqual(result["status"], "root_missing")
        self.assertFalse(result["root_exists"])
        self.assertEqual(result["files"], [])
        self.assertEqual(result["summary"]["regular_files"], 0)

    def test_nested_hashes_duplicates_and_symlink_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "bin"
            (root / "nested").mkdir(parents=True)
            payload = make_pe()
            (root / "one.exe").write_bytes(payload)
            (root / "nested" / "two.dll").write_bytes(payload)
            try:
                (root / "linked.exe").symlink_to(root / "one.exe")
            except (NotImplementedError, OSError):
                self.skipTest("symlink creation is not available")
            result = scan_root(root)
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["summary"]["entries"], 3)
        self.assertEqual(result["summary"]["regular_files"], 2)
        self.assertEqual(result["summary"]["symlinks"], 1)
        self.assertEqual(result["summary"]["duplicate_hash_groups"], 1)
        self.assertIsNone(next(item for item in result["files"] if item["kind"] == "symlink")["sha256"])
        self.assertEqual(result["duplicate_hashes"][0]["paths"], ["nested/two.dll", "one.exe"])


if __name__ == "__main__":
    unittest.main()
