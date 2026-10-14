#!/usr/bin/env python3
"""Run verified REA 6.5.0 static artifact inspections and save raw JSON Evidence.

Supported adapters here are deliberately narrow and evidence-based:
  * PE32/PE32+ resource identities/payload hashes via inspect-pe-resources.
  * Caller-supplied GNU objdump output via inspect-with-objdump.

The wrapper never executes or writes the selected artifact. Results are saved
under analysis/report/; the PE resource operation is not a decompiler.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Sequence

REA_PACKAGE = "rea-agents"
REA_VERSION = "6.5.0"
ROOT = Path(__file__).resolve().parents[2]
REPORT_ROOT = ROOT / "analysis" / "report"
OBJDUMP_OPERATIONS = (
    "file_headers",
    "section_headers",
    "symbols",
    "relocations",
    "dwarf",
    "disassemble",
    "disassemble_all",
)
_VERSION_CACHE: tuple[list[str], str] | None = None


class ReaInvocationError(RuntimeError):
    """A REA launcher failed, returned an unexpected version, or invalid JSON."""


def _launcher() -> list[str]:
    configured = os.environ.get("REA_COMMAND")
    if configured:
        command = shlex.split(configured)
        if not command:
            raise ReaInvocationError("REA_COMMAND is set but contains no executable")
        return command
    npx = shutil.which("npx")
    if not npx:
        raise ReaInvocationError("npx is unavailable; install REA 6.5.0 or set REA_COMMAND")
    return [npx, "--yes", "--package=rea-agents@6.5.0", "rea"]


def rea_version(timeout: int = 180) -> tuple[list[str], str]:
    """Return the verified package launcher and enforce the documented pin."""
    global _VERSION_CACHE
    if _VERSION_CACHE is not None:
        return _VERSION_CACHE
    launcher = _launcher()
    try:
        process = subprocess.run(
            [*launcher, "--version"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ReaInvocationError(f"Could not query REA version: {exc}") from exc
    if process.returncode != 0:
        raise ReaInvocationError(
            f"REA --version exited {process.returncode}: {process.stderr.strip()}"
        )
    observed = process.stdout.strip().splitlines()[-1].strip() if process.stdout.strip() else ""
    if observed != REA_VERSION:
        raise ReaInvocationError(
            f"Expected REA {REA_VERSION}, observed {observed or 'no version output'}; "
            "use the pinned npx package or set REA_COMMAND to a matching executable."
        )
    _VERSION_CACHE = (launcher, observed)
    return _VERSION_CACHE


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _regular_input(value: str | Path) -> Path:
    path = Path(value).expanduser().absolute()
    try:
        info = path.lstat()
    except OSError as exc:
        raise ReaInvocationError(f"Cannot inspect input path {path}: {exc}") from exc
    if path.is_symlink():
        raise ReaInvocationError(f"Input symlink is not accepted by this wrapper: {path}")
    if not path.is_file():
        raise ReaInvocationError(f"Input must be a regular file: {path}")
    if info.st_size < 0:
        raise ReaInvocationError(f"Input reports an invalid size: {path}")
    return path.resolve(strict=True)


def _report_output(path: Path | None, artifact: Path, digest: str, label: str) -> Path | None:
    if path is None:
        path = REPORT_ROOT / "rea" / f"{artifact.name}.{digest[:12]}.{label}.json"
    path = path.expanduser().absolute()
    try:
        path.resolve(strict=False).relative_to(REPORT_ROOT.resolve())
    except ValueError as exc:
        raise ReaInvocationError(f"Evidence output must be beneath {REPORT_ROOT}") from exc
    return path


def _atomic_write(path: Path, content: str) -> None:
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


def inspect_artifact(
    mode: str,
    artifact_value: str | Path,
    *,
    objdump_operation: str | None = None,
    output: str | Path | None = None,
    timeout: int = 600,
) -> dict[str, Any]:
    """Run one REA CLI inspection and optionally save its unmodified JSON output."""
    artifact = _regular_input(artifact_value)
    digest_before = _sha256(artifact)
    launcher, version = rea_version()
    if mode == "pe-resources":
        label = "pe-resources"
        arguments = ["inspect-pe-resources", str(artifact)]
    elif mode == "objdump":
        if objdump_operation not in OBJDUMP_OPERATIONS:
            raise ReaInvocationError(
                "objdump operation must be one of: " + ", ".join(OBJDUMP_OPERATIONS)
            )
        label = f"objdump-{objdump_operation}"
        arguments = ["inspect-with-objdump", str(artifact), objdump_operation]
    else:
        raise ReaInvocationError(f"Unsupported wrapper mode: {mode}")
    arguments.extend(["--format", "json"])
    command = [*launcher, *arguments]
    try:
        process = subprocess.run(
            command,
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise ReaInvocationError(f"REA inspection exceeded {timeout} seconds") from exc
    except OSError as exc:
        raise ReaInvocationError(f"Could not launch REA: {exc}") from exc
    if process.returncode != 0:
        detail = process.stderr.strip() or process.stdout.strip()
        raise ReaInvocationError(f"REA exited {process.returncode}: {detail[:4000]}")
    try:
        evidence = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        raise ReaInvocationError(
            f"REA returned non-JSON output despite --format json: {exc}"
        ) from exc
    digest_after = _sha256(artifact)
    result: dict[str, Any] = {
        "package": REA_PACKAGE,
        "version": version,
        "mode": mode,
        "objdump_operation": objdump_operation,
        "command": command,
        "artifact_path": str(artifact),
        "artifact_sha256_before": digest_before,
        "artifact_sha256_after": digest_after,
        "input_unchanged": digest_before == digest_after,
        "evidence": evidence,
        "stderr": process.stderr,
    }
    output_path = _report_output(Path(output) if output is not None else None, artifact, digest_before, label)
    if output_path is not None:
        # Save the exact REA JSON Evidence, not a rewritten or normalized derivative.
        _atomic_write(output_path, process.stdout.rstrip() + "\n")
        result["evidence_path"] = str(output_path)
    return result


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="mode", required=True)
    pe = subparsers.add_parser("pe-resources", help="Inspect PE32/PE32+ resources using REA.")
    pe.add_argument("artifact", type=Path)
    pe.add_argument("--output", type=Path, help="Raw JSON Evidence output beneath analysis/report/.")
    pe.add_argument("--timeout", type=int, default=600)
    objdump = subparsers.add_parser("objdump", help="Capture a verified GNU objdump operation through REA.")
    objdump.add_argument("artifact", type=Path)
    objdump.add_argument("operation", choices=OBJDUMP_OPERATIONS)
    objdump.add_argument("--output", type=Path, help="Raw JSON Evidence output beneath analysis/report/.")
    objdump.add_argument("--timeout", type=int, default=600)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        result = inspect_artifact(
            args.mode,
            args.artifact,
            objdump_operation=getattr(args, "operation", None),
            output=args.output,
            timeout=args.timeout,
        )
    except ReaInvocationError as exc:
        print(f"rea_inspect: {exc}", file=sys.stderr)
        return 1
    if "evidence_path" in result:
        print(f"saved={result['evidence_path']}")
    print(f"rea={result['package']}@{result['version']} mode={result['mode']}")
    print(f"artifact_sha256={result['artifact_sha256_before']} unchanged={str(result['input_unchanged']).lower()}")
    if not result["input_unchanged"]:
        print("warning: input SHA-256 changed while REA ran; review the Evidence before relying on it.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
