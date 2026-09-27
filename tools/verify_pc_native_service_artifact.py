from __future__ import annotations

import argparse
import hashlib
import json
import ntpath
import os
import re
import shutil
import stat
import sys
import tempfile
from pathlib import Path
from typing import BinaryIO

FORMAT_VERSION = "pc.native.device_service.artifact_manifest.v1"
EXPECTED_REPOSITORY = "foto6/help-pc-1"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
PROTECTED_ROOT = ntpath.normcase(ntpath.normpath(r"E:\manhwa"))


class ArtifactVerificationError(RuntimeError):
    pass


def _protected(path: str | os.PathLike[str]) -> bool:
    candidate = ntpath.normcase(ntpath.normpath(str(path).replace("/", "\\")))
    return candidate == PROTECTED_ROOT or candidate.startswith(PROTECTED_ROOT + "\\")


def _reject_protected(path: str | os.PathLike[str], label: str) -> None:
    if _protected(path):
        raise ArtifactVerificationError(f"{label} uses a protected path")


def _is_reparse(st: os.stat_result) -> bool:
    attrs = getattr(st, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(st.st_mode) or bool(attrs & reparse_flag)


def _assert_no_link_components(path: Path, label: str) -> None:
    current = Path(path.anchor) if path.anchor else Path()
    parts = path.parts[1:] if path.anchor else path.parts
    for part in parts:
        current = current / part
        try:
            st = os.lstat(current)
        except FileNotFoundError:
            raise ArtifactVerificationError(f"{label} path does not exist") from None
        if _is_reparse(st):
            raise ArtifactVerificationError(f"{label} path contains a symlink/reparse point")


def _canonical_existing_file(raw_path: str, label: str) -> Path:
    if not raw_path:
        raise ArtifactVerificationError(f"{label} path is required")
    _reject_protected(raw_path, label)
    candidate = Path(raw_path)
    if not candidate.is_absolute():
        raise ArtifactVerificationError(f"{label} path must be absolute")
    candidate = Path(os.path.abspath(candidate))
    _reject_protected(candidate, label)
    _assert_no_link_components(candidate, label)
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError:
        raise ArtifactVerificationError(f"{label} path does not exist") from None
    _reject_protected(resolved, label)
    if os.path.normcase(str(candidate)) != os.path.normcase(str(resolved)):
        raise ArtifactVerificationError(f"{label} path is not canonical")
    st = os.stat(resolved, follow_symlinks=False)
    if not stat.S_ISREG(st.st_mode):
        raise ArtifactVerificationError(f"{label} must be a regular file")
    return resolved


def _canonical_stage_parent(raw_path: str) -> Path:
    if not raw_path:
        raise ArtifactVerificationError("stage root is required")
    _reject_protected(raw_path, "stage")
    candidate = Path(raw_path)
    if not candidate.is_absolute():
        raise ArtifactVerificationError("stage root must be absolute")
    candidate = Path(os.path.abspath(candidate))
    _reject_protected(candidate, "stage")
    parent = candidate.parent
    _assert_no_link_components(parent, "stage parent")
    resolved_parent = parent.resolve(strict=True)
    if os.path.normcase(str(parent)) != os.path.normcase(str(resolved_parent)):
        raise ArtifactVerificationError("stage parent is not canonical")
    return resolved_parent / candidate.name


def _read_exact(path: Path) -> bytes:
    with path.open("rb") as handle:
        return handle.read()


def _require_keys(value: object, expected: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != expected:
        raise ArtifactVerificationError(f"{label} keys mismatch")
    return value


def _require_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ArtifactVerificationError(f"{label} must be a lowercase SHA-256")
    return value


def _require_git_sha(value: object, label: str) -> str:
    if not isinstance(value, str) or GIT_SHA_RE.fullmatch(value) is None:
        raise ArtifactVerificationError(f"{label} must be a lowercase 40-hex git SHA")
    return value


def _hash_stream(handle: BinaryIO) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    while True:
        chunk = handle.read(1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
        total += len(chunk)
    return digest.hexdigest(), total


def _file_identity(st: os.stat_result) -> tuple[int, int, int]:
    return (int(st.st_dev), int(st.st_ino), int(st.st_size))


def validate_manifest(
    *,
    manifest_path: str,
    artifact_path: str,
    expected_artifact_sha256: str,
    expected_producer_sha: str,
    expected_package_version: str,
    expected_protocol_version: str,
    expected_capability_contract_version: str,
    expected_capability_digest: str,
) -> tuple[dict, Path, BinaryIO]:
    manifest_file = _canonical_existing_file(manifest_path, "manifest")
    artifact_file = _canonical_existing_file(artifact_path, "artifact")

    expected_artifact_sha256 = _require_sha256(expected_artifact_sha256, "expected artifact sha256")
    expected_producer_sha = _require_git_sha(expected_producer_sha, "expected producer sha")
    expected_capability_digest = _require_sha256(expected_capability_digest, "expected capability digest")
    if not expected_package_version:
        raise ArtifactVerificationError("expected package version is required")
    if not expected_protocol_version:
        raise ArtifactVerificationError("expected protocol version is required")
    if not expected_capability_contract_version:
        raise ArtifactVerificationError("expected capability contract version is required")

    try:
        raw_manifest = json.loads(_read_exact(manifest_file).decode("utf-8"))
    except Exception as exc:
        raise ArtifactVerificationError("manifest is not valid UTF-8 JSON") from exc

    manifest = _require_keys(
        raw_manifest,
        {"format_version", "producer", "artifact", "contracts"},
        "manifest",
    )
    if manifest["format_version"] != FORMAT_VERSION:
        raise ArtifactVerificationError("artifact manifest version mismatch")

    producer = _require_keys(
        manifest["producer"],
        {"repository", "sha", "package_version"},
        "producer",
    )
    artifact = _require_keys(
        manifest["artifact"],
        {"filename", "sha256", "size_bytes"},
        "artifact",
    )
    contracts = _require_keys(
        manifest["contracts"],
        {
            "protocol_version",
            "capability_contract_version",
            "capability_digest",
        },
        "contracts",
    )

    producer_sha = _require_git_sha(producer["sha"], "producer sha")
    artifact_sha = _require_sha256(artifact["sha256"], "artifact sha256")
    capability_digest = _require_sha256(contracts["capability_digest"], "capability digest")

    if producer["repository"] != EXPECTED_REPOSITORY:
        raise ArtifactVerificationError("producer repository mismatch")
    if producer_sha != expected_producer_sha:
        raise ArtifactVerificationError("producer sha mismatch")
    if producer["package_version"] != expected_package_version:
        raise ArtifactVerificationError("package version mismatch")
    if contracts["protocol_version"] != expected_protocol_version:
        raise ArtifactVerificationError("protocol version mismatch")
    if contracts["capability_contract_version"] != expected_capability_contract_version:
        raise ArtifactVerificationError("capability contract version mismatch")
    if capability_digest != expected_capability_digest:
        raise ArtifactVerificationError("capability digest mismatch")
    if artifact_sha != expected_artifact_sha256:
        raise ArtifactVerificationError("artifact manifest sha256 mismatch")
    if not isinstance(artifact["filename"], str) or Path(artifact["filename"]).name != artifact["filename"]:
        raise ArtifactVerificationError("artifact filename is invalid")
    if not artifact["filename"].endswith(".whl"):
        raise ArtifactVerificationError("production artifact must be a wheel")
    if artifact_file.name != artifact["filename"]:
        raise ArtifactVerificationError("artifact filename does not match manifest")
    if isinstance(artifact["size_bytes"], bool) or not isinstance(artifact["size_bytes"], int) or artifact["size_bytes"] < 1:
        raise ArtifactVerificationError("artifact size is invalid")

    handle = artifact_file.open("rb", buffering=0)
    try:
        opened = os.fstat(handle.fileno())
        current = os.stat(artifact_file, follow_symlinks=False)
        if _file_identity(opened) != _file_identity(current):
            raise ArtifactVerificationError("artifact identity changed before hashing")
        digest, size = _hash_stream(handle)
        if digest != expected_artifact_sha256:
            raise ArtifactVerificationError("artifact sha256 mismatch")
        if size != artifact["size_bytes"]:
            raise ArtifactVerificationError("artifact size mismatch")
        current_after = os.stat(artifact_file, follow_symlinks=False)
        if _file_identity(opened) != _file_identity(current_after):
            raise ArtifactVerificationError("artifact identity changed during hashing")
        handle.seek(0)
        return manifest, artifact_file, handle
    except Exception:
        handle.close()
        raise


def verify_and_stage(
    *,
    manifest_path: str,
    artifact_path: str,
    stage_root: str,
    expected_artifact_sha256: str,
    expected_producer_sha: str,
    expected_package_version: str,
    expected_protocol_version: str,
    expected_capability_contract_version: str,
    expected_capability_digest: str,
) -> dict:
    manifest, artifact_file, handle = validate_manifest(
        manifest_path=manifest_path,
        artifact_path=artifact_path,
        expected_artifact_sha256=expected_artifact_sha256,
        expected_producer_sha=expected_producer_sha,
        expected_package_version=expected_package_version,
        expected_protocol_version=expected_protocol_version,
        expected_capability_contract_version=expected_capability_contract_version,
        expected_capability_digest=expected_capability_digest,
    )
    stage_dir = _canonical_stage_parent(stage_root)
    staged = stage_dir / manifest["artifact"]["filename"]
    tmp: Path | None = None
    try:
        stage_dir.mkdir(mode=0o700)
        fd, raw_tmp = tempfile.mkstemp(prefix=".artifact-", suffix=".tmp", dir=stage_dir)
        tmp = Path(raw_tmp)
        with os.fdopen(fd, "wb") as target:
            shutil.copyfileobj(handle, target, length=1024 * 1024)
            target.flush()
            os.fsync(target.fileno())
        handle.close()

        staged_digest = hashlib.sha256(tmp.read_bytes()).hexdigest()
        if staged_digest != expected_artifact_sha256:
            raise ArtifactVerificationError("staged artifact sha256 mismatch")
        os.replace(tmp, staged)
        tmp = None
        final_digest = hashlib.sha256(staged.read_bytes()).hexdigest()
        if final_digest != expected_artifact_sha256:
            raise ArtifactVerificationError("final staged artifact sha256 mismatch")
        return {
            "staged_artifact": str(staged),
            "artifact_sha256": expected_artifact_sha256,
            "producer_sha": manifest["producer"]["sha"],
            "package_version": manifest["producer"]["package_version"],
            "protocol_version": manifest["contracts"]["protocol_version"],
            "capability_contract_version": manifest["contracts"]["capability_contract_version"],
            "capability_digest": manifest["contracts"]["capability_digest"],
        }
    except Exception:
        if not handle.closed:
            handle.close()
        if tmp is not None:
            try:
                tmp.unlink()
            except FileNotFoundError:
                pass
        shutil.rmtree(stage_dir, ignore_errors=True)
        raise


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Verify and stage an immutable PC native service wheel.")
    parser.add_argument("--artifact", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--stage-root", required=True)
    parser.add_argument("--expected-artifact-sha256", required=True)
    parser.add_argument("--expected-producer-sha", required=True)
    parser.add_argument("--expected-package-version", required=True)
    parser.add_argument("--expected-protocol-version", required=True)
    parser.add_argument("--expected-capability-contract-version", required=True)
    parser.add_argument("--expected-capability-digest", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = verify_and_stage(
            manifest_path=args.manifest,
            artifact_path=args.artifact,
            stage_root=args.stage_root,
            expected_artifact_sha256=args.expected_artifact_sha256,
            expected_producer_sha=args.expected_producer_sha,
            expected_package_version=args.expected_package_version,
            expected_protocol_version=args.expected_protocol_version,
            expected_capability_contract_version=args.expected_capability_contract_version,
            expected_capability_digest=args.expected_capability_digest,
        )
    except ArtifactVerificationError as exc:
        print(f"artifact verification failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
