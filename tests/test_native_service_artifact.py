from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from pc_remote_transport.executor_adapter import (
    NATIVE_CONTROL_PROTOCOL_V1,
    NATIVE_TOOL_REGISTRY_V1,
    TOOL_REGISTRY_DIGEST,
)

ROOT = Path(__file__).resolve().parents[1]
VERIFIER_PATH = ROOT / "tools" / "verify_pc_native_service_artifact.py"
BOOTSTRAP_PATH = ROOT / "tools" / "install_pc_native_device_service.ps1"
EXPECTED_PRODUCER = "a" * 40
EXPECTED_VERSION = "0.1.0"

spec = importlib.util.spec_from_file_location("service_artifact_verifier", VERIFIER_PATH)
assert spec is not None and spec.loader is not None
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


@pytest.fixture(scope="session")
def built_wheel(tmp_path_factory: pytest.TempPathFactory) -> Path:
    output = tmp_path_factory.mktemp("service-wheel")
    subprocess.run(
        [sys.executable, "-m", "pip", "wheel", ".", "--no-deps", "-w", str(output)],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    shutil.rmtree(ROOT / "build", ignore_errors=True)
    wheels = list(output.glob("pc_executor-*.whl"))
    assert len(wheels) == 1
    return wheels[0]


def make_manifest(
    tmp_path: Path,
    artifact: Path,
    *,
    producer_sha: str = EXPECTED_PRODUCER,
    package_version: str = EXPECTED_VERSION,
    protocol_version: str = NATIVE_CONTROL_PROTOCOL_V1,
    capability_contract_version: str = NATIVE_TOOL_REGISTRY_V1,
    capability_digest: str = TOOL_REGISTRY_DIGEST,
    artifact_sha256: str | None = None,
) -> Path:
    raw = artifact.read_bytes()
    digest = artifact_sha256 or hashlib.sha256(raw).hexdigest()
    manifest = {
        "format_version": verifier.FORMAT_VERSION,
        "producer": {
            "repository": verifier.EXPECTED_REPOSITORY,
            "sha": producer_sha,
            "package_version": package_version,
        },
        "artifact": {
            "filename": artifact.name,
            "sha256": digest,
            "size_bytes": len(raw),
        },
        "contracts": {
            "protocol_version": protocol_version,
            "capability_contract_version": capability_contract_version,
            "capability_digest": capability_digest,
        },
    }
    path = tmp_path / "artifact-manifest.json"
    path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    return path


def verify_kwargs(tmp_path: Path, artifact: Path, manifest: Path) -> dict:
    return {
        "manifest_path": str(manifest),
        "artifact_path": str(artifact),
        "stage_root": str(tmp_path / "stage"),
        "expected_artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
        "expected_producer_sha": EXPECTED_PRODUCER,
        "expected_package_version": EXPECTED_VERSION,
        "expected_protocol_version": NATIVE_CONTROL_PROTOCOL_V1,
        "expected_capability_contract_version": NATIVE_TOOL_REGISTRY_V1,
        "expected_capability_digest": TOOL_REGISTRY_DIGEST,
    }


def assert_rejected_without_stage(kwargs: dict, match: str) -> None:
    stage = Path(kwargs["stage_root"])
    with pytest.raises(verifier.ArtifactVerificationError, match=match):
        verifier.verify_and_stage(**kwargs)
    assert not stage.exists()


def copied_artifact(tmp_path: Path, built_wheel: Path) -> Path:
    artifact = tmp_path / built_wheel.name
    shutil.copyfile(built_wheel, artifact)
    return artifact


def test_modified_artifact_rejected_before_install_mutation(tmp_path: Path, built_wheel: Path) -> None:
    artifact = copied_artifact(tmp_path, built_wheel)
    manifest = make_manifest(tmp_path, artifact)
    expected = hashlib.sha256(artifact.read_bytes()).hexdigest()
    artifact.write_bytes(artifact.read_bytes() + b"tampered")
    kwargs = verify_kwargs(tmp_path, artifact, manifest)
    kwargs["expected_artifact_sha256"] = expected
    assert_rejected_without_stage(kwargs, "artifact sha256 mismatch")


def test_wrong_producer_sha_rejected_before_install_mutation(tmp_path: Path, built_wheel: Path) -> None:
    artifact = copied_artifact(tmp_path, built_wheel)
    manifest = make_manifest(tmp_path, artifact, producer_sha="b" * 40)
    assert_rejected_without_stage(verify_kwargs(tmp_path, artifact, manifest), "producer sha mismatch")


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("protocol_version", "pc.native.control.v0", "protocol version mismatch"),
        ("capability_contract_version", "pc.native.tool_registry.v0", "capability contract version mismatch"),
        ("capability_digest", "0" * 64, "capability digest mismatch"),
    ],
)
def test_wrong_contract_metadata_rejected_before_install_mutation(
    tmp_path: Path,
    built_wheel: Path,
    field: str,
    value: str,
    expected: str,
) -> None:
    artifact = copied_artifact(tmp_path, built_wheel)
    overrides = {field: value}
    manifest = make_manifest(tmp_path, artifact, **overrides)
    assert_rejected_without_stage(verify_kwargs(tmp_path, artifact, manifest), expected)


def test_missing_manifest_rejected_before_install_mutation(tmp_path: Path, built_wheel: Path) -> None:
    artifact = copied_artifact(tmp_path, built_wheel)
    kwargs = verify_kwargs(tmp_path, artifact, tmp_path / "missing.json")
    assert_rejected_without_stage(kwargs, "manifest path does not exist")


def test_stale_package_version_rejected_before_install_mutation(tmp_path: Path, built_wheel: Path) -> None:
    artifact = copied_artifact(tmp_path, built_wheel)
    manifest = make_manifest(tmp_path, artifact, package_version="0.0.9")
    assert_rejected_without_stage(verify_kwargs(tmp_path, artifact, manifest), "package version mismatch")


def test_manifest_cannot_carry_secret_metadata(tmp_path: Path, built_wheel: Path) -> None:
    artifact = copied_artifact(tmp_path, built_wheel)
    manifest = make_manifest(tmp_path, artifact)
    raw = json.loads(manifest.read_text(encoding="utf-8"))
    raw["token"] = "must-not-be-accepted"
    manifest.write_text(json.dumps(raw), encoding="utf-8")
    assert_rejected_without_stage(verify_kwargs(tmp_path, artifact, manifest), "manifest keys mismatch")


def test_symlink_artifact_rejected_before_install_mutation(tmp_path: Path, built_wheel: Path) -> None:
    real_artifact = copied_artifact(tmp_path, built_wheel)
    link_dir = tmp_path / "links"
    link_dir.mkdir()
    link = link_dir / real_artifact.name
    try:
        link.symlink_to(real_artifact)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable on this runner")
    manifest = make_manifest(tmp_path, real_artifact)
    kwargs = verify_kwargs(tmp_path, link, manifest)
    assert_rejected_without_stage(kwargs, "symlink/reparse point")


def test_path_identity_swap_is_detected_before_staging(
    tmp_path: Path,
    built_wheel: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = copied_artifact(tmp_path, built_wheel)
    manifest = make_manifest(tmp_path, artifact)
    kwargs = verify_kwargs(tmp_path, artifact, manifest)
    original = verifier._file_identity
    calls = {"count": 0}

    def changed_identity(st):
        calls["count"] += 1
        value = original(st)
        if calls["count"] == 4:
            return (value[0], value[1] + 1, value[2])
        return value

    monkeypatch.setattr(verifier, "_file_identity", changed_identity)
    assert_rejected_without_stage(kwargs, "artifact identity changed during hashing")


def test_protected_artifact_path_rejected_before_filesystem_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    touched = {"lstat": False}

    def forbidden_lstat(path):
        touched["lstat"] = True
        raise AssertionError("protected path must be rejected before lstat")

    monkeypatch.setattr(verifier.os, "lstat", forbidden_lstat)
    with pytest.raises(verifier.ArtifactVerificationError, match="protected path"):
        verifier._canonical_existing_file(r"E:\manhwa\never-touch.whl", "artifact")
    assert touched["lstat"] is False


def test_approved_artifact_stages_and_installs_exact_package(tmp_path: Path, built_wheel: Path) -> None:
    artifact = copied_artifact(tmp_path, built_wheel)
    manifest = make_manifest(tmp_path, artifact)
    kwargs = verify_kwargs(tmp_path, artifact, manifest)
    result = verifier.verify_and_stage(**kwargs)
    staged = Path(result["staged_artifact"])

    assert staged.exists()
    assert hashlib.sha256(staged.read_bytes()).hexdigest() == kwargs["expected_artifact_sha256"]
    assert result["producer_sha"] == EXPECTED_PRODUCER
    assert result["protocol_version"] == NATIVE_CONTROL_PROTOCOL_V1
    assert result["capability_digest"] == TOOL_REGISTRY_DIGEST

    venv = tmp_path / "venv"
    subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
    python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    subprocess.run(
        [str(python), "-m", "pip", "install", "--no-deps", str(staged)],
        check=True,
        capture_output=True,
        text=True,
    )
    probe = subprocess.run(
        [
            str(python),
            "-c",
            "import importlib.metadata as m; print(m.version('pc-executor'))",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert probe.stdout.strip() == EXPECTED_VERSION


def test_production_bootstrap_has_no_local_checkout_install_path() -> None:
    text = BOOTSTRAP_PATH.read_text(encoding="utf-8")
    lower = text.lower()
    assert "$reporoot" not in lower
    assert "pip install --disable-pip-version-check $reporoot" not in lower
    assert "--expected-producer-sha" in lower
    assert "--expected-artifact-sha256" in lower
    assert "--expected-capability-digest" in lower
    assert "$stagedartifact" in lower
    assert "pip install --disable-pip-version-check --upgrade --force-reinstall $stagedartifact" in lower

    verify_index = lower.index("$verificationjson = & python @verifyargs")
    service_root_index = lower.index("$serviceroot = join-path $env:programdata")
    first_service_mutation = lower.index("new-item -itemtype directory -force -path $serviceroot")
    install_registration = lower.index("& $cli install")
    assert verify_index < service_root_index < first_service_mutation < install_registration

    # Token material remains hidden-input only and is never accepted as a bootstrap argument.
    assert "[string]$token" not in lower
    assert "secret set --generation" in lower
    assert '$configure += "--disable"' in lower
