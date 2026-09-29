"""R20 candidate namespace and rollback regressions; no real SCM/LSA writes."""
from __future__ import annotations

import importlib
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from pc_remote_transport import r20_candidate as r20
from pc_remote_transport import r20_candidate_cli as cli
from pc_remote_transport.protocol import TokenMaterial
from pc_remote_transport.service import DEFAULT_SECRET_NAME


class RecordingSecret:
    def __init__(self):
        self.log = []

    def read(self, key):
        self.log.append(("read", key))
        return TokenMaterial(1, b"A" * 32)

    def write(self, key, material):
        self.log.append(("write", key))

    def delete(self, key):
        self.log.append(("delete", key))


class RecordingApi:
    def __init__(self, status="not_installed"):
        self.current = status
        self.log = []

    def status(self):
        self.log.append(("status",))
        return self.current

    def install(self, root):
        self.log.append(("install", str(root)))

    def remove(self):
        self.log.append(("remove",))

    def stop(self):
        self.log.append(("stop",))


class RecordingStore:
    def __init__(self, root):
        self.root = root
        self.log = []

    def initialize(self):
        self.log.append("initialize")


class R20CandidateScopeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="r20-shadow-tests-")
        base = Path(self.temp.name)
        self.candidate = base / "candidate"
        self.legacy = base / "legacy"

    def tearDown(self):
        self.temp.cleanup()

    def scope(self, state=None, expected=None, legacy=None):
        return r20.assert_r20_scope(
            state if state is not None else self.candidate,
            expected_root=expected if expected is not None else self.candidate,
            legacy_root=legacy if legacy is not None else self.legacy,
        )

    def test_static_candidate_name_state_and_secret_are_distinct_from_old(self):
        self.assertNotEqual(r20.R20_SERVICE_NAME, r20.LEGACY_SERVICE_NAME)
        self.assertNotEqual(r20.R20_SECRET_NAME, r20.LEGACY_SECRET_NAME)
        self.assertEqual(r20.R20_SERVICE_NAME, "PCNativeCandidateR20")
        self.assertIn("CandidateR20", r20.R20_SECRET_NAME)

    def test_exact_scoped_state_accepted_without_mutation(self):
        self.assertEqual(self.scope(), self.candidate)
        self.assertFalse(self.candidate.exists())

    def test_mismatched_state_root_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "not its exact"):
            self.scope(self.candidate / "other")

    def test_same_and_nested_legacy_roots_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "overlap"):
            self.scope(self.candidate, self.candidate, self.candidate)
        with self.assertRaisesRegex(RuntimeError, "overlap"):
            self.scope(self.candidate, self.candidate, self.candidate / "old")
        with self.assertRaisesRegex(RuntimeError, "overlap"):
            self.scope(self.candidate / "nested", self.candidate / "nested", self.candidate)

    def test_reparse_in_candidate_ancestor_rejected(self):
        target = self.candidate.parent / "actual"
        target.mkdir()
        alias = self.candidate.parent / "alias"
        try:
            alias.symlink_to(target, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation not permitted under this test identity")
        with self.assertRaisesRegex(RuntimeError, "reparse"):
            self.scope(alias, alias, self.legacy)

    def test_candidate_secret_maps_all_default_protocol_calls_to_candidate_key(self):
        recording = RecordingSecret()
        adapter = r20.CandidateScopedSecretStore(recording)
        adapter.read(DEFAULT_SECRET_NAME)
        adapter.write(DEFAULT_SECRET_NAME, TokenMaterial(1, b"B" * 32))
        adapter.delete(DEFAULT_SECRET_NAME)
        self.assertEqual(recording.log, [
            ("read", r20.R20_SECRET_NAME),
            ("write", r20.R20_SECRET_NAME),
            ("delete", r20.R20_SECRET_NAME),
        ])
        self.assertNotIn(r20.LEGACY_SECRET_NAME, str(recording.log))

    def test_any_unknown_secret_request_fails_before_store_access(self):
        recording = RecordingSecret()
        adapter = r20.CandidateScopedSecretStore(recording)
        for fn, args in (
            (adapter.read, (r20.LEGACY_SECRET_NAME,)),
            (adapter.write, ("random", TokenMaterial(1, b"C" * 32))),
            (adapter.delete, ("",)),
        ):
            with self.assertRaises(RuntimeError):
                fn(*args)
        self.assertEqual(recording.log, [])

    def test_runtime_binds_operations_under_candidate_config_root(self):
        config = SimpleNamespace()
        store = RecordingStore(self.candidate)
        with patch.object(r20, "assert_r20_scope", return_value=self.candidate) as scope, patch.object(
            r20, "build_default_runtime", return_value="real-runtime"
        ) as factory:
            out = r20.r20_runtime(config, TokenMaterial(1,b"D"*32),store,"health","secret")
        self.assertEqual(out, "real-runtime")
        scope.assert_called_once_with(self.candidate)
        self.assertEqual(factory.call_args.kwargs["operations_state_root"],
                         self.candidate / "operations")

    def test_preflight_existing_candidate_blocks_and_does_not_install(self):
        api = RecordingApi(status="running")
        ctl = r20.R20CandidateController(RecordingStore(self.candidate), api=api)
        with patch.object(cli, "assert_r20_scope", return_value=self.candidate):
            result = cli._preflight(ctl, ctl.config_store)
        self.assertEqual(result["candidate_scm_state"], "running")
        self.assertIs(result["candidate_install_eligible"], False)
        self.assertIs(result["legacy_service_touched"], False)
        self.assertEqual(api.log,[("status",)])

    def test_candidate_install_targets_only_its_name_and_rolls_back_own_api(self):
        api = RecordingApi()
        sent = []
        ctl = r20.R20CandidateController(
            RecordingStore(self.candidate),api=api,
            command_runner=lambda argv,**kwargs:sent.append(argv),
        )
        with patch.object(r20, "assert_r20_scope", return_value=self.candidate):
            ctl.install()
        self.assertEqual(api.log,[("status",),("install",str(self.candidate))])
        self.assertEqual(len(sent),2)
        self.assertTrue(all(args[2] == r20.R20_SERVICE_NAME for args in sent))
        self.assertNotIn(r20.LEGACY_SERVICE_NAME,str(sent))

        failed_api=RecordingApi()
        failed_ctl=r20.R20CandidateController(
            RecordingStore(self.candidate),api=failed_api,
            command_runner=lambda *a,**k: (_ for _ in ()).throw(OSError("fixture failure")),
        )
        with patch.object(r20,"assert_r20_scope",return_value=self.candidate):
            with self.assertRaises(OSError):
                failed_ctl.install()
        self.assertEqual(failed_api.log[-1],("remove",))

    def test_uninstall_requires_prior_confirmed_candidate_stop(self):
        running=RecordingApi(status="running")
        with self.assertRaisesRegex(RuntimeError,"stop the candidate"):
            r20.R20CandidateController(RecordingStore(self.candidate),api=running).uninstall()
        self.assertEqual(running.log,[("status",)])
        stopped=RecordingApi(status="stopped")
        r20.R20CandidateController(RecordingStore(self.candidate),api=stopped).uninstall()
        self.assertEqual(stopped.log,[("status",),("remove",)])

    def test_cli_has_separate_executable_entrypoint(self):
        import tomllib
        root=Path(__file__).resolve().parents[1]
        pyproject=tomllib.loads((root/"pyproject.toml").read_text(encoding="utf8"))
        scripts=pyproject["project"]["scripts"]
        self.assertEqual(scripts["pc-native-r20-service"],
                         "pc_remote_transport.r20_candidate_cli:main")
        self.assertEqual(scripts["pc-native-device-service"],
                         "pc_remote_transport.service_cli:main")


if __name__ == "__main__":
    unittest.main()
