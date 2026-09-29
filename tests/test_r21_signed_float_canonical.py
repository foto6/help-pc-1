"""R21 signed wire: Python integral-float canonicalization must match JS JSON.stringify."""
from __future__ import annotations

import json
import math
import unittest

from pc_remote_transport.protocol import (
    JS_MAX_SAFE_INTEGER, ProtocolError, TokenMaterial, canonical_json,
    encode_frame, decode_frame,
)


class SignedFloatCanonicalizationTests(unittest.TestCase):
    def test_search_list_actual_integral_float_regression(self):
        raw = canonical_json({"retention_seconds": 900.0, "runtime_ms": 0})
        self.assertEqual(raw, '{"retention_seconds":900,"runtime_ms":0}')

    def test_nested_finite_integral_float_and_negative_zero(self):
        raw = canonical_json({
            "nested": [{"duration_seconds": 1.0, "signed_zero": -0.0}],
            "fraction": 1.5,
        })
        self.assertEqual(
            raw,
            '{"fraction":1.5,"nested":[{"duration_seconds":1,"signed_zero":0}]}',
        )

    def test_oversized_integral_float_matches_safe_integer_string_policy(self):
        raw = json.loads(canonical_json({"value": float(JS_MAX_SAFE_INTEGER + 1)}))
        self.assertEqual(raw["value"], str(JS_MAX_SAFE_INTEGER + 1))
        self.assertIsInstance(raw["value"], str)

    def test_nonfinite_values_fail_before_signing(self):
        for value in (float("nan"), float("inf"), -float("inf")):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ProtocolError, "non-finite"):
                    canonical_json({"retention_seconds": value})

    def test_actual_signed_frame_has_no_python_only_dot_zero(self):
        token = TokenMaterial(1, b"a" * 32)
        encoded = encode_frame(
            device_id="r21-protocol-probe",
            session_epoch="r21-boot-epoch",
            sequence=7,
            frame_type="heartbeat",
            payload={"retention_seconds": 900.0, "elapsed_seconds": -0.0},
            token=token,
        )
        frame = json.loads(encoded)
        self.assertEqual(frame["payload"]["retention_seconds"], 900)
        self.assertEqual(frame["payload"]["elapsed_seconds"], 0)
        self.assertNotIn("900.0", encoded)
        decoded = decode_frame(
            encoded,
            token=token,
            expected_device_id="r21-protocol-probe",
            expected_session_epoch="r21-boot-epoch",
        )
        self.assertEqual(decoded["payload"]["retention_seconds"], 900)


if __name__ == "__main__":
    unittest.main()
