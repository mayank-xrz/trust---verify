"""Unit tests for shared JSON schemas using jsonschema.

Validates:
- schemas/envelope.schema.json (P4-06)
- schemas/key_state.schema.json (P4-07)
- schemas/audit_event.schema.json (P4-08)

Asserts:
- Valid payloads pass validation.
- Missing required fields are rejected.
- Additional injected properties are rejected (additionalProperties: false).
- Invalid types, ranges, enums, and patterns are rejected.
"""

from __future__ import annotations

import json
import os
import unittest

import jsonschema

SCHEMAS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "schemas"))


def load_schema(name: str) -> dict:
    with open(os.path.join(SCHEMAS_DIR, name), "r", encoding="utf-8") as f:
        return json.load(f)


class TestSharedSchemas(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.envelope_schema = load_schema("envelope.schema.json")
        cls.key_state_schema = load_schema("key_state.schema.json")
        cls.audit_event_schema = load_schema("audit_event.schema.json")

    # --------------------------------------------------------------------------
    # P4-06: Envelope Schema Tests
    # --------------------------------------------------------------------------

    def get_valid_envelope(self) -> dict:
        return {
            "version": "1.0",
            "sender_id": "node-a",
            "recipient_id": "node-b",
            "seq_num": 42,
            "session_id": "sess-a1b2c3d4e5f6",
            "kem_ciphertext": "a2VtX2NpcGhlcnRleHRfZGF0YQ==",
            "nonce": "bm9uY2VfdmFsdWVfZGF0YQ==",
            "ciphertext": "YWVhZF9jaXBoZXJ0ZXh0X3BheWxvYWQ=",
            "associated_data": {
                "sender_id": "node-a",
                "recipient_id": "node-b",
                "seq_num": 42,
                "session_id": "sess-a1b2c3d4e5f6",
            },
            "signature": "cG9zdF9xdWFudHVtX2RpZ2l0YWxfc2lnbmF0dXJl",
            "sig_alg": "ML-DSA-65",
            "kem_alg": "ML-KEM-768",
        }

    def test_valid_envelope(self):
        payload = self.get_valid_envelope()
        jsonschema.validate(instance=payload, schema=self.envelope_schema)

    def test_envelope_missing_required_field(self):
        for field in [
            "version", "sender_id", "recipient_id", "seq_num", "session_id",
            "kem_ciphertext", "nonce", "ciphertext", "associated_data",
            "signature", "sig_alg", "kem_alg"
        ]:
            payload = self.get_valid_envelope()
            del payload[field]
            with self.assertRaises(jsonschema.ValidationError, msg=f"Missing {field} should fail"):
                jsonschema.validate(instance=payload, schema=self.envelope_schema)

    def test_envelope_additional_properties_rejected(self):
        payload = self.get_valid_envelope()
        payload["injected_field"] = "malicious_payload"
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(instance=payload, schema=self.envelope_schema)

    def test_envelope_associated_data_additional_properties_rejected(self):
        payload = self.get_valid_envelope()
        payload["associated_data"]["extra_binding"] = "illegal"
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(instance=payload, schema=self.envelope_schema)

    def test_envelope_negative_seq_num_rejected(self):
        payload = self.get_valid_envelope()
        payload["seq_num"] = -1
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(instance=payload, schema=self.envelope_schema)

    def test_envelope_invalid_enums_rejected(self):
        payload = self.get_valid_envelope()
        payload["sig_alg"] = "RSA-2048"
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(instance=payload, schema=self.envelope_schema)

        payload = self.get_valid_envelope()
        payload["kem_alg"] = "Kyber-512"
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(instance=payload, schema=self.envelope_schema)

    # --------------------------------------------------------------------------
    # P4-07: Key State Schema Tests
    # --------------------------------------------------------------------------

    def get_valid_key_state(self) -> dict:
        return {
            "key_id": "key-node-a-v1",
            "identity_id": "node-a",
            "device_id": "dev-enclave-01",
            "version": 1,
            "algorithm": "ML-KEM-768",
            "public_key": "cHVibGljX2tleV9ieXRlc19iYXNlNjQ=",
            "status": "active",
            "created_at": "2026-11-26T12:00:00Z",
            "grace_cutoff": None,
            "revoked_at": None,
            "authority_sig": "YXV0aG9yaXR5X3NpZ25hdHVyZQ==",
        }

    def test_valid_key_state_active(self):
        payload = self.get_valid_key_state()
        jsonschema.validate(instance=payload, schema=self.key_state_schema)

    def test_valid_key_state_grace_and_revoked(self):
        payload = self.get_valid_key_state()
        payload["status"] = "grace"
        payload["grace_cutoff"] = "2026-11-26T12:05:00Z"
        jsonschema.validate(instance=payload, schema=self.key_state_schema)

        payload["status"] = "revoked"
        payload["revoked_at"] = "2026-11-26T12:06:00Z"
        jsonschema.validate(instance=payload, schema=self.key_state_schema)

    def test_key_state_missing_required_field(self):
        for field in [
            "key_id", "identity_id", "device_id", "version", "algorithm",
            "public_key", "status", "created_at", "grace_cutoff", "revoked_at", "authority_sig"
        ]:
            payload = self.get_valid_key_state()
            del payload[field]
            with self.assertRaises(jsonschema.ValidationError, msg=f"Missing {field} should fail"):
                jsonschema.validate(instance=payload, schema=self.key_state_schema)

    def test_key_state_additional_properties_rejected(self):
        payload = self.get_valid_key_state()
        payload["private_key"] = "leak"
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(instance=payload, schema=self.key_state_schema)

    def test_key_state_version_zero_rejected(self):
        payload = self.get_valid_key_state()
        payload["version"] = 0
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(instance=payload, schema=self.key_state_schema)

    def test_key_state_invalid_status_enum(self):
        payload = self.get_valid_key_state()
        payload["status"] = "compromised"  # Must be 'revoked'
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(instance=payload, schema=self.key_state_schema)

    # --------------------------------------------------------------------------
    # P4-08: Audit Event Schema Tests
    # --------------------------------------------------------------------------

    def get_valid_audit_event(self) -> dict:
        return {
            "event_id": "c73256ac-22bb-49f1-ac57-197291f2b2b2",
            "timestamp": "2026-11-26T14:30:00Z",
            "actor_id": "service-node-a",
            "service": "settlement-service",
            "action": "TRANSFER_ASSET",
            "resource": "asset://treasury/bond-001",
            "status": "allow",
            "metadata": {
                "amount": 50000,
                "currency": "USD",
                "verified": True,
                "flag": None,
            },
            "prev_hash": "a" * 64,
            "record_hash": "b" * 64,
            "sig": "YXVkaXRfbG9nX3NpZw==",
        }

    def test_valid_audit_event(self):
        payload = self.get_valid_audit_event()
        jsonschema.validate(instance=payload, schema=self.audit_event_schema)

    def test_audit_event_missing_required_field(self):
        for field in [
            "event_id", "timestamp", "actor_id", "service", "action",
            "resource", "status", "metadata", "prev_hash", "record_hash", "sig"
        ]:
            payload = self.get_valid_audit_event()
            del payload[field]
            with self.assertRaises(jsonschema.ValidationError, msg=f"Missing {field} should fail"):
                jsonschema.validate(instance=payload, schema=self.audit_event_schema)

    def test_audit_event_additional_properties_rejected(self):
        payload = self.get_valid_audit_event()
        payload["injected_raw_sql"] = "DROP TABLE audit_events;"
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(instance=payload, schema=self.audit_event_schema)

    def test_audit_event_invalid_hash_lengths(self):
        payload = self.get_valid_audit_event()
        payload["prev_hash"] = "abc"  # Must be exactly 64 hex chars
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(instance=payload, schema=self.audit_event_schema)

        payload = self.get_valid_audit_event()
        payload["record_hash"] = "z" * 64  # 'z' is not hex
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(instance=payload, schema=self.audit_event_schema)

    def test_audit_event_invalid_uuid(self):
        payload = self.get_valid_audit_event()
        payload["event_id"] = "not-a-uuid"
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(instance=payload, schema=self.audit_event_schema)

    def test_audit_event_status_enum(self):
        payload = self.get_valid_audit_event()
        payload["status"] = "permitted"  # Must be 'allow', 'deny', or 'error'
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(instance=payload, schema=self.audit_event_schema)


if __name__ == "__main__":
    unittest.main()
