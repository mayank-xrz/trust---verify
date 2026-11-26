"""Black-box Track 4 adapter verification; never imports or edits the adapter."""
import base64
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

from pqcrypto.kem import ml_kem_768

ADAPTER = Path(__file__).with_name("track4_service.py").resolve()
COMMAND = [sys.executable, "-B", str(ADAPTER)]


def call(payload, environment):
    process = subprocess.Popen(COMMAND, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=environment, cwd=ADAPTER.parent)
    encoded = json.dumps(payload, ensure_ascii=False).encode("utf-8") if isinstance(payload, dict) else payload
    stdout, stderr = process.communicate(encoded, timeout=8)
    return {"pid": process.pid, "exit_code": process.returncode,
            "stdout": stdout.decode("utf-8", "replace"), "stderr": stderr.decode("utf-8", "replace")}


def parsed(result):
    return json.loads(result["stdout"])


def public_record(label, payload, result, assertions, body, secret_bytes=()):
    if isinstance(payload, dict):
        summary = {k: v for k, v in payload.items() if k not in {"contents", "public_key", "key_material"}}
        if "contents" in payload:
            summary["contents"] = "[REDACTED PLAINTEXT BODY]"
        if "public_key" in payload:
            summary["public_key"] = {"base64_length": len(payload["public_key"]),
                                     "sha256_prefix": hashlib.sha256(payload["public_key"].encode()).hexdigest()[:12]}
        if "key_material" in payload:
            summary["key_material"] = "[REDACTED]"
    else:
        summary = "[MALFORMED JSON]"
    combined = result["stdout"] + result["stderr"]
    no_leak = body not in combined and all(
        representation not in combined
        for secret in secret_bytes if secret
        for representation in (base64.b64encode(secret).decode(), secret.hex(),
                               base64.b64encode(secret[:16]).decode(), secret[:16].hex(),
                               secret.decode("ascii") if secret.isascii() else "[non-ASCII secret]")
    )
    assertions["no_plaintext_or_secret_in_output"] = no_leak
    return {"label": label, "command": COMMAND, "input_summary": summary,
            "pid": result["pid"], "exit_code": result["exit_code"],
            "raw_stdout": result["stdout"], "raw_stderr": result["stderr"],
            "assertions": assertions, "verdict": "PASS" if all(assertions.values()) else "FAIL"}


def main():
    cases = []
    actor = "actor-" + secrets.token_hex(8)
    asset = "asset-" + secrets.token_hex(8)
    body = "synthetic-body-" + secrets.token_hex(16)
    challenge = secrets.token_hex(24)
    key_marker = "synthetic-key-" + secrets.token_hex(12)
    public_key, private_key = ml_kem_768.generate_keypair()
    with tempfile.TemporaryDirectory(prefix="track4-blackbox-") as directory:
        environment = {**os.environ, "TRACK4_STATE_DIR": directory}
        setup = {"op": "setup", "owners": {asset: actor}, "contents": {asset: body},
                 "disabled": [], "key_material": key_marker}
        setup_result = call(setup, environment)
        setup_assertions = {"exit_zero": setup_result["exit_code"] == 0,
                            "one_json_object": parsed(setup_result) == {"ready": True},
                            "state_in_selected_dir": (Path(directory) / "track4-local" / "state.json").is_file()}
        cases.append(public_record("setup", setup, setup_result, setup_assertions, body,
                                   (private_key, key_marker.encode())))

        authorized = {"op": "protected_read", "actor": actor, "asset": asset,
                      "challenge": challenge, "public_key": base64.b64encode(public_key).decode("ascii")}
        result_a = call(authorized, environment)
        response_a = parsed(result_a) if result_a["exit_code"] == 0 else {}
        ciphertext = b""
        shared_secret = b""
        try:
            ciphertext = base64.b64decode(response_a["ciphertext"], validate=True)
            canonical_b64 = base64.b64encode(ciphertext).decode("ascii") == response_a["ciphertext"]
            shared_secret = ml_kem_768.decrypt(private_key, ciphertext)
        except (KeyError, ValueError, TypeError):
            canonical_b64 = False
        expected_proof = hmac.new(shared_secret, (challenge + body).encode("utf-8"), hashlib.sha256).hexdigest() if shared_secret else ""
        assertions_a = {
            "exit_zero": result_a["exit_code"] == 0,
            "separate_process": result_a["pid"] != setup_result["pid"],
            "authorized_fields": set(response_a) == {"ciphertext", "proof"},
            "standard_base64": canonical_b64,
            "kem_ciphertext_length": len(ciphertext) == ml_kem_768.CIPHERTEXT_SIZE,
            "exact_hmac_transcript": response_a.get("proof") == expected_proof,
            "lowercase_hex_proof": isinstance(response_a.get("proof"), str) and len(response_a["proof"]) == 64
                                   and all(char in "0123456789abcdef" for char in response_a["proof"]),
        }
        cases.append(public_record("A authorized protected_read", authorized, result_a, assertions_a,
                                   body, (private_key, shared_secret, key_marker.encode())))

        unauthorized = {**authorized, "actor": "non-owner-" + secrets.token_hex(8)}
        result_b = call(unauthorized, environment)
        response_b = parsed(result_b) if result_b["exit_code"] == 0 else {}
        assertions_b = {"exit_zero": result_b["exit_code"] == 0,
                        "explicit_denial": response_b.get("decision") == "deny",
                        "no_ciphertext_or_proof": "ciphertext" not in response_b and "proof" not in response_b}
        cases.append(public_record("B unauthorized protected_read", unauthorized, result_b,
                                   assertions_b, body, (private_key, shared_secret, key_marker.encode())))

        for label, bad_key in (("C1 invalid Base64", "bad!"),
                               ("C2 wrong key length", base64.b64encode(secrets.token_bytes(20)).decode("ascii"))):
            malformed = {**authorized, "public_key": bad_key}
            result_c = call(malformed, environment)
            assertions_c = {"nonzero_exit": result_c["exit_code"] != 0,
                            "no_stdout": result_c["stdout"] == "",
                            "diagnostic_only_on_stderr": bool(result_c["stderr"]),
                            "no_traceback": "Traceback" not in result_c["stderr"],
                            "no_proof_or_plaintext": "proof" not in result_c["stdout"]}
            cases.append(public_record(label, malformed, result_c, assertions_c,
                                       body, (private_key, shared_secret, key_marker.encode())))

        altered_challenge = secrets.token_hex(24)
        altered_proof = hmac.new(shared_secret, (altered_challenge + body).encode("utf-8"), hashlib.sha256).hexdigest() if shared_secret else ""
        assertions_d = {"challenge_changes_expected_proof": bool(expected_proof) and expected_proof != altered_proof,
                        "response_matches_original_only": response_a.get("proof") == expected_proof
                        and response_a.get("proof") != altered_proof}
        cases.append({"label": "D tampered challenge", "command": "local HMAC recomputation",
                      "input_summary": {"original_challenge": challenge, "altered_challenge": altered_challenge,
                                        "stored_body": "[REDACTED PLAINTEXT BODY]"},
                      "raw_stdout": result_a["stdout"], "raw_stderr": result_a["stderr"],
                      "assertions": assertions_d, "verdict": "PASS" if all(assertions_d.values()) else "FAIL"})

        malformed_json = call(b"not-json", environment)
        assertions_json = {"nonzero_exit": malformed_json["exit_code"] != 0,
                           "no_stdout": malformed_json["stdout"] == "",
                           "stderr_only": bool(malformed_json["stderr"]),
                           "no_traceback": "Traceback" not in malformed_json["stderr"]}
        cases.append(public_record("malformed JSON process behavior", b"not-json", malformed_json,
                                   assertions_json, body, (private_key, shared_secret, key_marker.encode())))

    with tempfile.TemporaryDirectory(prefix="track4-fallback-") as directory:
        fallback_env = dict(os.environ)
        fallback_env.pop("TRACK4_STATE_DIR", None)
        fallback_env["TMPDIR"] = directory
        fallback_env["TEMP"] = directory
        fallback_env["TMP"] = directory
        fallback_setup = {"op": "setup", "owners": {asset: actor}, "contents": {asset: body},
                          "disabled": [], "key_material": key_marker}
        fallback_result = call(fallback_setup, fallback_env)
        fallback_read = {"op": "read", "actor": actor, "asset": asset, "request_id": secrets.token_hex(8)}
        fallback_read_result = call(fallback_read, fallback_env)
        read_response = parsed(fallback_read_result) if fallback_read_result["exit_code"] == 0 else {}
        fallback_assertions = {"setup_exit_zero": fallback_result["exit_code"] == 0,
                               "read_exit_zero": fallback_read_result["exit_code"] == 0,
                               "separate_process": fallback_result["pid"] != fallback_read_result["pid"],
                               "fallback_state_file": (Path(directory) / "track4-local" / "state.json").is_file(),
                               "persisted_body_matches": read_response.get("body") == body,
                               "no_secret_in_diagnostics": all(value not in fallback_result["stderr"] + fallback_read_result["stderr"]
                                                               for value in (body, key_marker, private_key.hex(),
                                                                             base64.b64encode(private_key).decode())),
                               "one_json_object_per_success": parsed(fallback_result) == {"ready": True}
                               and read_response.get("decision") == "allow"}
        # Raw read output contains the synthetic plaintext body, so redact that field in the record.
        redacted_read_stdout = fallback_read_result["stdout"].replace(body, "[REDACTED PLAINTEXT BODY]")
        cases.append({"label": "fallback temp state and fresh processes", "command": COMMAND,
                      "input_summary": {"setup": "[REDACTED PLAINTEXT BODY]", "read": fallback_read},
                      "setup_pid": fallback_result["pid"], "read_pid": fallback_read_result["pid"],
                      "setup_exit_code": fallback_result["exit_code"], "read_exit_code": fallback_read_result["exit_code"],
                      "raw_setup_stdout": fallback_result["stdout"], "raw_setup_stderr": fallback_result["stderr"],
                      "read_stdout_redacted": redacted_read_stdout, "raw_read_stderr": fallback_read_result["stderr"],
                      "assertions": fallback_assertions,
                      "verdict": "PASS" if all(fallback_assertions.values()) else "FAIL"})

    report = {"adapter": str(ADAPTER), "python": sys.version.split()[0], "cases": cases,
              "overall": "PASS" if all(case["verdict"] == "PASS" for case in cases) else "FAIL"}
    print(json.dumps(report, indent=2))
    return 0 if report["overall"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
