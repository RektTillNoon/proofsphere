#!/usr/bin/env python3
"""Rehearse the public receipt in separate production-verifier processes."""

import json
import os
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "target/release/proofsphere"
CHALLENGE = ROOT / "evidence/demo/challenge.json"
PROOF = ROOT / "evidence/demo/vulnerable.psproof"
REPORT = ROOT / "evidence/demo/verification.json"


def verify(scenario, challenge, proof):
    start = time.perf_counter_ns()
    process = subprocess.run(
        [str(VERIFIER), "verify", "--scenario", scenario, "--challenge", str(challenge),
         "--proof", str(proof), "--json"],
        cwd=ROOT, capture_output=True, text=True, check=False,
        env={**os.environ, "RISC0_DEV_MODE": "1"},
    )
    elapsed_ms = round((time.perf_counter_ns() - start) / 1_000_000, 3)
    assert process.stderr == "", "verifier emitted unexpected diagnostics"
    result = json.loads(process.stdout)
    assert process.returncode == {"accepted": 0, "rejected": 2, "error": 3}[result["status"]]
    return {"exit_code": process.returncode, "elapsed_ms": elapsed_ms, **result}


def main():
    valid = [verify("vault-vulnerable-v1", CHALLENGE, PROOF) for _ in range(3)]
    assert all(item["status"] == "accepted" and item["code"] == "CLAIM_VERIFIED" for item in valid)

    with tempfile.TemporaryDirectory(prefix="proofsphere-verify-") as temporary:
        temporary = Path(temporary)
        challenge = json.loads(CHALLENGE.read_text())
        challenge["nonce"] = "0" * 64 if challenge["nonce"] != "0" * 64 else "1" * 64
        wrong_nonce = temporary / "wrong-nonce.json"
        wrong_nonce.write_text(json.dumps(challenge))
        altered_nonce = verify("vault-vulnerable-v1", wrong_nonce, PROOF)
        assert altered_nonce["code"] == "CHALLENGE_MISMATCH"

        proof_bytes = bytearray(PROOF.read_bytes())
        assert len(proof_bytes) > 128
        proof_bytes[100] ^= 1
        corrupted = temporary / "corrupted.psproof"
        corrupted.write_bytes(proof_bytes)
        altered_receipt = verify("vault-vulnerable-v1", CHALLENGE, corrupted)
        assert altered_receipt["status"] == "rejected"

        patched_challenge = temporary / "patched-challenge.json"
        generated = subprocess.run(
            [str(VERIFIER), "challenge", "--scenario", "vault-patched-v1", "--out", str(patched_challenge)],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        assert generated.stderr == ""
        patched_expectation = verify("vault-patched-v1", patched_challenge, PROOF)
        assert patched_expectation["code"] == "SCENARIO_MISMATCH"

    registry = json.loads((ROOT / "fixtures/registry.json").read_text())
    report = {
        "format": "proofsphere-public-verification-v1",
        "proof_bytes": PROOF.stat().st_size,
        "guest_image_id": registry["scenarios"][0]["guest_image_id"],
        "runs": valid,
        "adversarial": {
            "changed_challenge": altered_nonce,
            "corrupted_receipt": altered_receipt,
            "patched_scenario": patched_expectation,
        },
        "verifier_mode": "separate release processes; RISC0_DEV_MODE=1 hostile environment; production verifier still disables dev mode",
    }
    REPORT.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Three independent accepted verifications and three adversarial rejections; wrote {REPORT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
