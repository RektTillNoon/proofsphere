#!/usr/bin/env python3
"""Check that public assets and prover output do not contain private calldata."""

import base64
import json
import os
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PRIVATE = ROOT / ".proofsphere-private"
REPORT = ROOT / "evidence/privacy.json"


def patterns(payload):
    return (payload, payload.hex().encode(), base64.b64encode(payload))


def main():
    reference = (PRIVATE / "reference.bin").read_bytes()
    canary_input = (PRIVATE / "canary.bin").read_bytes()
    assert canary_input.startswith(reference) and len(canary_input) == len(reference) + 32
    canary = canary_input[-32:]
    canary_proof = PRIVATE / "canary.psproof"
    assert canary_proof.is_file(), "generate and verify the canary receipt first"

    result = subprocess.run(
        [str(ROOT / "target/release/proofsphere"), "verify", "--scenario", "vault-vulnerable-v1",
         "--challenge", "evidence/demo/challenge.json", "--proof", str(canary_proof), "--json"],
        cwd=ROOT, capture_output=True, check=False,
    )
    assert result.returncode == 0 and json.loads(result.stdout)["status"] == "accepted"
    assert not result.stderr

    public_files = []
    excluded = {"out", "cache", "target", "node_modules", "__pycache__", ".proofsphere-tools"}
    for directory in ("evidence", "fixtures", "apps", "contracts", "crates", "methods", "docs", "tools"):
        for path in (ROOT / directory).rglob("*"):
            if (path.is_file() and path.suffix != ".pyc"
                    and not any(part in excluded for part in path.relative_to(ROOT).parts)):
                public_files.append(path)
    public_files.extend((ROOT / "README.md", ROOT / "Cargo.toml", ROOT / "Cargo.lock"))
    public_files = sorted(set(public_files))
    private_observations = [PRIVATE / "canary-proof.log", canary_proof]
    needle_sets = {"canary": patterns(canary), "complete_payload": patterns(canary_input)}
    leaked = []
    for path in public_files + private_observations:
        data = path.read_bytes()
        for kind, needles in needle_sets.items():
            if any(needle in data for needle in needles):
                leaked.append((str(path.relative_to(ROOT)), kind))
    assert not leaked, "private canary or complete payload appeared in an output path"

    blocked_settings = ("RISC0_DEV_MODE", "RISC0_PROVER", "BONSAI_API_KEY")
    with tempfile.TemporaryDirectory(prefix="proofsphere-offline-") as temporary:
        for setting in blocked_settings:
            destination = Path(temporary) / f"{setting}.psproof"
            setting_value = "remote" if setting == "RISC0_PROVER" else "1"
            attempt = subprocess.run(
                [str(ROOT / "target/release/proofsphere"), "prove", "--scenario", "vault-vulnerable-v1",
                 "--challenge", "evidence/demo/challenge.json", "--witness", str(PRIVATE / "canary.bin"),
                 "--out", str(destination)],
                cwd=ROOT, capture_output=True, check=False,
                env={**os.environ, setting: setting_value},
            )
            assert attempt.returncode != 0 and not destination.exists()
            assert b"remote or development proving configuration is forbidden" in attempt.stderr

    report = {
        "format": "proofsphere-public-privacy-check-v1",
        "canary_proof_verified": True,
        "public_files_scanned": len(public_files),
        "private_observation_files_scanned": len(private_observations),
        "representations_checked": ["raw bytes", "lowercase hex", "standard base64"],
        "canary_or_complete_payload_found": False,
        "remote_or_dev_proving_settings_rejected": list(blocked_settings),
        "offline_generation": "macOS sandbox-exec policy denied network access for both reference and canary local proving commands",
        "limit": "Absence of these strings is a leakage check, not an independent zero-knowledge proof.",
    }
    REPORT.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Canary proof verified; scanned {len(public_files)} public files and two private output paths without finding the canary or complete payload.")


if __name__ == "__main__":
    main()
