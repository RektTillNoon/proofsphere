#!/usr/bin/env python3
"""Record public, machine-specific reproduction metadata without private metrics."""

import hashlib
import json
import platform
import subprocess
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "evidence/toolchain.json"


def command(*args):
    return subprocess.run(args, cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()


def sha(path):
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def package_version(lock, name):
    return next(package["version"] for package in lock["package"] if package["name"] == name)


def main():
    lock = tomllib.loads((ROOT / "Cargo.lock").read_text())
    guest_lock = tomllib.loads((ROOT / "methods/guest/Cargo.lock").read_text())
    registry = json.loads((ROOT / "fixtures/registry.json").read_text())
    cli_features = command("cargo", "tree", "-p", "proofsphere-cli", "-e", "features", "--locked")
    portal_features = command("cargo", "tree", "-p", "proofsphere-portal", "-e", "features", "--locked")
    assert 'risc0-zkvm feature "prove"' in cli_features
    assert 'risc0-zkvm feature "disable-dev-mode"' in portal_features
    assert 'risc0-zkvm feature "prove"' not in portal_features
    assert 'proofsphere-proof feature "prove"' not in portal_features
    assert "bonsai" not in cli_features.lower() and "bonsai" not in portal_features.lower()

    hardware = command("system_profiler", "SPHardwareDataType")
    def hardware_line(name):
        return next(
            line.split(":", 1)[1].strip()
            for line in hardware.splitlines()
            if line.strip().startswith(name + ":")
        )
    scenarios = [
        {
            "id": item["id"],
            "guest_image_id": item["guest_image_id"],
            "scenario_digest": item["scenario_digest"],
            "code_digest": item["code_digest"],
            "state_digest": item["state_digest"],
            "environment_digest": item["environment_digest"],
            "claim_digest": item["claim_digest"],
        }
        for item in registry["scenarios"]
    ]
    report = {
        "format": "proofsphere-public-toolchain-v1",
        "host": {
            "os": f"macOS {platform.mac_ver()[0]}",
            "architecture": platform.machine(),
            "model": hardware_line("Model Identifier"),
            "chip": hardware_line("Chip"),
            "memory": hardware_line("Memory"),
            "prover_backend": "RISC Zero LocalProver with macOS Metal kernels",
        },
        "tools": {
            "host_rustc": command("rustc", "--version"),
            "guest_rustc": command(str(ROOT / ".proofsphere-tools/risc0/toolchains/v1.97.0-rust-aarch64-apple-darwin/bin/rustc"), "--version"),
            "risc0_zkvm": package_version(lock, "risc0-zkvm"),
            "guest_risc0_zkvm": package_version(guest_lock, "risc0-zkvm"),
            "r0vm": "3.0.6",
            "cargo_risczero": "3.0.6",
            "evm": package_version(lock, "evm"),
            "solc": "0.8.26",
            "foundry": command(str(ROOT / ".proofsphere-tools/bin/forge"), "--version").splitlines()[0],
            "node": command("node", "--version"),
            "pnpm": command("pnpm", "--version"),
        },
        "features": {
            "cli_local_prove": True,
            "portal_verifier_only": True,
            "sdk_disable_dev_mode": True,
            "bonsai_dependency": False,
            "audit_command": "cargo tree -p proofsphere-portal -e features --locked",
        },
        "limits": {
            "private_calldata_bytes": 256,
            "proof_payload_bytes": 8 * 1024 * 1024,
            "guest_segment_limit_po2": 20,
            "guest_session_cycle_limit": 1 << 27,
        },
        "build_compatibility": "On macOS Xcode 27, tools/build-bin/xcrun selects Metal 3.0 for unchanged upstream kernels.",
        "locks_sha256": {
            "host": sha("Cargo.lock"),
            "guest": sha("methods/guest/Cargo.lock"),
            "compiler": sha("tools/contracts/pnpm-lock.yaml"),
        },
        "compiler_runtime_sha256": {
            "vulnerable": hashlib.sha256(bytes.fromhex((ROOT / "fixtures/compiler/DemoVault.runtime.hex").read_text().strip())).hexdigest(),
            "patched": hashlib.sha256(bytes.fromhex((ROOT / "fixtures/compiler/PatchedVault.runtime.hex").read_text().strip())).hexdigest(),
        },
        "public_proof_sha256": sha("evidence/demo/vulnerable.psproof"),
        "scenarios": scenarios,
    }
    REPORT.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Wrote {REPORT.relative_to(ROOT)} with two registry scenarios and a verifier-only feature audit.")


if __name__ == "__main__":
    main()
