"""Independent byte-vector encoder for the dossier's public wire formats.

No Rust encoder is called. The mapping slot was independently checked with
Foundry `cast index address 0x0000000000000000000000000000000000002001 0`.
"""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
address = lambda value: value.to_bytes(20, "big")
word = lambda value: value.to_bytes(32, "big")
le = lambda value, size: value.to_bytes(size, "little")
sha = lambda value: hashlib.sha256(value).digest()
target, victim, attacker = map(address, (0x1001, 0x2001, 0x3001))
deposit = 10 * 10**18
slot = bytes.fromhex("7bd7939cb82c663b57030f4099dfc38b533b65cba110a5aa84a7e1c80511b4f3")
runtime = b"\x00"

state = b"PSPHS001" + le(3, 4)
for addr, nonce, balance, code, storage in (
    (target, 1, deposit, runtime, [(slot, word(deposit))]),
    (victim, 1, 0, b"", []),
    (attacker, 0, 0, b"", []),
):
    state += addr + le(nonce, 8) + word(balance) + le(len(code), 4) + code + le(len(storage), 4)
    for key, value in storage:
        state += key + value
environment = (b"PSPHE001" + b"\x01" + word(31337) + attacker + word(0) + word(1)
               + address(0) + word(1) + word(0) + word(500000) + word(0)
               + b"\x01" + word(0) + le(0, 4))
claim = b"ProofSphere/unauthorized-withdrawal/v1" + le(256, 2) + le(500000, 8) + word(1)
descriptor = b"PSPHSC01" + target + victim + attacker + sha(runtime) + sha(state) + sha(environment) + sha(claim)
nonce = bytes(range(32))
journal = b"PSPHJ001" + sha(descriptor) + nonce + b"\x01"
assert len(environment) == 310 and len(descriptor) == 196 and len(journal) == 73
result = {name: value.hex() for name, value in {
    "state": state, "environment": environment, "claim": claim, "scenario_descriptor": descriptor,
    "scenario_digest": sha(descriptor), "journal": journal, "victim_slot": slot,
}.items()}
destination = ROOT / "fixtures" / "golden.json"
destination.parent.mkdir(parents=True, exist_ok=True)
destination.write_text(json.dumps(result, indent=2) + "\n")
