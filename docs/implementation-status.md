# Implementation record

Canonical requirements: [technical design dossier](proofsphere-hackathon-technical-design-dossier.pdf), version 0.3. This is a local hackathon demonstration using synthetic contracts and a pinned EVM fixture. It makes no claim about a live-chain exploit.

## Completed gates

- [x] Host and guest Rust 1.97.0, RISC Zero 3.0.6, EVM 0.42.0, Solidity 0.8.26, Foundry, and pnpm toolchains pinned or recorded; portal feature tree audited without proving or Bonsai dependencies.
- [x] Vulnerable and patched vaults compiled deterministically; slot-0 ledger layout, characterization, patch regression, rollback, and boundary behavior checked by six Forge tests.
- [x] Canonical setup/input/journal encodings, strict JSON handling, golden vectors, native EVM transaction runner, applied post-state predicate, and differential checks covered by Rust tests.
- [x] Generic RISC Zero guest produced a genuine release-mode succinct receipt for the vulnerable scenario. The public proof is `evidence/demo/vulnerable.psproof`; the pinned image and fixture digests appear in `evidence/toolchain.json`.
- [x] Independently generated public scenario registry and owner challenge; bounded proof container; production-only verifier; wrong image, scenario, nonce, journal, and fake receipt cases rejected.
- [x] CLI confines raw calldata to the local prover and writes proof files atomically without clobbering. Verifier-only portal binds loopback, owns challenge generation, limits uploads and verifier concurrency, and rejects replaced requests.
- [x] Desktop-first interactive portal presents the public setup, private input boundary, proof artifact, and verification. Recorded and fresh requests both accepted matching genuine proofs through the browser. Desktop (1440 × 900) and narrow-screen (390 × 844) layouts were inspected with no horizontal overflow; keyboard and stale-response behavior were exercised. See `evidence/ui/browser-smoke.json` and screenshots.
- [x] Privacy canary audit scanned public files and private proof/logs; proving under a network-deny macOS sandbox succeeded; remote prover environment settings were refused before proving. See `evidence/privacy.json`. Raw witnesses and performance logs remain ignored in `.proofsphere-private/`.
- [x] Three independent release verifier processes accepted the public receipt within the five-second demo target; changed challenge, corrupt receipt, and patched scenario were rejected. See `evidence/demo/verification.json`.
- [x] README documents reproduction, trust boundary, recorded/fresh flows, limitations, and toolchain evidence. The dossier was updated and compiled to PDF.

## Verification notes

The genuine release proof test was run twice with `./tools/build.sh test --release -j 2 -p proofsphere-proof --features prove --locked --test real_receipt -- --ignored --nocapture`. Full workspace Rust tests and `forge test --root contracts -vv` passed. `python3 tools/verify-evidence.py` and `python3 tools/privacy-audit.py` passed. The browser accepted the recorded proof on desktop, rejected its reuse after a fresh request replaced the challenge, and accepted a newly proved receipt for that fresh request.

The portal is built separately from the prover CLI so Cargo feature unification cannot link proving into the verifier process. Debug Clippy uses `RISC0_SKIP_BUILD=1 RISC0_SKIP_BUILD_KERNELS=1` because the installed RISC-V guest toolchain is used for the actual release proof build; the genuine release test compiles and runs the guest. On macOS Xcode 27, `tools/build-bin/xcrun` selects Metal 3.0 for otherwise unchanged upstream RISC Zero kernels.

Starting checkout: clean `develop` at `8738db00d57284cdbf16b104b19c627009522fd3`. Implementation source, compiled evidence, and documentation are tracked in this task branch. The final owner-clean pass found the canonical ownership sound: guest and native runner own statement truth; registry and portal own trusted expectations; browser state renders only verifier results. No further semantic cleanup was justified after the successful receipt was generated because changing guest source would change the image identity and invalidate public proof evidence.
