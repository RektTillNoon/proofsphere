# ProofSphere

ProofSphere is a hackathon project for proving that a smart contract permits an unauthorized withdrawal while keeping the triggering transaction calldata private.

## Design dossier

The reviewed **v0.2** dossier is the implementation baseline:

- [Read the PDF](docs/proofsphere-hackathon-technical-design-dossier.pdf)
- [Edit the LaTeX source](docs/proofsphere-hackathon-technical-design-dossier.tex)

Implementation has not started. The dossier specifies the proof statement, architecture, data formats, tests, and implementation gates.

## Initial scope

- A deliberately vulnerable Solidity vault and a patched variant, using synthetic funds.
- Private calldata supplied to a local RISC Zero prover written in Rust.
- Independent verification of a genuine proof of unauthorized withdrawal.
- A small local dashboard using JavaScript, HTML, and CSS.

Severity scoring, live-chain execution, researcher attribution, and bounty payments are deferred. The first implementation milestone is a genuine vault proof verified through the CLI before dashboard work.

The public toy contract may make the defect obvious. The demonstration establishes that verification does not require transmitting the exact exploit payload; it does not certify contract safety.
