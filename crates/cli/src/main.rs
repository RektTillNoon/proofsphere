use clap::{Parser, Subcommand};
use proofsphere_model::{
    MAX_CALLDATA, U256,
    claim::LABEL,
    input::GuestInput,
    scenario::Commitments,
    transport::{
        MAX_JSON, environment_from_json, environment_to_json, state_from_json, state_to_json,
    },
};
use proofsphere_proof::{
    container::{self, ContainerError},
    files::{read_bounded, write_new},
    prover,
    setup::{Challenge, EntryJson, Registry, RegistryJson},
    verify,
};
use std::{
    io::Write,
    path::{Path, PathBuf},
    process::ExitCode,
};

#[derive(Parser)]
#[command(
    version,
    about = "Private proof of unauthorized withdrawal in a synthetic vault"
)]
struct Cli {
    #[arg(long, global = true, default_value = "fixtures/registry.json")]
    registry: PathBuf,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Generate both public states by executing the victim's ordinary deposit.
    Fixture {
        #[arg(long, default_value = "fixtures")]
        out: PathBuf,
    },
    /// Bind generated fixture commitments to this build's generic guest image.
    Registry,
    /// Create an owner request using OS randomness.
    Challenge {
        #[arg(long)]
        scenario: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Write the known synthetic payload to a user-only local file.
    DemoWitness {
        #[arg(long, default_value = ".proofsphere-private/reference.bin")]
        out: PathBuf,
    },
    /// Produce and locally verify a genuine succinct receipt, without remote proving.
    Prove {
        #[arg(long)]
        scenario: String,
        #[arg(long)]
        challenge: PathBuf,
        #[arg(long)]
        witness: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Independently verify a receipt against the trusted registry and owner request.
    Verify {
        #[arg(long)]
        scenario: String,
        #[arg(long)]
        challenge: PathBuf,
        #[arg(long)]
        proof: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

fn print_verification(status: &str, code: &str, accepted: bool, json: bool) {
    if json {
        let mut report = serde_json::json!({ "status": status, "code": code });
        if accepted {
            report["claim"] = LABEL.into();
        }
        println!("{report}");
    } else if accepted {
        println!("{LABEL}");
    } else {
        println!("Verification {status}: {code}");
    }
}

fn write_private_metrics(metrics: &prover::Metrics) -> Result<(), &'static str> {
    let directory = Path::new(".proofsphere-private");
    std::fs::create_dir_all(directory).map_err(|_| "could not create private directory")?;
    let metadata =
        std::fs::symlink_metadata(directory).map_err(|_| "could not inspect private directory")?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("private directory must be an ordinary directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| "could not protect private directory")?;
    }
    let report = serde_json::json!({
        "format": "proofsphere-private-performance-v1",
        "proof_generation_ms": metrics.proof_ms,
        "compression_ms": serde_json::Value::Null,
        "segments": metrics.segments,
        "total_cycles": metrics.total_cycles,
        "user_cycles": metrics.user_cycles,
        "paging_cycles": metrics.paging_cycles,
        "reserved_cycles": metrics.reserved_cycles,
        "peak_rss_bytes": metrics.peak_rss_bytes,
    });
    let bytes =
        serde_json::to_vec_pretty(&report).map_err(|_| "could not encode private measurements")?;
    let path = directory.join("performance.json");
    let mut options = std::fs::OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|_| "could not open private measurements")?;
    file.write_all(&bytes)
        .map_err(|_| "could not write private measurements")?;
    file.sync_all()
        .map_err(|_| "could not flush private measurements")?;
    Ok(())
}

fn write_public_generated(path: &Path, bytes: &[u8]) -> Result<(), &'static str> {
    if std::fs::symlink_metadata(path).is_ok() {
        if read_bounded(path, bytes.len())? == bytes {
            return Ok(());
        }
        return Err("existing generated file differs from this build");
    }
    write_new(path, bytes)
}

fn fixture(out: &Path) -> Result<(), &'static str> {
    for (name, directory) in [
        ("DemoVault", "vault-vulnerable"),
        ("PatchedVault", "vault-patched"),
    ] {
        let runtime = read_bounded(
            &out.join("compiler").join(format!("{name}.runtime.hex")),
            2 * proofsphere_model::MAX_CODE + 1,
        )?;
        let text = std::str::from_utf8(&runtime).map_err(|_| "invalid compiler runtime")?;
        let runtime = hex::decode(text.trim()).map_err(|_| "invalid compiler runtime")?;
        let state = proofsphere_runner::fixture(runtime).map_err(|_| "fixture deposit failed")?;
        let dir = out.join(directory);
        write_public_generated(
            &dir.join("state.json"),
            &state_to_json(&state).map_err(|_| "state export failed")?,
        )?;
        write_public_generated(
            &dir.join("environment.json"),
            &environment_to_json().map_err(|_| "environment export failed")?,
        )?;
    }
    println!("Both public fixtures generated from successful victim deposits.");
    Ok(())
}
fn registry(path: &Path) -> Result<(), &'static str> {
    let root = path.parent().unwrap_or(Path::new("."));
    let mut entries = Vec::with_capacity(2);
    for (id, label, directory) in [
        ("vault-patched-v1", "Patched vault", "vault-patched"),
        (
            "vault-vulnerable-v1",
            "Vulnerable vault",
            "vault-vulnerable",
        ),
    ] {
        let state_file = format!("{directory}/state.json");
        let environment_file = format!("{directory}/environment.json");
        let state = state_from_json(&read_bounded(&root.join(&state_file), MAX_JSON)?)
            .map_err(|_| "invalid public state")?;
        let environment =
            environment_from_json(&read_bounded(&root.join(&environment_file), MAX_JSON)?)
                .map_err(|_| "invalid public environment")?;
        let c = Commitments::compute(&state, environment).map_err(|_| "invalid public setup")?;
        entries.push(EntryJson {
            id: id.into(),
            label: label.into(),
            state_file,
            environment_file,
            code_digest: hex::encode(c.code),
            state_digest: hex::encode(c.state),
            environment_digest: hex::encode(c.environment),
            claim_digest: hex::encode(c.claim),
            scenario_digest: hex::encode(c.scenario),
            guest_image_id: prover::image_id().to_string(),
        });
    }
    let json = RegistryJson {
        format: "proofsphere-registry-v1".into(),
        scenarios: entries,
    };
    write_public_generated(
        path,
        &serde_json::to_vec_pretty(&json).map_err(|_| "registry serialization failed")?,
    )?;
    Registry::load(path)?;
    println!("Registry generated and all commitments independently recomputed.");
    Ok(())
}

fn run(cli: Cli) -> Result<u8, &'static str> {
    match cli.command {
        Command::Fixture { out } => fixture(&out)?,
        Command::Registry => registry(&cli.registry)?,
        Command::DemoWitness { out } => {
            if out.parent() != Some(Path::new(".proofsphere-private")) || out.file_name().is_none()
            {
                return Err("demo witness output must be directly under .proofsphere-private");
            }
            std::fs::create_dir_all(".proofsphere-private")
                .map_err(|_| "could not create private directory")?;
            let metadata = std::fs::symlink_metadata(".proofsphere-private")
                .map_err(|_| "could not inspect private directory")?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err("private directory must be an ordinary directory");
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(
                    ".proofsphere-private",
                    std::fs::Permissions::from_mode(0o700),
                )
                .map_err(|_| "could not protect private directory")?;
            }
            write_new(
                &out,
                &proofsphere_runner::reference_payload(U256::from(1_000_000_000_000_000_000_u64)),
            )?;
            println!("Synthetic witness written locally with user-only permissions.");
        }
        Command::Challenge { scenario, out } => {
            let registry = Registry::load(&cli.registry)?;
            let challenge = Challenge::new(registry.get(&scenario)?)?;
            write_new(
                &out,
                &serde_json::to_vec_pretty(&challenge)
                    .map_err(|_| "challenge serialization failed")?,
            )?;
            println!("Owner challenge created.");
        }
        Command::Prove {
            scenario,
            challenge,
            witness,
            out,
        } => {
            if std::fs::symlink_metadata(&out).is_ok() {
                return Err("proof output already exists");
            }
            prover::check_local_environment()?;
            let registry = Registry::load(&cli.registry)?;
            let scenario = registry.get(&scenario)?;
            let challenge = Challenge::load(&challenge, scenario)?;
            let expected = challenge.expected(scenario)?;
            if expected.image != prover::image_id() {
                return Err("registry image differs from this prover build");
            }
            let calldata = read_bounded(&witness, MAX_CALLDATA)?;
            proofsphere_runner::prove_transition(&scenario.state, scenario.environment, &calldata)
                .map_err(|_| "private input does not demonstrate the registered claim")?;
            let input = GuestInput {
                state: scenario.state.clone(),
                environment: scenario.environment,
                nonce: expected.nonce,
                calldata,
            };
            let proved = prover::prove(&input)?;
            let bytes = container::encode(&proved.receipt)
                .map_err(|_| "receipt container encoding failed")?;
            write_private_metrics(&proved.metrics)?;
            write_new(&out, &bytes)?;
            println!(
                "Genuine succinct proof written after local verification; {} public bytes.",
                bytes.len()
            );
        }
        Command::Verify {
            scenario,
            challenge,
            proof,
            json,
        } => {
            // Operational setup failures have a distinct result from rejected proof submissions.
            let operation = || {
                let registry = Registry::load(&cli.registry)?;
                let scenario = registry.get(&scenario)?;
                let challenge = Challenge::load(&challenge, scenario)?;
                let expected = challenge.expected(scenario)?;
                Ok::<_, &'static str>(expected)
            };
            let expected = match operation() {
                Ok(value) => value,
                Err(_) => {
                    print_verification("error", "OPERATIONAL_ERROR", false, json);
                    return Ok(3);
                }
            };
            let bytes = match read_bounded(&proof, container::MAX_FILE) {
                Ok(bytes) => bytes,
                Err("file exceeds permitted size") => {
                    print_verification("rejected", "TOO_LARGE", false, json);
                    return Ok(2);
                }
                Err(_) => {
                    print_verification("error", "OPERATIONAL_ERROR", false, json);
                    return Ok(3);
                }
            };
            let receipt = match container::decode(&bytes) {
                Ok(receipt) => receipt,
                Err(error) => {
                    print_verification(
                        "rejected",
                        match error {
                            ContainerError::TooLarge => "TOO_LARGE",
                            ContainerError::UnsupportedFormat => "UNSUPPORTED_FORMAT",
                        },
                        false,
                        json,
                    );
                    return Ok(2);
                }
            };
            match verify::verify(&receipt, expected) {
                Ok(_) => print_verification("accepted", "CLAIM_VERIFIED", true, json),
                Err(reason) => {
                    print_verification("rejected", reason.code(), false, json);
                    return Ok(2);
                }
            }
        }
    }
    Ok(0)
}
fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => ExitCode::from(code),
        Err(message) => {
            eprintln!("ProofSphere: {message}");
            ExitCode::from(3)
        }
    }
}
