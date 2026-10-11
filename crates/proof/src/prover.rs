use crate::verify::{Expected, verify};
use std::time::Instant;

/// These values are private operational measurements, never journal fields.
pub struct Metrics {
    pub proof_ms: u128,
    pub segments: usize,
    pub total_cycles: u64,
    pub user_cycles: u64,
    pub paging_cycles: u64,
    pub reserved_cycles: u64,
    pub peak_rss_bytes: Option<u64>,
}
pub struct Proved {
    pub receipt: Receipt,
    pub metrics: Metrics,
}

fn peak_rss_bytes() -> Option<u64> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // libc writes rusage on success; no uninitialized field is read on failure.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } != 0 {
        return None;
    }
    let used = unsafe { usage.assume_init() }.ru_maxrss;
    if used < 0 {
        return None;
    }
    #[cfg(target_os = "macos")]
    {
        Some(used as u64)
    }
    #[cfg(not(target_os = "macos"))]
    {
        (used as u64).checked_mul(1024)
    }
}
use proofsphere_model::{input::GuestInput, scenario::Commitments};
use risc0_zkvm::{ExecutorEnv, LocalProver, Prover, ProverOpts, Receipt, sha::Digest};

pub fn image_id() -> Digest {
    Digest::from(proofsphere_methods::PROOFSPHERE_GUEST_ID)
}

pub fn check_local_environment() -> Result<(), &'static str> {
    let value = |name| std::env::var_os(name);
    if value("RISC0_DEV_MODE").is_some_and(|v| v != "0" && !v.is_empty())
        || value("BONSAI_API_URL").is_some()
        || value("BONSAI_API_KEY").is_some()
        || value("RISC0_PROVER").is_some_and(|v| !v.is_empty() && v != "local")
    {
        return Err("remote or development proving configuration is forbidden");
    }
    Ok(())
}

pub fn prove(input: &GuestInput) -> Result<Proved, &'static str> {
    check_local_environment()?;
    let scenario = Commitments::compute(&input.state, input.environment)
        .map_err(|_| "invalid public setup")?
        .scenario;
    let bytes = input.encode().map_err(|_| "invalid bounded input")?;
    let env = ExecutorEnv::builder()
        .write_slice(&bytes)
        .segment_limit_po2(20)
        .session_limit(Some(1 << 27))
        .build()
        .map_err(|_| "could not create local executor")?;
    let prover = LocalProver::new("proofsphere-local");
    let started = Instant::now();
    let info = prover
        .prove_with_opts(
            env,
            proofsphere_methods::PROOFSPHERE_GUEST_ELF,
            &ProverOpts::succinct().with_dev_mode(false),
        )
        .map_err(|_| "local proof generation failed")?;
    let proof_ms = started.elapsed().as_millis();
    verify(
        &info.receipt,
        Expected {
            image: image_id(),
            scenario,
            nonce: input.nonce,
        },
    )
    .map_err(|_| "generated receipt failed independent verification")?;
    Ok(Proved {
        receipt: info.receipt,
        metrics: Metrics {
            proof_ms,
            segments: info.stats.segments,
            total_cycles: info.stats.total_cycles,
            user_cycles: info.stats.user_cycles,
            paging_cycles: info.stats.paging_cycles,
            reserved_cycles: info.stats.reserved_cycles,
            peak_rss_bytes: peak_rss_bytes(),
        },
    })
}
