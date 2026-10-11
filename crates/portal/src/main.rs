mod server;
use clap::Parser;
use proofsphere_model::transport::{MAX_JSON, parse_json};
use proofsphere_proof::{
    files::read_bounded,
    setup::{Challenge, Registry},
};
use std::{path::PathBuf, process::ExitCode, sync::Arc};

#[derive(Parser)]
#[command(version, about = "Loopback-only independent ProofSphere verifier")]
struct Args {
    #[arg(long, default_value = "fixtures/registry.json")]
    registry: PathBuf,
    #[arg(long)]
    recorded_challenge: Option<PathBuf>,
}

async fn run(args: Args) -> Result<(), &'static str> {
    let registry = Registry::load(&args.registry)?;
    let recorded = if let Some(path) = args.recorded_challenge {
        let challenge: Challenge = parse_json(&read_bounded(&path, MAX_JSON)?)
            .map_err(|_| "invalid recorded owner challenge")?;
        challenge.expected(registry.get(&challenge.scenario_id)?)?;
        Some(challenge)
    } else {
        None
    };
    let state = Arc::new(server::AppState::new(registry, recorded));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:4173")
        .await
        .map_err(|_| "could not bind loopback port 4173")?;
    println!("ProofSphere verifier: http://127.0.0.1:4173");
    axum::serve(listener, server::router(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .map_err(|_| "portal server failed")
}
#[tokio::main]
async fn main() -> ExitCode {
    match run(Args::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("ProofSphere: {message}");
            ExitCode::from(3)
        }
    }
}
