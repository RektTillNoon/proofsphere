use crate::{files::read_bounded, verify::Expected};
use hex::FromHex;
use proofsphere_model::{
    Environment, State,
    scenario::Commitments,
    transport::{MAX_JSON, environment_from_json, fixed_hex, parse_json, state_from_json},
};
use risc0_zkvm::sha::Digest;
use serde::{Deserialize, Serialize};
use std::path::{Component, Path};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryJson {
    pub format: String,
    pub scenarios: Vec<EntryJson>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntryJson {
    pub id: String,
    pub label: String,
    pub state_file: String,
    pub environment_file: String,
    pub code_digest: String,
    pub state_digest: String,
    pub environment_digest: String,
    pub claim_digest: String,
    pub scenario_digest: String,
    pub guest_image_id: String,
}
pub struct Scenario {
    pub id: String,
    pub label: String,
    pub state: State,
    pub environment: Environment,
    pub commitments: Commitments,
    pub image: Digest,
}
pub struct Registry {
    pub scenarios: Vec<Scenario>,
}

fn image(text: &str) -> Result<Digest, &'static str> {
    let digest = Digest::from_hex(text).map_err(|_| "invalid image ID")?;
    if digest.to_string() != text {
        return Err("noncanonical image ID");
    }
    Ok(digest)
}
fn safe_file(root: &Path, relative: &str) -> Result<std::path::PathBuf, &'static str> {
    let relative = Path::new(relative);
    if relative
        .components()
        .any(|c| !matches!(c, Component::Normal(_)))
        || relative.as_os_str().is_empty()
    {
        return Err("fixture path is not relative and bounded");
    }
    let path = root
        .join(relative)
        .canonicalize()
        .map_err(|_| "could not locate public fixture")?;
    if !path.starts_with(root) {
        return Err("fixture path escapes registry directory");
    }
    Ok(path)
}
impl Registry {
    pub fn load(path: &Path) -> Result<Self, &'static str> {
        let root = path
            .parent()
            .unwrap_or(Path::new("."))
            .canonicalize()
            .map_err(|_| "could not locate registry directory")?;
        let json: RegistryJson =
            parse_json(&read_bounded(path, MAX_JSON)?).map_err(|_| "invalid registry JSON")?;
        if json.format != "proofsphere-registry-v1" || json.scenarios.len() != 2 {
            return Err("unsupported registry");
        }
        let mut scenarios = Vec::with_capacity(2);
        for (entry, id) in json
            .scenarios
            .into_iter()
            .zip(["vault-patched-v1", "vault-vulnerable-v1"])
        {
            if entry.id != id {
                return Err("invalid or unordered scenario IDs");
            }
            let state = state_from_json(&read_bounded(
                &safe_file(&root, &entry.state_file)?,
                MAX_JSON,
            )?)
            .map_err(|_| "invalid registered state")?;
            let environment = environment_from_json(&read_bounded(
                &safe_file(&root, &entry.environment_file)?,
                MAX_JSON,
            )?)
            .map_err(|_| "invalid registered environment")?;
            let commitments = Commitments::compute(&state, environment)
                .map_err(|_| "invalid setup commitments")?;
            for (text, expected) in [
                (&entry.code_digest, commitments.code),
                (&entry.state_digest, commitments.state),
                (&entry.environment_digest, commitments.environment),
                (&entry.claim_digest, commitments.claim),
                (&entry.scenario_digest, commitments.scenario),
            ] {
                if fixed_hex::<32>(text, false).map_err(|_| "invalid registry digest")? != expected
                {
                    return Err("registry commitment does not match public setup");
                }
            }
            scenarios.push(Scenario {
                id: entry.id,
                label: entry.label,
                state,
                environment,
                commitments,
                image: image(&entry.guest_image_id)?,
            });
        }
        if scenarios[0].image != scenarios[1].image {
            return Err("scenario variants must share the generic guest");
        }
        Ok(Self { scenarios })
    }
    pub fn get(&self, id: &str) -> Result<&Scenario, &'static str> {
        self.scenarios
            .iter()
            .find(|s| s.id == id)
            .ok_or("unknown scenario")
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    pub format: String,
    pub scenario_id: String,
    pub scenario_digest: String,
    pub guest_image_id: String,
    pub nonce: String,
}
impl Challenge {
    pub fn new(scenario: &Scenario) -> Result<Self, &'static str> {
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(|_| "OS randomness unavailable")?;
        Ok(Self {
            format: "proofsphere-challenge-v1".into(),
            scenario_id: scenario.id.clone(),
            scenario_digest: hex::encode(scenario.commitments.scenario),
            guest_image_id: scenario.image.to_string(),
            nonce: hex::encode(nonce),
        })
    }
    pub fn load(path: &Path, scenario: &Scenario) -> Result<Self, &'static str> {
        let challenge: Self = parse_json(&read_bounded(path, MAX_JSON)?)
            .map_err(|_| "invalid owner challenge JSON")?;
        challenge.expected(scenario)?;
        Ok(challenge)
    }
    pub fn expected(&self, scenario: &Scenario) -> Result<Expected, &'static str> {
        if self.format != "proofsphere-challenge-v1"
            || self.scenario_id != scenario.id
            || fixed_hex::<32>(&self.scenario_digest, false)
                .map_err(|_| "invalid scenario digest")?
                != scenario.commitments.scenario
            || image(&self.guest_image_id)? != scenario.image
        {
            return Err("owner challenge does not match trusted scenario");
        }
        Ok(Expected {
            image: scenario.image,
            scenario: scenario.commitments.scenario,
            nonce: fixed_hex(&self.nonce, false).map_err(|_| "invalid owner nonce")?,
        })
    }
}
