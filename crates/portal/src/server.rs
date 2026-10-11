use axum::{
    Json, Router,
    body::to_bytes,
    extract::{Request, State},
    http::{HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use proofsphere_model::claim::LABEL;
use proofsphere_proof::{
    container::{self, ContainerError},
    setup::{Challenge, Registry},
    verify,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    sync::{Arc, Mutex},
    time::Instant,
};
use tokio::sync::Semaphore;

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
enum Mode {
    Fresh,
    Recorded,
}
#[derive(Clone)]
struct Active {
    challenge: Challenge,
    generation: u64,
    mode: Mode,
}
struct Requests {
    active: Option<Active>,
    generation: u64,
}
pub struct AppState {
    registry: Registry,
    requests: Mutex<Requests>,
    verifier: Arc<Semaphore>,
    #[cfg(test)]
    before_verify: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}
impl AppState {
    pub fn new(registry: Registry, recorded: Option<Challenge>) -> Self {
        let active = recorded.map(|challenge| Active {
            challenge,
            generation: 1,
            mode: Mode::Recorded,
        });
        let generation = if active.is_some() { 1 } else { 0 };
        Self {
            registry,
            requests: Mutex::new(Requests { active, generation }),
            verifier: Arc::new(Semaphore::new(1)),
            #[cfg(test)]
            before_verify: Mutex::new(None),
        }
    }
}
fn report(status: &str, code: &str, active: Option<&Active>) -> Value {
    let mut result = json!({ "status": status, "code": code });
    if let Some(active) = active {
        result["scenario_id"] = active.challenge.scenario_id.clone().into();
        result["nonce"] = active.challenge.nonce.clone().into();
        result["generation"] = active.generation.to_string().into();
        result["mode"] = json!(active.mode);
    }
    result
}
fn response(status: StatusCode, code: &str, active: Option<&Active>) -> Response {
    let outcome = if matches!(code, "UNSUPPORTED_FORMAT" | "TOO_LARGE") {
        "rejected"
    } else {
        "error"
    };
    (status, Json(report(outcome, code, active))).into_response()
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route(
            "/",
            get(|| async { Html(include_str!("../../../apps/portal/index.html")) }),
        )
        .route(
            "/app.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    include_str!("../../../apps/portal/app.js"),
                )
            }),
        )
        .route(
            "/styles.css",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
                    include_str!("../../../apps/portal/styles.css"),
                )
            }),
        )
        .route("/api/scenarios", get(scenarios))
        .route("/api/challenge", get(download_challenge).post(challenge))
        .route("/api/verify", post(verify_proof))
        .layer(middleware::from_fn(security))
        .with_state(state)
}

async fn security(request: Request, next: Next) -> Response {
    let headers = request.headers();
    let host = headers.get(header::HOST).and_then(|h| h.to_str().ok());
    if !matches!(host, Some("127.0.0.1:4173" | "localhost:4173")) {
        return response(StatusCode::BAD_REQUEST, "INVALID_HOST", None);
    }
    if let Some(origin) = headers.get(header::ORIGIN) {
        let expected = format!("http://{}", host.unwrap_or_default());
        if origin.to_str().ok() != Some(expected.as_str()) {
            return response(StatusCode::FORBIDDEN, "INVALID_ORIGIN", None);
        }
    }
    if request.method() == Method::POST
        && headers
            .get("X-ProofSphere-UI")
            .and_then(|h| h.to_str().ok())
            != Some("1")
    {
        return response(StatusCode::FORBIDDEN, "UI_HEADER_REQUIRED", None);
    }
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        "X-Content-Type-Options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("Referrer-Policy", HeaderValue::from_static("no-referrer"));
    headers.insert("Content-Security-Policy", HeaderValue::from_static(
        "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"));
    response
}

async fn scenarios(State(state): State<Arc<AppState>>) -> Response {
    let active = match state.requests.lock() {
        Ok(r) => r.active.clone(),
        Err(_) => return response(StatusCode::INTERNAL_SERVER_ERROR, "OPERATIONAL_ERROR", None),
    };
    let scenarios: Vec<_> = state.registry.scenarios.iter().map(|s| json!({
        "id": s.id, "label": s.label, "scenario_digest": hex::encode(s.commitments.scenario),
        "code_digest": hex::encode(s.commitments.code), "state_digest": hex::encode(s.commitments.state),
        "environment_digest": hex::encode(s.commitments.environment), "claim_digest": hex::encode(s.commitments.claim),
        "guest_image_id": s.image.to_string(),
    })).collect();
    let active_request = active.map(|a| {
        json!({ "scenario_id": a.challenge.scenario_id, "nonce": a.challenge.nonce,
        "generation": a.generation.to_string(), "mode": a.mode })
    });
    Json(json!({ "scenarios": scenarios, "active_request": active_request })).into_response()
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    scenario_id: String,
}

async fn challenge(State(state): State<Arc<AppState>>, request: Request) -> Response {
    if request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        != Some("application/json")
    {
        return response(StatusCode::BAD_REQUEST, "UNSUPPORTED_FORMAT", None);
    }
    let bytes = match to_bytes(request.into_body(), 1024).await {
        Ok(bytes) => bytes,
        Err(_) => return response(StatusCode::PAYLOAD_TOO_LARGE, "TOO_LARGE", None),
    };
    let selection: Selection = match serde_json::from_slice(&bytes) {
        Ok(selection) => selection,
        Err(_) => return response(StatusCode::BAD_REQUEST, "UNSUPPORTED_FORMAT", None),
    };
    let scenario = match state.registry.get(&selection.scenario_id) {
        Ok(scenario) => scenario,
        Err(_) => return response(StatusCode::BAD_REQUEST, "UNKNOWN_SCENARIO", None),
    };
    let challenge = match Challenge::new(scenario) {
        Ok(challenge) => challenge,
        Err(_) => return response(StatusCode::INTERNAL_SERVER_ERROR, "OPERATIONAL_ERROR", None),
    };
    let mut requests = match state.requests.lock() {
        Ok(r) => r,
        Err(_) => return response(StatusCode::INTERNAL_SERVER_ERROR, "OPERATIONAL_ERROR", None),
    };
    let generation = match requests.generation.checked_add(1) {
        Some(generation) => generation,
        None => return response(StatusCode::INTERNAL_SERVER_ERROR, "OPERATIONAL_ERROR", None),
    };
    requests.generation = generation;
    requests.active = Some(Active {
        challenge: challenge.clone(),
        generation,
        mode: Mode::Fresh,
    });
    Json(json!({ "challenge": challenge, "generation": generation.to_string(), "mode": Mode::Fresh })).into_response()
}

async fn download_challenge(State(state): State<Arc<AppState>>) -> Response {
    let active = match state.requests.lock() {
        Ok(r) => r.active.clone(),
        Err(_) => return response(StatusCode::INTERNAL_SERVER_ERROR, "OPERATIONAL_ERROR", None),
    };
    match active {
        Some(active) => (
            [(
                header::CONTENT_DISPOSITION,
                "attachment; filename=challenge.json",
            )],
            Json(active.challenge),
        )
            .into_response(),
        None => response(StatusCode::CONFLICT, "NO_ACTIVE_CHALLENGE", None),
    }
}

async fn verify_proof(State(state): State<Arc<AppState>>, request: Request) -> Response {
    let active = match state.requests.lock() {
        Ok(r) => r.active.clone(),
        Err(_) => return response(StatusCode::INTERNAL_SERVER_ERROR, "OPERATIONAL_ERROR", None),
    };
    let Some(active) = active else {
        return response(StatusCode::CONFLICT, "NO_ACTIVE_CHALLENGE", None);
    };
    if request
        .headers()
        .get("X-ProofSphere-Generation")
        .and_then(|h| h.to_str().ok())
        != Some(active.generation.to_string().as_str())
    {
        return response(StatusCode::CONFLICT, "REQUEST_REPLACED", Some(&active));
    }
    if request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        != Some("application/octet-stream")
    {
        return response(StatusCode::BAD_REQUEST, "UNSUPPORTED_FORMAT", Some(&active));
    }
    let permit = match state.verifier.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return response(StatusCode::CONFLICT, "VERIFIER_BUSY", Some(&active)),
    };
    let bytes = match to_bytes(request.into_body(), container::MAX_FILE).await {
        Ok(bytes) => bytes,
        Err(_) => return response(StatusCode::PAYLOAD_TOO_LARGE, "TOO_LARGE", Some(&active)),
    };
    let expected = match state
        .registry
        .get(&active.challenge.scenario_id)
        .and_then(|s| active.challenge.expected(s))
    {
        Ok(expected) => expected,
        Err(_) => {
            return response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "OPERATIONAL_ERROR",
                Some(&active),
            );
        }
    };
    #[cfg(test)]
    let before_verify = state
        .before_verify
        .lock()
        .ok()
        .and_then(|hook| hook.clone());
    // The worker owns the permit. Dropping a disconnected HTTP future cannot release it early.
    let task = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        #[cfg(test)]
        if let Some(hook) = before_verify {
            hook();
        }
        let started = Instant::now();
        let result = match container::decode(&bytes) {
            Ok(receipt) => verify::verify(&receipt, expected)
                .map(|_| ())
                .map_err(|e| (StatusCode::OK, e.code())),
            Err(ContainerError::TooLarge) => Err((StatusCode::PAYLOAD_TOO_LARGE, "TOO_LARGE")),
            Err(ContainerError::UnsupportedFormat) => {
                Err((StatusCode::BAD_REQUEST, "UNSUPPORTED_FORMAT"))
            }
        };
        (result, started.elapsed().as_millis())
    });
    let result = match task.await {
        Ok(result) => result,
        Err(_) => {
            return response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "OPERATIONAL_ERROR",
                Some(&active),
            );
        }
    };
    let requests = match state.requests.lock() {
        Ok(r) => r,
        Err(_) => {
            return response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "OPERATIONAL_ERROR",
                Some(&active),
            );
        }
    };
    if requests.active.as_ref().map(|a| a.generation) != Some(active.generation) {
        return response(StatusCode::CONFLICT, "REQUEST_REPLACED", Some(&active));
    }
    match result {
        (Ok(()), elapsed) => {
            let mut output = report("accepted", "CLAIM_VERIFIED", Some(&active));
            output["claim"] = LABEL.into();
            output["verification_ms"] = json!(elapsed);
            Json(output).into_response()
        }
        (Err((status, code)), _) => {
            (status, Json(report("rejected", code, Some(&active)))).into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request as HttpRequest};
    use tower::ServiceExt;

    fn registry() -> Registry {
        Registry::load(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/registry.json"),
        )
        .unwrap()
    }
    fn request(method: Method, uri: &str, body: Vec<u8>) -> HttpRequest<Body> {
        let mut builder = HttpRequest::builder()
            .method(method.clone())
            .uri(uri)
            .header(header::HOST, "127.0.0.1:4173");
        if method == Method::POST {
            builder = builder.header("X-ProofSphere-UI", "1").header(
                header::CONTENT_TYPE,
                if uri == "/api/verify" {
                    "application/octet-stream"
                } else {
                    "application/json"
                },
            );
        }
        builder.body(Body::from(body)).unwrap()
    }
    async fn json_response(response: Response) -> (StatusCode, Value) {
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 8192).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }
    fn new_request(id: &str) -> HttpRequest<Body> {
        request(
            Method::POST,
            "/api/challenge",
            format!(r#"{{"scenario_id":"{id}"}}"#).into_bytes(),
        )
    }
    fn proof_request(generation: &str) -> HttpRequest<Body> {
        let mut request = request(Method::POST, "/api/verify", b"bad proof".to_vec());
        request
            .headers_mut()
            .insert("X-ProofSphere-Generation", generation.parse().unwrap());
        request
    }

    #[tokio::test]
    async fn owner_request_replaces_previous_nonce_and_rejects_stale_upload() {
        let app = router(Arc::new(AppState::new(registry(), None)));
        let (status, initial) = json_response(
            app.clone()
                .oneshot(request(Method::GET, "/api/scenarios", vec![]))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(initial["active_request"].is_null());
        let (status, missing) =
            json_response(app.clone().oneshot(proof_request("0")).await.unwrap()).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(missing["code"], "NO_ACTIVE_CHALLENGE");

        let (_, first) = json_response(
            app.clone()
                .oneshot(new_request("vault-vulnerable-v1"))
                .await
                .unwrap(),
        )
        .await;
        let (_, second) = json_response(
            app.clone()
                .oneshot(new_request("vault-patched-v1"))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(first["generation"], "1");
        assert_eq!(second["generation"], "2");
        assert_eq!(second["mode"], "fresh");
        assert_ne!(first["challenge"]["nonce"], second["challenge"]["nonce"]);
        let (status, stale) =
            json_response(app.clone().oneshot(proof_request("1")).await.unwrap()).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(stale["code"], "REQUEST_REPLACED");
        let (_, current) = json_response(
            app.clone()
                .oneshot(request(Method::GET, "/api/challenge", vec![]))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(current, second["challenge"]);
    }

    #[tokio::test]
    async fn recorded_startup_and_request_headers_remain_owner_controlled() {
        let registry = registry();
        let challenge = Challenge::load(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../evidence/demo/challenge.json"),
            registry.get("vault-vulnerable-v1").unwrap(),
        )
        .unwrap();
        let app = router(Arc::new(AppState::new(registry, Some(challenge))));
        let (_, data) = json_response(
            app.clone()
                .oneshot(request(Method::GET, "/api/scenarios", vec![]))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(data["active_request"]["mode"], "recorded");
        let mut foreign = new_request("vault-patched-v1");
        foreign
            .headers_mut()
            .insert(header::ORIGIN, "https://elsewhere.example".parse().unwrap());
        let (status, _) = json_response(app.clone().oneshot(foreign).await.unwrap()).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let mut no_ui = new_request("vault-patched-v1");
        no_ui.headers_mut().remove("X-ProofSphere-UI");
        let (status, _) = json_response(app.clone().oneshot(no_ui).await.unwrap()).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let mut foreign_host = request(Method::GET, "/api/scenarios", vec![]);
        foreign_host
            .headers_mut()
            .insert(header::HOST, "evil.example".parse().unwrap());
        let (status, _) = json_response(app.clone().oneshot(foreign_host).await.unwrap()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (_, still_recorded) = json_response(
            app.clone()
                .oneshot(request(Method::GET, "/api/scenarios", vec![]))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(still_recorded["active_request"]["mode"], "recorded");
        let (_, fresh) = json_response(
            app.clone()
                .oneshot(new_request("vault-patched-v1"))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(fresh["mode"], "fresh");
        assert_eq!(fresh["generation"], "2");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn aborted_http_waiter_does_not_release_verifier_permit() {
        use std::{sync::mpsc, time::Duration};
        let state = Arc::new(AppState::new(registry(), None));
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let release_rx = Arc::new(Mutex::new(release_rx));
        state
            .before_verify
            .lock()
            .unwrap()
            .replace(Arc::new(move || {
                started_tx.send(()).unwrap();
                release_rx
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap();
            }));
        let app = router(state.clone());
        let (_, first) = json_response(
            app.clone()
                .oneshot(new_request("vault-vulnerable-v1"))
                .await
                .unwrap(),
        )
        .await;
        let generation = first["generation"].as_str().unwrap().to_string();
        let worker = tokio::spawn(app.clone().oneshot(proof_request(&generation)));
        tokio::task::spawn_blocking(move || {
            started_rx.recv_timeout(Duration::from_secs(5)).unwrap()
        })
        .await
        .unwrap();
        worker.abort();
        let (status, busy) = json_response(
            app.clone()
                .oneshot(proof_request(&generation))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(busy["code"], "VERIFIER_BUSY");
        let (_, second) = json_response(
            app.clone()
                .oneshot(new_request("vault-patched-v1"))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(second["generation"], "2");
        release_tx.send(()).unwrap();
        let permit = tokio::time::timeout(Duration::from_secs(5), state.verifier.acquire())
            .await
            .unwrap()
            .unwrap();
        drop(permit);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn replacement_during_verification_never_returns_acceptance() {
        use std::{sync::mpsc, time::Duration};
        let state = Arc::new(AppState::new(registry(), None));
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let release_rx = Arc::new(Mutex::new(release_rx));
        state
            .before_verify
            .lock()
            .unwrap()
            .replace(Arc::new(move || {
                started_tx.send(()).unwrap();
                release_rx
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap();
            }));
        let app = router(state);
        let (_, first) = json_response(
            app.clone()
                .oneshot(new_request("vault-vulnerable-v1"))
                .await
                .unwrap(),
        )
        .await;
        let generation = first["generation"].as_str().unwrap().to_string();
        let worker = tokio::spawn(app.clone().oneshot(proof_request(&generation)));
        tokio::task::spawn_blocking(move || {
            started_rx.recv_timeout(Duration::from_secs(5)).unwrap()
        })
        .await
        .unwrap();
        let (_, second) = json_response(
            app.clone()
                .oneshot(new_request("vault-patched-v1"))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(second["generation"], "2");
        release_tx.send(()).unwrap();
        let (status, result) = json_response(worker.await.unwrap().unwrap()).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(result["code"], "REQUEST_REPLACED");
        assert!(result.get("claim").is_none());
    }
}
