use axum::{extract::{FromRef, State}, routing::{get, post}, Json, Router};
use base64::{engine::general_purpose, Engine};
use rand::{distributions::Alphanumeric, Rng};
use reqwest::StatusCode;
use rsa::{pkcs8::DecodePublicKey, sha2::{Digest, Sha256}, Pkcs1v15Sign, RsaPublicKey};
use tokio::sync::Mutex;
use verifier::models::{NonceResponse, SignedPayload};
use std::{collections::HashSet, fs, sync::Arc};

type SharedNonces = Arc<Mutex<HashSet<String>>>;

#[derive(Clone)]
struct AppState {
    nonces: SharedNonces,
}

impl FromRef<AppState> for SharedNonces {
    fn from_ref(app_state: &AppState) -> Self {
        app_state.nonces.clone()
    }
}

#[tokio::main]
async fn main() {
    let nonces = Arc::new(Mutex::new(HashSet::new()));
    let app_state = AppState { nonces };

    let app = Router::new()
        .route("/nonce", get(generate_nonce))
        .route("/verify", post(verify_signature))
        .with_state(app_state);
    
    let listener = tokio::net::TcpListener::bind("lcoalhost:7878").await.unwrap();
    println!("Now listening...");
    axum::serve(listener, app).await.unwrap();
}

#[axum::debug_handler]
async fn generate_nonce(State(nonces): State<SharedNonces>) -> Json<NonceResponse> {
    let nonce: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    // Mark nonce as used
    let mut nonce_store = nonces.lock().await;
    nonce_store.insert(nonce.clone()); 

    return Json(NonceResponse { nonce });
}

#[axum::debug_handler]
async fn verify_signature(
    State(nonces): State<SharedNonces>, 
    Json(payload): Json<SignedPayload>
) -> Result<StatusCode, StatusCode> {
    // Check nonce hasn't been used
    let nonce_store = nonces.lock().await;
    if nonce_store.contains(&payload.nonce) {
        return Err(StatusCode::CONFLICT); // Replay detected
    }

    let public_key_pem = fs::read_to_string("./src/keys/public_key.pem").unwrap();
    let public_key = RsaPublicKey::from_public_key_pem(&public_key_pem).map_err(|_| StatusCode::BAD_REQUEST).unwrap();

    let signature_bytes = general_purpose::STANDARD.decode(&payload.signature).map_err(|_| StatusCode::BAD_REQUEST).unwrap();
    
    let hash = Sha256::digest(payload.message);
    let padding = Pkcs1v15Sign::new::<Sha256>();

    if public_key.verify(padding, &hash, &signature_bytes).is_ok() {
        Ok(StatusCode::OK)
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}
