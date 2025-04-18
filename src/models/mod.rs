use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct NonceResponse {
    pub nonce: String,
}

#[derive(Deserialize, Serialize)]
pub struct SignedPayload {
    pub message: String,
    pub nonce: String,
    pub signature: String,
}