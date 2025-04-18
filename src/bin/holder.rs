use rand::thread_rng;
use rsa::{pkcs8::DecodePrivateKey, sha2::{Digest, Sha256}, Pkcs1v15Sign, RsaPrivateKey};
use verifier::models::{SignedPayload, NonceResponse};
use std::fs;
use base64::{engine::general_purpose, Engine};
use reqwest::blocking::Client;

fn main() {
    let client = Client::new();

    let nonce_res: NonceResponse = client
        .get("http://localhost:7878/nonce")
        .send().unwrap()
        .json().unwrap();

    let nonce = nonce_res.nonce;

    let priv_key_pem = fs::read_to_string("./src/keys/private_key.pem").unwrap();
    let priv_key = RsaPrivateKey::from_pkcs8_pem(&priv_key_pem).unwrap();
    
    let message = "hello world";
    let hash = Sha256::digest(message);
    let padding = Pkcs1v15Sign::new::<Sha256>();
    let mut rng = thread_rng();
    let signature = priv_key.sign_with_rng(&mut rng, padding, &hash).unwrap();

    let payload = SignedPayload {
        message: message.to_string(),
        nonce,
        signature: general_purpose::STANDARD.encode(&signature)
    };

    let verify_res = client
        .post("http://localhost:7878/verify")
        .json(&payload)
        .send().unwrap();

    println!("Verify response: {}", verify_res.status());
}