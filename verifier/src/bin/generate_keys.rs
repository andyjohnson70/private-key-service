use std::path::Path;
use rsa::{self, pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding}, RsaPrivateKey};
use rand::{self};

// Script to generate public and private keys. Using RSA to generate keys and writing them in PKCS8 format.
// Can store private key with SecureStore
fn main() {
    let mut rng = rand::thread_rng();
    let bits = 2048;
    let priv_key = RsaPrivateKey::new(&mut rng, bits).unwrap();
    let pub_key = priv_key.to_public_key();
    let priv_path = Path::new("./src/keys/private_key.pem");
    let _ = priv_key.write_pkcs8_pem_file(priv_path, rsa::pkcs8::LineEnding::default()).unwrap();
    let pub_path = Path::new("./src/keys/public_key.pem");
    let _ = pub_key.write_public_key_pem_file(pub_path, LineEnding::default()).unwrap();
}