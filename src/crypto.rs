use {
    crypto::{
        hmac::Hmac,
        digest::Digest,
        sha2::{Sha256, Sha512},
        pbkdf2::pbkdf2 as crypto_pbkdf2,
    },
    rand::{
        rngs::OsRng,
        RngCore,
    },
};

use crate::{
    error::Bip0039Error
};

static PBKDF2_ROUNDS: u32 = 2048;
static PBKDF2_BYTES: usize = 64;

pub fn sha256(input: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.input(input);

    hash.result_str()
}

pub fn gen_random_bytes(length: usize) -> Result<Vec<u8>, Bip0039Error> {
    let mut entropy = vec![0u8; length];
    OsRng.fill_bytes(&mut entropy);

    Ok(entropy)
}

pub fn pbkdf2(input: &[u8], salt: String) -> Vec<u8> {
    let mut hmac = Hmac::new(Sha512::new(), input);
    let mut seed = vec![0u8; PBKDF2_BYTES];
    crypto_pbkdf2(&mut hmac, salt.as_bytes(), PBKDF2_ROUNDS, &mut seed);

    seed
}
