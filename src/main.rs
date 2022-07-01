use bip0039::{
    bip39::{hex_string_to_bytes, Bip39},
    crypto::sha256,
    keytype,
    language::Language,
};

fn main() {
    let kt = keytype::KeyType::for_word_length(12).unwrap();

    let bip39 = match Bip39::new(&kt, Language::English, "") {
        Ok(b) => b,
        Err(e) => {
            println!("error: {:?}", e);
            return;
        }
    };

    let phrase = &bip39.mnemonic;
    let hex = &bip39.to_hex();
    println!("phrase: {:?}", phrase);
    println!("seed: {:?}", hex);
}
