use bitreader::BitReader;

use crate::{
    crypto::{gen_random_bytes, sha256},
    error::Bip0039Error,
    keytype::KeyType,
    language::Language,
};

static BIP39_WORDLIST_ENGLISH: &'static str = include_str!("words/en.txt");

pub struct Bip39 {
    pub mnemonic: String,
    pub seed: Vec<u8>,
    pub lang: Language,
}

impl Bip39 {
    fn to_hex(&self) -> String {
        static CHARS: &'static [u8] = b"0123456789abcdef";

        let seed: &[u8] = self.seed.as_ref();
        let mut v = Vec::with_capacity(seed.len() * 2);
        for &byte in seed.iter() {
            v.push(CHARS[(byte >> 4) as usize]);
            v.push(CHARS[(byte & 0xf) as usize]);
        }

        unsafe { String::from_utf8_unchecked(v) }
    }

    pub fn new(key_type: &KeyType, lang: Language, password: &str) -> Result<Bip39, Bip0039Error> {
        let entropy_bits = key_type.entropy_bits();
        let num_words = key_type.total_bits();
        let word_list = Bip39::wordlist(&lang);
        let entropy = gen_random_bytes(entropy_bits / 8)?;
        let entropy_hash = sha256(entropy.as_ref()).from_hex().unwrap();

        let mut combined = Vec::from(entropy);
        combined.extend(&entropy_hash);
        let mut reader = BitReader::new(combined.as_ref());

        let mut words = Vec::new();
        for _ in 0..num_words {
            let n = reader.read_u16(11);
            words.push(word_list[n.unwrap() as usize].as_ref());
        }

        let mnemonic = words.join(" ");
        Bip39::from_mnemonic(mnemonic, lang, password.to_string())
    }

    pub fn from_mnemonic(
        mnemonic: String,
        lang: Language,
        password: String,
    ) -> Result<Bip39, Bip0039Error> {
        Bip39::validate(&mnemonic, &lang)?;

        Ok(Bip39 {
            mnemonic: mnemonic.clone(),
            seed: vec![],
            lang: lang,
        })
    }

    pub fn validate(mnemonic: &String, lang: &Language) -> Result<(), Bip0039Error> {
        if (mnemonic == "") {
            return Err(Bip0039Error::EntropyUnavailable);
        }

        Ok(())
    }

    fn wordlist(lang: &Language) -> Vec<String> {
        let lang_words = match *lang {
            Language::English => BIP39_WORDLIST_ENGLISH,
        };

        lang_words.split_whitespace().map(|s| s.into()).collect()
    }
}
