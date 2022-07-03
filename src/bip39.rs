use {bit_vec::BitVec, bitreader::BitReader};

use crate::{
    crypto::{gen_random_bytes, pbkdf2, sha256},
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
    pub fn to_hex(&self) -> String {
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
        let num_words = key_type.word_length();
        let word_list = Bip39::wordlist(&lang);
        let entropy = gen_random_bytes(entropy_bits / 8)?;
        let entropy_hash = hex_string_to_bytes(&sha256(entropy.as_ref()));

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
            seed: Bip39::generate_seed(&mnemonic.as_bytes(), &password),
            lang: lang,
        })
    }

    pub fn validate(mnemonic: &String, lang: &Language) -> Result<(), Bip0039Error> {
        if mnemonic == "" {
            return Err(Bip0039Error::EntropyUnavailable);
        }

        let key_type = KeyType::for_mnemonic(&mnemonic)?;
        let entropy_bits = key_type.entropy_bits();
        let checksum_bits = key_type.checksum_bits();

        let mut word_map = std::collections::HashMap::new();
        let word_list = Bip39::wordlist(lang);

        for (i, item) in word_list.into_iter().enumerate() {
            word_map.insert(item, i as u16);
        }

        let mut to_validate = BitVec::new();
        for word in mnemonic.split(" ").into_iter() {
            let n = word_map.get(word).unwrap();
            for i in 0..11 {
                let bit = Bip39::bit_from_u16_as_u11(*n, i);
                to_validate.push(bit);
            }
        }

        let mut checksum_to_validate = BitVec::new();
        &checksum_to_validate.extend((&to_validate).into_iter().skip(entropy_bits).take(checksum_bits);
        assert_eq!(checksum_to_validate.len(), checksum_bits, "invalid checksum size");

        let mut entropy_to_validate = BitVec::new();
        &entropy_to_validate.extend((&to_validate).into_iter().take(entropy_bits));
        assert_eq!(entropy_to_validate.len(), entropy_bits, "invalid entropy size");

        let hash = sha256(entropy_to_validate.to_bytes().as_ref()).from_hex().unwrap();
        let entropy_hash_to_validate_bits = BitVec::from_bytes(hash.as_ref());

        let mut new_checksum = BitVec::new();
        &new_checksum.extend(entropy_hash_to_validate_bits.into_iter().take(checksum_bits));
        assert_eq!(new_checksum.len(), checksum_bits, "invalid new checksum size");
        if !(new_checksum == checksum_to_validate) {
            return Err(Bip39Error::InvalidChecksum)
        }

        Ok(())
    }

    fn wordlist(lang: &Language) -> Vec<String> {
        let lang_words = match *lang {
            Language::English => BIP39_WORDLIST_ENGLISH,
        };

        lang_words.split_whitespace().map(|s| s.into()).collect()
    }

    fn generate_seed(entropy: &[u8], password: &str) -> Vec<u8> {
        let salt = format!("mnemonic{}", password);
        pbkdf2(entropy, salt)
    }

    fn bit_from_u16_as_u11(input: u16, position: u16) -> bool {
        if position < 11 {
            input & (1 << (10 - position)) != 0
        } else {
            false
        }
    }
}

pub fn hex_string_to_bytes(str: &String) -> Vec<u8> {
    let mut b = Vec::with_capacity(str.len() / 2);
    let mut modulus = 0;
    let mut buf = 0;

    for (idx, byte) in str.bytes().enumerate() {
        buf <<= 4;
        match byte {
            b'A'..=b'F' => buf |= byte - b'A' + 10,
            b'a'..=b'f' => buf |= byte - b'a' + 10,
            b'0'..=b'9' => buf |= byte - b'0',
            b' ' | b'\r' | b'\n' | b'\t' => {
                buf >>= 4;
                continue;
            }
            _ => {
                return vec![];
            }
        }

        modulus += 1;
        if modulus == 2 {
            modulus = 0;
            b.push(buf);
        }
    }

    match modulus {
        0 => b.into_iter().collect(),
        _ => vec![],
    }
}
