use crate::{
    error::Bip0039Error
};

#[derive(Debug)]
pub enum KeyType {
    Key128,
    Key160,
    Key192,
    Key224,
    Key256
}

impl KeyType {
    pub fn for_keysize(size: usize) -> Result<KeyType, Bip0039Error> {
        let kt = match size {
            128 => KeyType::Key128,
            160 => KeyType::Key160,
            192 => KeyType::Key192,
            224 => KeyType::Key224,
            256 => KeyType::Key256,
            _ => {
                return Err(Bip0039Error::InvalidKeysize);
            }
        };

        Ok(kt)
    }

    pub fn for_word_length(length: usize) -> Result<KeyType, Bip0039Error> {
        let kt = match length {
            12 => KeyType::Key128,
            15 => KeyType::Key160,
            18 => KeyType::Key192,
            21 => KeyType::Key224,
            24 => KeyType::Key256,
            _ => {
                return Err(Bip0039Error::InvalidWordLength);
            }
        };

        Ok(kt)
    }

    pub fn for_mnemonic(mnemonic: &str) -> Result<KeyType, Bip0039Error> {
        let v: Vec<&str> = mnemonic.split(" ").into_iter().collect();

        let kt = match v.len() {
            12 => KeyType::Key128,
            15 => KeyType::Key160,
            18 => KeyType::Key192,
            21 => KeyType::Key224,
            24 => KeyType::Key256,
            _ => {
                return Err(Bip0039Error::InvalidWordLength);
            }
        };

        Ok(kt)
    }

    pub fn word_length(&self) -> usize {
        match *self {
            KeyType::Key128 => 12,
            KeyType::Key160 => 15,
            KeyType::Key192 => 18,
            KeyType::Key224 => 21,
            KeyType::Key256 => 24,
        }
    }

    pub fn total_bits(&self) -> usize {
        match *self {
            KeyType::Key128 => 132,
            KeyType::Key160 => 165,
            KeyType::Key192 => 198,
            KeyType::Key224 => 231,
            KeyType::Key256 => 264,
        }
    }

    pub fn entropy_bits(&self) -> usize {
        match *self {
            KeyType::Key128 => 128,
            KeyType::Key160 => 160,
            KeyType::Key192 => 192,
            KeyType::Key224 => 224,
            KeyType::Key256 => 256,
        }
    }

    pub fn checksum_bits(&self) -> usize {
        match *self {
            KeyType::Key128 => 4,
            KeyType::Key160 => 5,
            KeyType::Key192 => 6,
            KeyType::Key224 => 7,
            KeyType::Key256 => 8,
        }
    }
}
