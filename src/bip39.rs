use crate::language::Language;

static BIP39_WORDLIST_ENGLISH: &'static str = include_str!("words/en.txt");
static CHARS: &'static[u8] = b"0123456789abcdef";

pub struct Bip39 {
    pub mnemonic: String,
    pub seed: Vec<u8>,
    pub lang: Language,
}
