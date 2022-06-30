#[derive(Debug)]
pub enum Bip0039Error {
    InvalidChecksum,
    InvalidKeysize,
    InvalidWordLength,
    EntropyUnavailable,
    LanguageUnavailable
}

impl From<std::io::Error> for Bip0039Error {
    fn from(_: std::io::Error) -> Self {
        Bip0039Error::EntropyUnavailable
    }
}