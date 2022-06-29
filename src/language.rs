use crate::error::Bip0039Error;

#[derive(Debug)]
pub enum Language {
    English
}

impl Language {
    pub fn for_loccale(locale: &str) -> Result<Language, Bip0039Error> {
        let lang = match locale {
            "en_US.UTF-8" => Language::English,
            "en_GB.UTF-8" => Language::English,

            _ => {
                return Err(Bip0039Error::LanguageUnavailable);
            }
        };

        Ok(lang)
    }
}
