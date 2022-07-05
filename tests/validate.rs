use bip0039::{bip39::Bip39, language::Language};

#[test]
fn validate_12_english() {
    let mnemonic = "solve gain health skill normal produce rug rebel churn planet rough balance";
    let bip0039 = Bip39::from_mnemonic(mnemonic.to_string(), Language::English, "".to_string());
    let _ = match bip0039 {
        Ok(b) => b,
        Err(_) => {
            assert!(false);
            return;
        }
    };
}

#[test]
fn validate_15_english() {
    let mnemonic = "hurdle dad three engage right seat domain canyon perfect edge shift cycle west bundle bright";
    let bip0039 = Bip39::from_mnemonic(mnemonic.to_string(), Language::English, "".to_string());
    let _ = match bip0039 {
        Ok(b) => b,
        Err(_) => {
            assert!(false);
            return;
        }
    };
}

#[test]
fn validate_mnemonic() {
    let mnemonic = "hurdle dad three engage right seat domain canyon perfect edge shift cycle west bundle bright";
    match Bip39::validate(&(mnemonic.to_string()), &Language::English) {
        Ok(res) => res,
        Err(_) => {
            assert!(false);
            return;
        }
    };
}
