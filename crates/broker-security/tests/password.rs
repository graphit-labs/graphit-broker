use broker_security::{LocalPasswordError, LocalPasswordHasher};
use zeroize::Zeroizing;

const PASSWORD: &str = "a sufficiently long native LOCAL password";
fn owner(pepper: u8) -> LocalPasswordHasher {
    LocalPasswordHasher::new(Zeroizing::new(vec![pepper; 32].into_boxed_slice())).unwrap()
}
#[test]
fn native_phc_is_salted_peppered_and_sdk_verified() {
    let owner = owner(31);
    let first = owner.hash(PASSWORD).unwrap();
    let second = owner.hash(PASSWORD).unwrap();
    assert!(
        first.as_str() != second.as_str(),
        "SDK must generate unique salts"
    );
    assert!(first.starts_with("$argon2id$v=19$m=65536,t=3,p=4$"));
    assert!(owner.verify(PASSWORD, &first).unwrap());
    assert!(
        !owner
            .verify("another sufficiently long native password", &first)
            .unwrap()
    );
    assert!(!self::owner(32).verify(PASSWORD, &first).unwrap());
    assert_eq!(format!("{owner:?}"), "LocalPasswordHasher([REDACTED])");
    assert_eq!(
        LocalPasswordError::InvalidHash.to_string(),
        "invalid LOCAL password hash"
    );
}
#[test]
fn creation_counts_unicode_characters_and_caps_input_bytes() {
    let owner = owner(31);
    assert!(matches!(
        owner.hash(&"é".repeat(14)),
        Err(LocalPasswordError::InvalidPassword)
    ));
    let unicode = "é".repeat(15);
    let hash = owner.hash(&unicode).unwrap();
    assert!(owner.verify(&unicode, &hash).unwrap());
    assert!(matches!(
        owner.hash(&"x".repeat(4097)),
        Err(LocalPasswordError::InvalidPassword)
    ));
    assert!(matches!(
        owner.verify(&"x".repeat(4097), &hash),
        Err(LocalPasswordError::InvalidPassword)
    ));
    let maximum = "x".repeat(4096);
    let hash = owner.hash(&maximum).unwrap();
    assert!(owner.verify(&maximum, &hash).unwrap());
    assert!(matches!(
        LocalPasswordHasher::new(Zeroizing::new(vec![1; 31].into_boxed_slice())),
        Err(LocalPasswordError::Configuration)
    ));
}
#[test]
fn malformed_phc_and_excessive_work_are_rejected_before_kdf() {
    let owner = owner(31);
    let valid = owner.hash(PASSWORD).unwrap();
    for malformed in [
        "invalid".to_owned(),
        valid.replace("argon2id", "argon2i"),
        valid.replace("v=19", "v=16"),
        valid.replace("m=65536", "m=1048577"),
        valid.replace("m=65536", "m=0"),
        valid.replace("t=3", "t=11"),
        valid.replace("t=3", "t=0"),
        valid.replace("p=4", "p=17"),
        valid.replace("p=4", "p=0"),
        valid.replace("m=65536,t=3,p=4", "m=65536,t=3"),
        valid.replace("m=65536,t=3,p=4", "m=65536,t=3,p=4,t=3"),
        valid.replace("m=65536,t=3,p=4", "m=65536,t=3,p=4,data=YXNkZg"),
        format!("{}$trailing", valid.as_str()),
        "x".repeat(513),
        "$argon2id$v=19$m=65536,t=3,p=4$c2hvcnQ$aGFzaA".to_owned(),
    ] {
        assert_eq!(
            LocalPasswordHasher::validate_hash(&malformed),
            Err(LocalPasswordError::InvalidHash)
        );
    }
    assert!(LocalPasswordHasher::validate_hash(&valid).is_ok());
}
