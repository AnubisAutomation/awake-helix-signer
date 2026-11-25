//! Known-answer vectors shared with the scripts repository, the website and
//! public specifications: session key attestation (EIP-712), per-bot key
//! derivation, BIP-39/BIP-32/BIP-44, Web3 Secret Storage keystores, EIP-55,
//! RLP, EIP-191.

use helix_signer_core::address::{keccak, Address};
use helix_signer_core::constants as c;
use helix_signer_core::keys::bip39;
use helix_signer_core::tx::Rlp;
use helix_signer_core::{attestation_digest, production, verify_attestation, KeyMaterial, Zeroizing};
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::Sha256;

// Shared with the Anubis Automation website's session key tests
// (and formerly the Python signer's tests): seed bytes(range(32)), this owner, this bot.
// The key derivation labels keep their AWAKE_HELIX_ names (they derive the
// website's keys); the attestation's EIP-712 domain is
// "Anubis Automation Session Key Attestation" since signer 0.7.0.
const VECTOR_ATTESTOR: &str = "0xA9BeE92e6C1d43B162D799883E4401485C9a3334";
const VECTOR_OWNER: &str = "0x1111111111111111111111111111111111111111";
const VECTOR_BOT: &str = "123e4567-e89b-42d3-a456-426614174000";
const VECTOR_SESSION_KEY: &str = "0x0AdfFDca6dcc6ad2F86340af27ba616370e69B70";
const VECTOR_SIGNATURE: &str = "0xb735d7e90479cf7c5bd33806bce744ac66ec83fdedfa711114fbdb878df8aa2a4e0de9e0a265f30c2529c7a6f65282dd7eed53014e9ed872c8aba54740fa0f381b";
/// The same attestation signed under the domain name signers before 0.7.0 used
/// ("Awake Helix Session Key Attestation"): no longer accepted.
const VECTOR_SIGNATURE_BEFORE_0_7: &str = "0x80d6cf5a80a39c1c383281c03743c9a850e0bb1e2fefb3860e5e7a3debe717b33244251c624e799a1e43afa435fce5d6352f58b541559050a0b877937b0d773b1c";

fn bot_bytes() -> [u8; 16] {
    let mut out = [0u8; 16];
    hex::decode_to_slice(VECTOR_BOT.replace('-', ""), &mut out).unwrap();
    out
}

/// The website's session key derivation: the first HMAC-SHA256 digest that is a valid key.
fn derive(seed: &[u8], message: &[u8]) -> KeyMaterial {
    for counter in 0u8..=255 {
        let mut mac = Hmac::<Sha256>::new_from_slice(seed).unwrap();
        mac.update(message);
        mac.update(&[counter]);
        let digest = mac.finalize().into_bytes();
        if let Ok(material) = KeyMaterial::from_private_key(&hex::encode(digest)) {
            return material;
        }
    }
    panic!("no key");
}

fn seed() -> Vec<u8> {
    (0u8..32).collect()
}

#[test]
fn per_bot_key_derivation_vector() {
    let attestor = derive(&seed(), b"AWAKE_HELIX_SESSION_ATTESTATION_KEY_V1\x00");
    assert_eq!(attestor.address().to_checksum(), VECTOR_ATTESTOR);
    let mut message = b"AWAKE_HELIX_SESSION_KEY_V1\x00".to_vec();
    let mut chain = [0u8; 32];
    chain[24..].copy_from_slice(&6714u64.to_be_bytes());
    message.extend_from_slice(&chain);
    message.extend_from_slice(&Address::parse(VECTOR_OWNER).unwrap().0);
    message.extend_from_slice(&bot_bytes());
    assert_eq!(derive(&seed(), &message).address().to_checksum(), VECTOR_SESSION_KEY);
}

#[test]
fn attestation_signature_vector_is_reproduced_byte_for_byte() {
    let attestor = derive(&seed(), b"AWAKE_HELIX_SESSION_ATTESTATION_KEY_V1\x00");
    let owner = Address::parse(VECTOR_OWNER).unwrap();
    let session = Address::parse(VECTOR_SESSION_KEY).unwrap();
    let digest = attestation_digest(6714, &owner, &bot_bytes(), &session);
    let signature = attestor.sign_digest(&digest).unwrap();
    assert_eq!(format!("0x{}", hex::encode(signature.to_bytes_65())), VECTOR_SIGNATURE);
}

#[test]
fn attestation_vector_verifies_against_its_attestor_only() {
    let owner = Address::parse(VECTOR_OWNER).unwrap();
    let session = Address::parse(VECTOR_SESSION_KEY).unwrap();
    let document = json!({"version": 1, "chainId": 6714, "owner": VECTOR_OWNER, "botId": VECTOR_BOT, "sessionKey": VECTOR_SESSION_KEY, "signature": VECTOR_SIGNATURE});
    let mut constants = production();
    constants.attestation_address = Address::parse(VECTOR_ATTESTOR).unwrap();
    verify_attestation(Some(&document), &owner, &bot_bytes(), &session, &constants).unwrap();
    let error = verify_attestation(Some(&document), &owner, &bot_bytes(), &session, &production()).unwrap_err();
    assert!(error.message().contains("not by the platform key"), "{error}");
    constants.attestation_address = Address::constant(c::ATTESTATION_PLACEHOLDER);
    let error = verify_attestation(Some(&document), &owner, &bot_bytes(), &session, &constants).unwrap_err();
    assert!(error.message().contains("no platform attestation address"), "{error}");
}

#[test]
fn attestation_under_the_former_domain_name_is_refused() {
    assert_eq!(c::ATTESTATION_NAME, "Anubis Automation Session Key Attestation");
    assert_eq!(c::ATTESTATION_DOMAIN_VERSION, "1");
    let owner = Address::parse(VECTOR_OWNER).unwrap();
    let session = Address::parse(VECTOR_SESSION_KEY).unwrap();
    let document = json!({"version": 1, "chainId": 6714, "owner": VECTOR_OWNER, "botId": VECTOR_BOT, "sessionKey": VECTOR_SESSION_KEY, "signature": VECTOR_SIGNATURE_BEFORE_0_7});
    let mut constants = production();
    constants.attestation_address = Address::parse(VECTOR_ATTESTOR).unwrap();
    let error = verify_attestation(Some(&document), &owner, &bot_bytes(), &session, &constants).unwrap_err();
    assert!(error.message().contains("not by the platform key"), "{error}");
}

#[test]
fn typed_data_hash_is_plain_eip712() {
    let word = |value: u64| {
        let mut out = [0u8; 32];
        out[24..].copy_from_slice(&value.to_be_bytes());
        out
    };
    let mut domain = keccak(b"EIP712Domain(string name,string version,uint256 chainId)").to_vec();
    domain.extend_from_slice(&keccak(b"Anubis Automation Session Key Attestation"));
    domain.extend_from_slice(&keccak(b"1"));
    domain.extend_from_slice(&word(6714));
    let mut message = keccak(b"SessionKeyAttestation(uint256 version,uint256 chainId,address owner,bytes16 botId,address sessionKey)").to_vec();
    message.extend_from_slice(&word(1));
    message.extend_from_slice(&word(6714));
    message.extend_from_slice(&Address::parse(VECTOR_OWNER).unwrap().word());
    let mut bot = [0u8; 32];
    bot[..16].copy_from_slice(&bot_bytes());
    message.extend_from_slice(&bot);
    message.extend_from_slice(&Address::parse(VECTOR_SESSION_KEY).unwrap().word());
    let mut digest = b"\x19\x01".to_vec();
    digest.extend_from_slice(&keccak(&domain));
    digest.extend_from_slice(&keccak(&message));
    let digest = keccak(&digest);
    let owner = Address::parse(VECTOR_OWNER).unwrap();
    let session = Address::parse(VECTOR_SESSION_KEY).unwrap();
    assert_eq!(digest, attestation_digest(6714, &owner, &bot_bytes(), &session));
    let mut signature = [0u8; 65];
    hex::decode_to_slice(&VECTOR_SIGNATURE[2..], &mut signature).unwrap();
    assert_eq!(helix_signer_core::secp::recover_65(&digest, &signature).unwrap().to_checksum(), VECTOR_ATTESTOR);
}

#[test]
fn hardhat_mnemonic_accounts() {
    let phrase = "test test test test test test test test test test test junk";
    for (index, expected) in [(0, "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"), (1, "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"), (2, "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC")] {
        let material = KeyMaterial::from_mnemonic(phrase, index, "").unwrap();
        assert_eq!(material.address().to_checksum(), expected);
        assert_eq!(material.path(), format!("m/44'/60'/0'/0/{index}"));
        assert_eq!(material.source(), "mnemonic");
    }
    // Extra whitespace (and the ideographic space) is normalized like Python's split().
    let spaced = "  test\u{3000}test test test test test test test test test test junk\n";
    assert_eq!(KeyMaterial::from_mnemonic(spaced, 0, "").unwrap().address().to_checksum(), "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
    for bad in ["test words that are not valid at all here twelve", "test test test test test test test test test test test test", ""] {
        let error = KeyMaterial::from_mnemonic(bad, 0, "").unwrap_err();
        assert_eq!(error.message(), "This is not a valid BIP-39 mnemonic (check the words and their order).");
        assert!(!error.message().contains("twelve"));
    }
    assert!(KeyMaterial::from_mnemonic(phrase, -1, "").is_err());
    assert!(KeyMaterial::from_mnemonic(phrase, 2_147_483_648, "").is_err());
}

#[test]
fn bip39_specification_vector() {
    // Trezor test vector: entropy 00..00, passphrase "TREZOR".
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    assert!(bip39::is_valid(phrase, "english"));
    let seed = bip39::to_seed(phrase, "TREZOR");
    assert_eq!(
        hex::encode(seed.as_ref()),
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
    );
    assert_eq!(bip39::detect_language(phrase), Some("english"));
    // "abandon" is also French: eth-account refuses words valid in two languages.
    assert_eq!(bip39::detect_language(&phrase.replace("about", "abandon")), None);
    assert!(!bip39::is_valid(&phrase.replace("about", "abandon"), "english"));
}

#[test]
fn web3_secret_storage_vectors() {
    // Web3 Secret Storage specification test vector (PBKDF2, password "testpassword").
    let pbkdf2 = json!({
        "crypto": {"cipher": "aes-128-ctr", "cipherparams": {"iv": "6087dab2f9fdbbfaddc31a909735c1e6"},
            "ciphertext": "5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46",
            "kdf": "pbkdf2", "kdfparams": {"c": 262144, "dklen": 32, "prf": "hmac-sha256", "salt": "ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"},
            "mac": "517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2"},
        "id": "3198bc9c-6672-5ab3-d995-4942343ae5b6", "version": 3
    });
    // Written by eth-account (Account.encrypt, scrypt n=1024) for the same key.
    let scrypt = json!({"address": "008AeEda4D805471dF9b2A5B0f38A0C3bCBA786b", "crypto": {"cipher": "aes-128-ctr", "cipherparams": {"iv": "4ad69de22c58b49e0af5d3d4fda25a34"}, "ciphertext": "945b5372b10979c3bf3ff52908237bac63abbb031e41aea87022f84416440334", "kdf": "scrypt", "kdfparams": {"dklen": 32, "n": 1024, "r": 8, "p": 1, "salt": "663454fd4408f4ad25ba00867c5528e0"}, "mac": "b897584cd079c29dded399f3cc9ea79fdf0c2822dba61792a98cd3dab10a0779"}, "id": "b2fce729-82f0-4663-8d64-e6379e34d245", "version": 3});
    let expected = KeyMaterial::from_private_key("7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d").unwrap().address();
    for document in [pbkdf2, scrypt] {
        let material = KeyMaterial::from_keystore_json(&document.to_string(), "vector.json", "testpassword").unwrap();
        assert_eq!(material.address(), expected);
        let error = KeyMaterial::from_keystore_json(&document.to_string(), "vector.json", "wrong").unwrap_err();
        assert_eq!(error.message(), "Wrong keystore password, or the keystore is damaged.");
    }
}

#[test]
fn keystore_round_trip_and_refusals() {
    let folder = std::env::temp_dir().join(format!("helix-keystore-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&folder);
    let material = KeyMaterial::from_private_key(&"42".repeat(32)).unwrap();
    let out = folder.join("new.json");
    let path = helix_signer_core::create_keystore(&material, "long password", &out, helix_signer_core::Kdf::Pbkdf2, Some(1000)).unwrap();
    assert_eq!(KeyMaterial::from_keystore(&path, "long password").unwrap().address(), material.address());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }
    assert!(helix_signer_core::create_keystore(&material, "long password", &out, helix_signer_core::Kdf::Pbkdf2, Some(1000)).unwrap_err().message().contains("already exists"));
    assert!(helix_signer_core::create_keystore(&material, "short", &folder.join("b.json"), helix_signer_core::Kdf::Pbkdf2, Some(1000)).unwrap_err().message().contains("8 characters"));
    let scrypt = folder.join("scrypt.json");
    helix_signer_core::create_keystore(&material, "long password", &scrypt, helix_signer_core::Kdf::Scrypt, Some(1024)).unwrap();
    assert_eq!(KeyMaterial::from_keystore(&scrypt, "long password").unwrap().address(), material.address());
    let mut document: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    document["address"] = json!("11".repeat(20));
    assert_eq!(
        KeyMaterial::from_keystore_json(&document.to_string(), "x", "long password").unwrap_err().message(),
        "The keystore's address field does not match its key."
    );
    assert!(KeyMaterial::from_keystore_json("{}", "x.json", "p").unwrap_err().message().contains("is not an Ethereum keystore"));
    assert!(KeyMaterial::from_keystore(&folder.join("missing.json"), "p").unwrap_err().message().contains("Cannot read the keystore file"));
    let _ = std::fs::remove_dir_all(&folder);
}

#[test]
fn keystore_json_round_trip_without_a_file() {
    let material = KeyMaterial::from_private_key(&"42".repeat(32)).unwrap();
    let text = helix_signer_core::keystore_json(&material, "long password").unwrap();
    let document: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(document["version"], json!(3));
    assert_eq!(document["crypto"]["kdf"], json!("scrypt"));
    assert_eq!(document["crypto"]["kdfparams"]["n"], json!(262144));
    assert_eq!(document["address"], json!(material.address().to_checksum().trim_start_matches("0x")));
    assert_eq!(KeyMaterial::from_keystore_json(&text, "x.json", "long password").unwrap().address(), material.address());
    assert!(KeyMaterial::from_keystore_json(&text, "x.json", "wrong password").is_err());
    assert!(!text.contains(&"42".repeat(32)));
    assert!(helix_signer_core::keystore_json(&material, "short").unwrap_err().message().contains("8 characters"));
}

#[test]
fn private_key_forms_and_hygiene() {
    let key = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
    let expected = "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23";
    assert_eq!(KeyMaterial::from_private_key(key).unwrap().address().to_checksum(), expected);
    assert_eq!(KeyMaterial::from_private_key(&format!("0x{key}\n")).unwrap().address().to_checksum(), expected);
    for bad in ["", "0x1234", &"zz".repeat(32), &"00".repeat(32), &"ff".repeat(32)] {
        let error = KeyMaterial::from_private_key(bad).unwrap_err();
        if !bad.is_empty() {
            assert!(!error.message().contains(bad));
        }
    }
    let mut material = KeyMaterial::from_private_key(key).unwrap();
    assert!(!format!("{material:?}").contains(key));
    let copy = material.clone();
    material.wipe();
    assert!(material.is_wiped());
    assert_eq!(material.sign_message("x").unwrap_err().message(), "The key was already wiped.");
    assert!(!copy.is_wiped());
    let _guard: Zeroizing<String> = Zeroizing::new(String::from("secret"));
}

#[test]
fn personal_sign_vector() {
    // eth-account's documented example key and message.
    let material = KeyMaterial::from_private_key("b25c7db31feed9122727bf0939dc769a96564b2de4c4726d035b36ecf1e5b364").unwrap();
    assert_eq!(material.address().to_checksum(), "0x5ce9454909639D2D17A3F753ce7d93fa0b9aB12E");
    let signature = material.sign_message("I♥SF").unwrap();
    assert_eq!(
        signature,
        "0xe6ca9bba58c88611fad66a6ce8f996908195593807c4b38bd528d2cff09d4eb33e5bfbbf4d3e39b1a2fd816a7680c19ebebaf3a141b239934ad43cb33fcec8ce1c"
    );
}

#[test]
fn rlp_specification_values() {
    assert_eq!(Rlp::Bytes(Vec::new()).encode(), vec![0x80]);
    assert_eq!(Rlp::u64(15).encode(), vec![0x0f]);
    assert_eq!(Rlp::List(vec![Rlp::List(vec![]), Rlp::List(vec![Rlp::List(vec![])]), Rlp::List(vec![Rlp::List(vec![]), Rlp::List(vec![Rlp::List(vec![])])])]).encode(), hex::decode("c7c0c1c0c3c0c1c0").unwrap());
    let lorem = b"Lorem ipsum dolor sit amet, consectetur adipisicing elit".to_vec();
    let encoded = Rlp::Bytes(lorem.clone()).encode();
    assert_eq!(&encoded[..2], &[0xb8, 0x38]);
    assert_eq!(&encoded[2..], &lorem[..]);
}

#[test]
fn checksums_and_selectors() {
    for address in ["0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359", "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB", "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"] {
        assert_eq!(Address::parse(address).unwrap().to_checksum(), address);
    }
    assert_eq!(c::selector("approve(address,uint256)"), "0x095ea7b3");
    assert_eq!(c::install_selector(), "0x853051bd");
    assert_eq!(c::revoke_selector(c::GrantKind::Policy), "0x4f2c9f0c");
}
