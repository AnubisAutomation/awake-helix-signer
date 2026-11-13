//! Ethereum V3 keystores, as eth-keyfile reads and writes them: scrypt or
//! PBKDF2-HMAC, AES-128-CTR, MAC = keccak(derived[16:32] || ciphertext).

use aes::cipher::{KeyIvInit, StreamCipher};
use serde_json::{json, Map, Value};
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

use crate::address::keccak;

type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;

/// Key derivation function of a new keystore.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kdf {
    /// scrypt, n = 262144, r = 8, p = 1 (eth-keyfile's default).
    Scrypt,
    /// PBKDF2-HMAC-SHA256, 1,000,000 iterations by default.
    Pbkdf2,
}

impl Kdf {
    /// eth-keyfile's default work factor.
    pub fn default_work_factor(&self) -> u32 {
        match self {
            Kdf::Scrypt => 262_144,
            Kdf::Pbkdf2 => 1_000_000,
        }
    }
}

fn lower_keys(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(map.iter().map(|(key, item)| (key.to_lowercase(), lower_keys(item))).collect()),
        other => other.clone(),
    }
}

fn decode_hex(value: &Value) -> Option<Vec<u8>> {
    let text = value.as_str()?;
    let text = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")).unwrap_or(text);
    hex::decode(text).ok()
}

fn small_int(value: &Value) -> Option<u64> {
    match value {
        Value::Number(number) => number.as_u64().or_else(|| number.as_f64().filter(|f| f.fract() == 0.0 && *f >= 0.0).map(|f| f as u64)),
        Value::Bool(flag) => Some(*flag as u64),
        _ => None,
    }
}

fn pbkdf2_sha256(password: &[u8], salt: &[u8], rounds: u32, out: &mut [u8]) -> Option<()> {
    (rounds > 0).then(|| pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, rounds, out))
}

fn pbkdf2_sha512(password: &[u8], salt: &[u8], rounds: u32, out: &mut [u8]) -> Option<()> {
    (rounds > 0).then(|| pbkdf2::pbkdf2_hmac::<Sha512>(password, salt, rounds, out))
}

fn derive(kdf: &str, params: &Map<String, Value>, password: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let salt = decode_hex(params.get("salt")?)?;
    let length = small_int(params.get("dklen")?)? as usize;
    if length == 0 || length > 1024 {
        return None;
    }
    let mut out = Zeroizing::new(vec![0u8; length]);
    match kdf {
        "pbkdf2" => {
            let prf = params.get("prf")?.as_str()?;
            let (hmac_part, _, hash) = {
                let (left, right) = prf.split_once('-').unwrap_or((prf, ""));
                (left, '-', right)
            };
            if hmac_part != "hmac" {
                return None;
            }
            let rounds = u32::try_from(small_int(params.get("c")?)?).ok()?;
            match hash {
                "sha256" => pbkdf2_sha256(password, &salt, rounds, &mut out)?,
                "sha512" => pbkdf2_sha512(password, &salt, rounds, &mut out)?,
                _ => return None,
            }
        }
        "scrypt" => {
            let n = small_int(params.get("n")?)?;
            let r = u32::try_from(small_int(params.get("r")?)?).ok()?;
            let p = u32::try_from(small_int(params.get("p")?)?).ok()?;
            if n < 2 || !n.is_power_of_two() {
                return None;
            }
            let parameters = scrypt::Params::new(n.trailing_zeros() as u8, r, p, length).ok()?;
            scrypt::scrypt(password, &salt, &parameters, &mut out).ok()?;
        }
        _ => return None,
    }
    Some(out)
}

/// ``decode_keyfile_json`` for version 3: the raw private key, or None for a
/// wrong password or an unsupported/damaged file.
pub fn decrypt(document: &Value, password: &str) -> Option<Zeroizing<Vec<u8>>> {
    let document = lower_keys(document);
    if small_int(document.get("version")?)? != 3 || document.get("version")?.is_boolean() {
        return None;
    }
    let crypto = document.get("crypto")?.as_object()?;
    let kdf = crypto.get("kdf")?.as_str()?;
    let params = crypto.get("kdfparams")?.as_object()?;
    let derived = derive(kdf, params, password.as_bytes())?;
    if derived.len() < 32 {
        return None;
    }
    let ciphertext = decode_hex(crypto.get("ciphertext")?)?;
    let mut mac_input = derived[16..32].to_vec();
    mac_input.extend_from_slice(&ciphertext);
    let mac = keccak(&mac_input);
    let expected = decode_hex(crypto.get("mac")?)?;
    if !constant_time_eq(&mac, &expected) {
        return None;
    }
    let iv_raw = decode_hex(crypto.get("cipherparams")?.as_object()?.get("iv")?)?;
    let significant: Vec<u8> = iv_raw.iter().copied().skip_while(|byte| *byte == 0).collect();
    if significant.len() > 16 {
        return None;
    }
    let mut iv = [0u8; 16];
    iv[16 - significant.len()..].copy_from_slice(&significant);
    let mut plain = Zeroizing::new(ciphertext);
    let mut cipher = Aes128Ctr::new(derived[..16].into(), (&iv).into());
    cipher.apply_keystream(&mut plain);
    Some(plain)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter().zip(right).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
}

/// Random bytes from the operating system.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    getrandom::getrandom(&mut out).expect("operating system randomness");
    out
}

/// A random UUID version 4.
pub fn uuid4() -> String {
    let mut bytes: [u8; 16] = random_bytes();
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    crate::plan::uuid_text(&bytes)
}

/// ``create_keyfile_json`` version 3 (same fields and order as eth-keyfile).
pub fn encrypt(key: &[u8; 32], address_checksum: &str, password: &str, kdf: Kdf, work_factor: Option<u32>) -> Option<Value> {
    let work = work_factor.unwrap_or_else(|| kdf.default_work_factor());
    let salt: [u8; 16] = random_bytes();
    let mut derived = Zeroizing::new(vec![0u8; 32]);
    let params = match kdf {
        Kdf::Pbkdf2 => {
            pbkdf2_sha256(password.as_bytes(), &salt, work, &mut derived)?;
            json!({"c": work, "dklen": 32, "prf": "hmac-sha256", "salt": hex::encode(salt)})
        }
        Kdf::Scrypt => {
            if work < 2 || !work.is_power_of_two() {
                return None;
            }
            let parameters = scrypt::Params::new(work.trailing_zeros() as u8, 8, 1, 32).ok()?;
            scrypt::scrypt(password.as_bytes(), &salt, &parameters, &mut derived).ok()?;
            json!({"dklen": 32, "n": work, "r": 8, "p": 1, "salt": hex::encode(salt)})
        }
    };
    let iv: [u8; 16] = random_bytes();
    let mut ciphertext = key.to_vec();
    let mut cipher = Aes128Ctr::new(derived[..16].into(), (&iv).into());
    cipher.apply_keystream(&mut ciphertext);
    let mut mac_input = derived[16..32].to_vec();
    mac_input.extend_from_slice(&ciphertext);
    let mac = keccak(&mac_input);
    Some(json!({
        "address": address_checksum.trim_start_matches("0x"),
        "crypto": {
            "cipher": "aes-128-ctr",
            "cipherparams": {"iv": hex::encode(iv)},
            "ciphertext": hex::encode(&ciphertext),
            "kdf": match kdf { Kdf::Scrypt => "scrypt", Kdf::Pbkdf2 => "pbkdf2" },
            "kdfparams": params,
            "mac": hex::encode(mac),
        },
        "id": uuid4(),
        "version": 3,
    }))
}
