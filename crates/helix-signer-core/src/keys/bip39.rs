//! BIP-39 mnemonics and BIP-32/44 derivation, as eth-account implements them
//! (``eth_account.hdaccount``): language detection over the same nine word
//! lists, unique-prefix expansion, checksum validation, NFKD normalization and
//! PBKDF2-HMAC-SHA512 with 2048 rounds.

use hmac::{Hmac, Mac};
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{Scalar, SecretKey, U256 as KU256};
use sha2::{Digest, Sha256, Sha512};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

type HmacSha512 = Hmac<Sha512>;

/// Languages eth-account supports, in its sorted order.
pub const LANGUAGES: [(&str, &str); 9] = [
    ("chinese_simplified", include_str!("../../wordlists/chinese_simplified.txt")),
    ("chinese_traditional", include_str!("../../wordlists/chinese_traditional.txt")),
    ("czech", include_str!("../../wordlists/czech.txt")),
    ("english", include_str!("../../wordlists/english.txt")),
    ("french", include_str!("../../wordlists/french.txt")),
    ("italian", include_str!("../../wordlists/italian.txt")),
    ("japanese", include_str!("../../wordlists/japanese.txt")),
    ("korean", include_str!("../../wordlists/korean.txt")),
    ("spanish", include_str!("../../wordlists/spanish.txt")),
];

const VALID_WORD_COUNTS: [usize; 5] = [12, 15, 18, 21, 24];

/// The 2048 words of a language.
pub fn wordlist(language: &str) -> Vec<&'static str> {
    LANGUAGES
        .iter()
        .find(|(name, _)| *name == language)
        .map(|(_, text)| text.lines().map(str::trim).collect())
        .unwrap_or_default()
}

fn nfkd(text: &str) -> String {
    text.nfkd().collect()
}

/// ``Mnemonic.detect_language``: the one language containing every word.
pub fn detect_language(phrase: &str) -> Option<&'static str> {
    let normalized = nfkd(phrase);
    let words: std::collections::HashSet<&str> = normalized.split(' ').collect();
    let matching: Vec<&'static str> = LANGUAGES
        .iter()
        .filter(|(name, _)| {
            let list = wordlist(name);
            words.iter().all(|word| list.contains(word))
        })
        .map(|(name, _)| *name)
        .collect();
    match matching.as_slice() {
        [one] => Some(one),
        [first, second] if first.contains("chinese") && second.contains("chinese") => Some("chinese_simplified"),
        _ => None,
    }
}

/// ``Mnemonic.expand``: replace unique prefixes by their word.
pub fn expand(phrase: &str, language: &str) -> String {
    let list = wordlist(language);
    phrase
        .split(' ')
        .map(|prefix| {
            if list.contains(&prefix) {
                return prefix.to_string();
            }
            let matches: Vec<&&str> = list.iter().filter(|word| word.starts_with(prefix)).collect();
            if matches.len() == 1 {
                matches[0].to_string()
            } else {
                prefix.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// ``Mnemonic.is_mnemonic_valid``.
pub fn is_valid(phrase: &str, language: &str) -> bool {
    let normalized = nfkd(phrase);
    let words: Vec<&str> = normalized.split(' ').collect();
    if !VALID_WORD_COUNTS.contains(&words.len()) {
        return false;
    }
    let list = wordlist(language);
    let mut bits: Vec<bool> = Vec::with_capacity(words.len() * 11);
    for word in &words {
        let Some(index) = list.iter().position(|item| item == word) else { return false };
        for bit in (0..11).rev() {
            bits.push((index >> bit) & 1 == 1);
        }
    }
    let entropy_bytes = 4 * words.len() / 3;
    let entropy: Vec<u8> = bits[..entropy_bytes * 8]
        .chunks(8)
        .map(|chunk| chunk.iter().fold(0u8, |acc, bit| (acc << 1) | *bit as u8))
        .collect();
    let checksum = Sha256::digest(&entropy);
    let stored = &bits[entropy_bytes * 8..];
    stored.iter().enumerate().all(|(index, bit)| ((checksum[index / 8] >> (7 - index % 8)) & 1 == 1) == *bit)
}

/// ``Mnemonic.to_seed``.
pub fn to_seed(phrase: &str, passphrase: &str) -> Zeroizing<[u8; 64]> {
    let password = Zeroizing::new(nfkd(phrase));
    let salt = Zeroizing::new(format!("mnemonic{}", nfkd(passphrase)));
    let mut seed = Zeroizing::new([0u8; 64]);
    pbkdf2::pbkdf2_hmac::<Sha512>(password.as_bytes(), salt.as_bytes(), 2048, seed.as_mut());
    seed
}

/// ``seed_from_mnemonic``: detect, expand, validate and stretch.
pub fn seed_from_mnemonic(words: &str, passphrase: &str) -> Option<Zeroizing<[u8; 64]>> {
    let language = detect_language(words)?;
    let expanded = Zeroizing::new(expand(words, language));
    if !is_valid(&expanded, language) {
        return None;
    }
    Some(to_seed(&expanded, passphrase))
}

fn hmac512(key: &[u8], data: &[u8]) -> Zeroizing<[u8; 64]> {
    let mut mac = HmacSha512::new_from_slice(key).expect("any key length");
    mac.update(data);
    let mut out = Zeroizing::new([0u8; 64]);
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

const ORDER: KU256 = KU256::from_be_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");

fn derive_child(key: &[u8; 32], chain: &[u8; 32], index: u32) -> Option<(Zeroizing<[u8; 32]>, [u8; 32])> {
    let mut index = index;
    loop {
        let mut data = Zeroizing::new(Vec::with_capacity(37));
        if index >= 0x8000_0000 {
            data.push(0);
            data.extend_from_slice(key);
        } else {
            let secret = SecretKey::from_slice(key).ok()?;
            data.extend_from_slice(secret.public_key().to_encoded_point(true).as_bytes());
        }
        data.extend_from_slice(&index.to_be_bytes());
        let child = hmac512(chain, &data);
        let left = KU256::from_be_slice(&child[..32]);
        if left >= ORDER {
            index = index.wrapping_add(1);
            continue;
        }
        let sum = <Scalar as Reduce<KU256>>::reduce(left) + <Scalar as Reduce<KU256>>::reduce(KU256::from_be_slice(key));
        if bool::from(sum.is_zero()) {
            index = index.wrapping_add(1);
            continue;
        }
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&sum.to_bytes());
        let mut next_chain = [0u8; 32];
        next_chain.copy_from_slice(&child[32..]);
        return Some((out, next_chain));
    }
}

/// BIP-32 private key of ``m/44'/60'/0'/0/<index>`` (``HDPath.derive``).
pub fn derive_ethereum(seed: &[u8; 64], index: u32) -> Option<Zeroizing<[u8; 32]>> {
    let master = hmac512(b"Bitcoin seed", seed);
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&master[..32]);
    let mut chain = [0u8; 32];
    chain.copy_from_slice(&master[32..]);
    for node in [44 | 0x8000_0000, 60 | 0x8000_0000, 0x8000_0000, 0, index] {
        let (next, next_chain) = derive_child(&key, &chain, node)?;
        key = next;
        chain = next_chain;
    }
    Some(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_are_complete() {
        for (name, _) in LANGUAGES {
            assert_eq!(wordlist(name).len(), 2048, "{name}");
        }
    }

    #[test]
    fn detection() {
        assert_eq!(detect_language("test test test test test test test test test test test junk"), Some("english"));
        assert_eq!(detect_language("abandon"), None); // also a French word
        assert_eq!(detect_language("的 的"), Some("chinese_simplified"));
        assert_eq!(detect_language("nosuchword"), None);
    }
}
