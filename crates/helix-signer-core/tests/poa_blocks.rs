//! Anubis headers carry a 280-byte proof-of-authority ``extraData``. A client
//! that enforces Ethereum's 32-byte limit (web3.py without its PoA middleware)
//! fails on every real block; the Account Service did. The signer reads the
//! latest block for its timestamp and base fee: it must accept real headers.

mod common;

use std::sync::Arc;

use helix_signer_core::chain;
use helix_signer_core::net::Rpc;
use helix_signer_core::U256;

#[test]
fn reads_time_and_fees_from_a_real_anubis_header() {
    let fake = common::Fake::new();
    let block = common::anubis_block(19_222_581, 0x6af9_d54f);
    let extra = block["extraData"].as_str().unwrap();
    assert_eq!((extra.len() - 2) / 2, 280);
    fake.state.lock().unwrap().block = 19_222_581;
    let rpc = Rpc::new("https://rpc.example/rpc", Arc::new(fake.clone())).unwrap();
    let chain_time = chain::check_chain(&rpc, &common::constants()).unwrap();
    assert!(chain_time.abs_diff(common::now()) <= 5);
    let (max_fee, tip) = chain::fees(&rpc).unwrap();
    // baseFeePerGas 0, gasPrice 12 gwei: tip = gasPrice, max fee = tip.
    assert_eq!(tip, U256::from(12_000_000_000u64));
    assert_eq!(max_fee, tip);
}
