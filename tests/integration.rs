//! Live mainnet integration tests.
//!
//! These tests hit real Solana mainnet RPC and are gated behind `#[ignore]`.
//! Run with:
//!   RPC_URL=https://your-rpc.helius.xyz cargo test -- --ignored
//!
//! Default RPC (public mainnet) will be used if RPC_URL is not set,
//! but may be rate-limited.

use solana_nonce_guard::multisig;
use solana_nonce_guard::rpc::RpcClient;
use solana_nonce_guard::scanner;
use solana_nonce_guard::tx_analyzer;

fn get_rpc_url() -> String {
    std::env::var("RPC_URL").unwrap_or_else(|_| {
        "https://api.mainnet-beta.solana.com".to_string()
    })
}

/// Fetch and decode the real Drift Security Council Squads v4 multisig.
/// Verifies the live on-chain state matches our fixture data.
#[tokio::test]
#[ignore]
async fn test_fetch_and_decode_real_drift_multisig() {
    let client = RpcClient::new(&get_rpc_url());

    let ms = multisig::fetch_and_decode_multisig(
        &client,
        "2LW6PSEjp81xSEttWwXDB6Etb1eKdhYPbFEojYbyhx88",
    )
    .await
    .expect("Should decode real Drift multisig");

    assert_eq!(ms.program, "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf");
    assert_eq!(ms.members.len(), 5, "Drift has 5 Security Council members");
    // Threshold may have been updated post-exploit, so just verify it's reasonable
    assert!(
        ms.threshold >= 1 && ms.threshold <= 5,
        "Threshold should be between 1 and 5, got {}",
        ms.threshold
    );
}

/// Find nonce accounts for a known Drift signer.
/// The nonce account from the exploit should still be on-chain.
///
/// NOTE: Requires an RPC that supports getProgramAccounts with memcmp filters
/// on the System Program. Most providers (public RPC, Helius) block this.
/// Triton, QuickNode, or self-hosted nodes typically support it.
#[tokio::test]
#[ignore]
async fn test_find_nonce_accounts_for_drift_signer() {
    let client = RpcClient::new(&get_rpc_url());

    let nonces = match scanner::find_nonce_accounts(
        &client,
        "39JyWrdbVdRqjzw9yyEjxNtTbTKcTPLdtdCgbz7C7Aq8",
    )
    .await
    {
        Ok(n) => n,
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("getProgramAccounts") || msg.contains("Too many accounts") {
                eprintln!(
                    "SKIPPED: RPC does not support getProgramAccounts with memcmp on System Program.\n\
                     Error: {}\n\
                     Use an RPC that supports this (Triton, QuickNode, self-hosted).",
                    msg
                );
                return;
            }
            panic!("Unexpected error: {}", e);
        }
    };

    let exploit_nonce = nonces.iter().find(|n| {
        n.address == "7s7s6saC5LHZoLyBXLM3pCjpWaA7meyQdP8NiH9ktAeC"
    });

    assert!(
        exploit_nonce.is_some(),
        "Exploit nonce account should still be on-chain. Found {} nonce accounts: {:?}",
        nonces.len(),
        nonces.iter().map(|n| &n.address).collect::<Vec<_>>()
    );
}

/// Scan transaction history for the Drift multisig.
/// The exploit transactions should be in the history and correctly flagged.
#[tokio::test]
#[ignore]
async fn test_scan_tx_history_real() {
    let client = RpcClient::new(&get_rpc_url());

    let findings = tx_analyzer::scan_tx_history(
        &client,
        "2LW6PSEjp81xSEttWwXDB6Etb1eKdhYPbFEojYbyhx88",
        20, // Limit to recent txs to avoid rate limiting
    )
    .await
    .expect("Should scan tx history without error");

    // We can't guarantee the exploit txs are in the most recent 20,
    // but the scan should complete without errors
    eprintln!(
        "Found {} nonce-related findings in last 20 txs",
        findings.len()
    );

    // Verify finding structure if any exist
    for f in &findings {
        assert!(!f.signature.is_empty());
        assert!(f.slot > 0);
    }
}

/// Run the full scan pipeline against the Drift multisig.
/// This is the ultimate end-to-end test.
///
/// NOTE: Requires an RPC that supports getProgramAccounts with memcmp filters
/// on the System Program. Most providers (public RPC, Helius) block this.
#[tokio::test]
#[ignore]
async fn test_full_scan_pipeline_real() {
    let client = RpcClient::new(&get_rpc_url());

    // Step 1: Decode multisig
    let ms = multisig::fetch_and_decode_multisig(
        &client,
        "2LW6PSEjp81xSEttWwXDB6Etb1eKdhYPbFEojYbyhx88",
    )
    .await
    .expect("Should decode multisig");

    eprintln!(
        "Multisig: threshold={}/{}, time_lock={}",
        ms.threshold,
        ms.members.len(),
        ms.time_lock
    );

    // Step 2: Scan nonce accounts for first member only (to limit RPC calls)
    let first_member = &ms.members[0..1];
    let (signer_infos, nonce_findings) = match scanner::scan_all_signers(&client, first_member)
        .await
    {
        Ok(result) => result,
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("getProgramAccounts") || msg.contains("Too many accounts") {
                eprintln!(
                    "SKIPPED: RPC does not support getProgramAccounts with memcmp on System Program.\n\
                     Error: {}",
                    msg
                );
                return;
            }
            panic!("Unexpected error: {}", e);
        }
    };

    eprintln!(
        "Signer {}: {} nonce accounts, suspicious={}",
        &signer_infos[0].pubkey[..12],
        signer_infos[0].nonce_accounts_found,
        signer_infos[0].is_suspicious
    );

    // Step 3: Scan tx history (small limit)
    let tx_findings = tx_analyzer::scan_tx_history(
        &client,
        "2LW6PSEjp81xSEttWwXDB6Etb1eKdhYPbFEojYbyhx88",
        5,
    )
    .await
    .expect("Should scan tx history");

    eprintln!("Found {} tx findings", tx_findings.len());

    // Step 4: Verify report can be generated
    let report = solana_nonce_guard::types::AuditReport {
        multisig_address: ms.address.clone(),
        multisig_program: ms.program.clone(),
        threshold: ms.threshold,
        signers: signer_infos,
        nonce_findings,
        tx_findings,
        risk_level: solana_nonce_guard::types::RiskLevel::Info, // placeholder
        recommendations: vec![],
        timestamp: chrono::Utc::now().to_rfc3339(),
    };

    let json = serde_json::to_string_pretty(&report).expect("Should serialize report");
    assert!(!json.is_empty());
    eprintln!("Report generated: {} bytes", json.len());
}
