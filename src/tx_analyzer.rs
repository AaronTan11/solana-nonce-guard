use anyhow::{Context, Result};
use serde_json::Value;

use crate::rpc::RpcClient;
use crate::types::{RiskLevel, TxFinding};

/// Nonce-related instruction types in jsonParsed format.
const ADVANCE_NONCE: &str = "advanceNonceAccount";
const INITIALIZE_NONCE: &str = "initializeNonceAccount";
const AUTHORIZE_NONCE: &str = "authorizeNonceAccount";
const WITHDRAW_NONCE: &str = "withdrawNonceAccount";

/// Scan transaction history for durable nonce usage.
/// Returns findings for any transactions using durable nonce instructions.
pub async fn scan_tx_history(
    rpc: &RpcClient,
    address: &str,
    limit: usize,
) -> Result<Vec<TxFinding>> {
    let sigs = rpc
        .get_signatures_for_address(address, limit)
        .await
        .context("Failed to fetch transaction signatures")?;

    let mut findings = Vec::new();

    for sig_info in &sigs {
        // Skip failed transactions
        if sig_info.err.is_some() {
            continue;
        }

        let tx = match rpc.get_transaction(&sig_info.signature).await {
            Ok(tx) => tx,
            Err(e) => {
                eprintln!(
                    "Warning: failed to fetch tx {}: {}",
                    &sig_info.signature[..12],
                    e
                );
                continue;
            }
        };

        let mut tx_findings = analyze_transaction(&tx, &sig_info.signature, sig_info.slot);
        findings.append(&mut tx_findings);

        // Rate limiting
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    // Detect rapid execution patterns and append supplementary findings
    let rapid_findings = detect_rapid_execution(&findings);
    findings.extend(rapid_findings);

    Ok(findings)
}

/// Analyze a single transaction for nonce-related instructions.
fn analyze_transaction(tx: &Value, signature: &str, slot: u64) -> Vec<TxFinding> {
    let mut findings = Vec::new();

    let instructions = match tx["transaction"]["message"]["instructions"].as_array() {
        Some(ixs) => ixs,
        None => return findings,
    };

    // Check if ix[0] is AdvanceNonceAccount — this means the entire tx is a durable nonce tx
    if let Some(first_ix) = instructions.first() {
        if is_nonce_instruction(first_ix, ADVANCE_NONCE) {
            let nonce_account = extract_nonce_account(first_ix).unwrap_or_default();
            let authority = extract_nonce_authority(first_ix).unwrap_or_default();
            let payload = summarize_payload(instructions);

            findings.push(TxFinding {
                signature: signature.to_string(),
                slot,
                nonce_account_used: nonce_account,
                nonce_authority: authority,
                payload_summary: payload,
                risk: RiskLevel::High,
                reason: "Transaction uses durable nonce (AdvanceNonceAccount as first instruction). \
                         This transaction was pre-signed and could have been held indefinitely before execution."
                    .to_string(),
            });
        }
    }

    // Also scan all instructions for other nonce operations (not just ix[0])
    for (i, ix) in instructions.iter().enumerate() {
        if i == 0 && is_nonce_instruction(ix, ADVANCE_NONCE) {
            continue; // Already handled above
        }

        if is_nonce_instruction(ix, INITIALIZE_NONCE) {
            let nonce_account = extract_nonce_account(ix).unwrap_or_default();
            let authority = extract_nonce_authority(ix).unwrap_or_default();
            findings.push(TxFinding {
                signature: signature.to_string(),
                slot,
                nonce_account_used: nonce_account,
                nonce_authority: authority,
                payload_summary: "InitializeNonceAccount".to_string(),
                risk: RiskLevel::Medium,
                reason: "New durable nonce account initialized. Monitor this account for future use \
                         in pre-signed transactions."
                    .to_string(),
            });
        }

        if is_nonce_instruction(ix, AUTHORIZE_NONCE) {
            let nonce_account = extract_nonce_account(ix).unwrap_or_default();
            let new_authority = ix["parsed"]["info"]["newAuthorized"]
                .as_str()
                .unwrap_or("unknown")
                .to_string();
            findings.push(TxFinding {
                signature: signature.to_string(),
                slot,
                nonce_account_used: nonce_account,
                nonce_authority: new_authority,
                payload_summary: "AuthorizeNonceAccount — authority changed".to_string(),
                risk: RiskLevel::High,
                reason: "Nonce account authority was changed. If unexpected, this could indicate \
                         an attacker gaining control of a durable nonce."
                    .to_string(),
            });
        }

        if is_nonce_instruction(ix, WITHDRAW_NONCE) {
            let nonce_account = extract_nonce_account(ix).unwrap_or_default();
            let authority = extract_nonce_authority(ix).unwrap_or_default();
            findings.push(TxFinding {
                signature: signature.to_string(),
                slot,
                nonce_account_used: nonce_account,
                nonce_authority: authority,
                payload_summary: "WithdrawNonceAccount".to_string(),
                risk: RiskLevel::Low,
                reason: "Nonce account withdrawn (closed). This is typically a cleanup action."
                    .to_string(),
            });
        }
    }

    findings
}

/// Detect rapid sequential durable nonce transaction execution.
/// Returns supplementary findings describing the pattern.
fn detect_rapid_execution(findings: &[TxFinding]) -> Vec<TxFinding> {
    // Filter to only AdvanceNonce findings (the durable nonce txs)
    let mut nonce_txs: Vec<&TxFinding> = findings
        .iter()
        .filter(|f| f.reason.contains("AdvanceNonceAccount as first instruction"))
        .collect();

    if nonce_txs.len() < 2 {
        return Vec::new();
    }

    // Sort by slot ascending
    nonce_txs.sort_by_key(|f| f.slot);

    let mut rapid_findings = Vec::new();
    let mut cluster_start = 0;

    for i in 1..nonce_txs.len() {
        let gap = nonce_txs[i].slot.saturating_sub(nonce_txs[i - 1].slot);

        if gap >= 10 {
            // Check if the previous cluster had 2+ txs
            if i - cluster_start >= 2 {
                rapid_findings.push(make_rapid_finding(
                    &nonce_txs[cluster_start..i],
                ));
            }
            cluster_start = i;
        }
    }

    // Check final cluster
    if nonce_txs.len() - cluster_start >= 2 {
        rapid_findings.push(make_rapid_finding(
            &nonce_txs[cluster_start..],
        ));
    }

    rapid_findings
}

fn make_rapid_finding(cluster: &[&TxFinding]) -> TxFinding {
    let first_slot = cluster.first().unwrap().slot;
    let last_slot = cluster.last().unwrap().slot;
    let sigs: Vec<&str> = cluster.iter().map(|f| f.signature.as_str()).collect();

    TxFinding {
        signature: sigs.join(", "),
        slot: first_slot,
        nonce_account_used: "multiple".to_string(),
        nonce_authority: "multiple".to_string(),
        payload_summary: format!(
            "{} durable nonce transactions executed within slots {}-{}",
            cluster.len(),
            first_slot,
            last_slot
        ),
        risk: RiskLevel::Critical,
        reason: format!(
            "RAPID EXECUTION: {} durable nonce transactions fired within {} slots. \
             This pattern is consistent with a coordinated attack execution phase.",
            cluster.len(),
            last_slot - first_slot
        ),
    }
}

/// Check if an instruction is a specific nonce instruction type.
fn is_nonce_instruction(ix: &Value, instruction_type: &str) -> bool {
    // jsonParsed format for system program instructions
    let program = ix["program"].as_str().unwrap_or_default();
    let parsed_type = ix["parsed"]["type"].as_str().unwrap_or_default();

    // Also check programId for unparsed instructions
    let program_id = ix["programId"].as_str().unwrap_or_default();

    (program == "system" || program_id == "11111111111111111111111111111111")
        && parsed_type == instruction_type
}

/// Extract the nonce account pubkey from a parsed nonce instruction.
fn extract_nonce_account(ix: &Value) -> Option<String> {
    ix["parsed"]["info"]["nonceAccount"]
        .as_str()
        .map(|s| s.to_string())
}

/// Extract the nonce authority pubkey from a parsed nonce instruction.
fn extract_nonce_authority(ix: &Value) -> Option<String> {
    ix["parsed"]["info"]["nonceAuthority"]
        .as_str()
        .map(|s| s.to_string())
}

/// Summarize the payload instructions (everything after ix[0] AdvanceNonceAccount).
fn summarize_payload(instructions: &[Value]) -> String {
    if instructions.len() <= 1 {
        return "No payload instructions".to_string();
    }

    let summaries: Vec<String> = instructions[1..]
        .iter()
        .map(|ix| {
            let program = ix["program"]
                .as_str()
                .or_else(|| ix["programId"].as_str())
                .unwrap_or("unknown");
            let ix_type = ix["parsed"]["type"].as_str().unwrap_or("unknown");
            if ix_type != "unknown" {
                format!("{}:{}", program, ix_type)
            } else {
                program.to_string()
            }
        })
        .collect();

    summaries.join(" → ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_is_nonce_instruction() {
        let ix = json!({
            "program": "system",
            "parsed": {
                "type": "advanceNonceAccount",
                "info": {
                    "nonceAccount": "NonceAddr123",
                    "nonceAuthority": "AuthAddr456"
                }
            }
        });

        assert!(is_nonce_instruction(&ix, ADVANCE_NONCE));
        assert!(!is_nonce_instruction(&ix, INITIALIZE_NONCE));
    }

    #[test]
    fn test_extract_nonce_fields() {
        let ix = json!({
            "program": "system",
            "parsed": {
                "type": "advanceNonceAccount",
                "info": {
                    "nonceAccount": "NonceAddr123",
                    "nonceAuthority": "AuthAddr456"
                }
            }
        });

        assert_eq!(
            extract_nonce_account(&ix),
            Some("NonceAddr123".to_string())
        );
        assert_eq!(
            extract_nonce_authority(&ix),
            Some("AuthAddr456".to_string())
        );
    }

    #[test]
    fn test_analyze_transaction_with_nonce() {
        let tx = json!({
            "transaction": {
                "message": {
                    "instructions": [
                        {
                            "program": "system",
                            "parsed": {
                                "type": "advanceNonceAccount",
                                "info": {
                                    "nonceAccount": "Nonce1",
                                    "nonceAuthority": "Auth1"
                                }
                            }
                        },
                        {
                            "program": "spl-token",
                            "parsed": {
                                "type": "transfer",
                                "info": {}
                            }
                        }
                    ]
                }
            }
        });

        let findings = analyze_transaction(&tx, "TxSig123", 12345);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].nonce_account_used, "Nonce1");
        assert_eq!(findings[0].risk, RiskLevel::High);
        assert!(findings[0].payload_summary.contains("spl-token"));
    }

    #[test]
    fn test_analyze_transaction_normal() {
        let tx = json!({
            "transaction": {
                "message": {
                    "instructions": [
                        {
                            "program": "spl-token",
                            "parsed": {
                                "type": "transfer",
                                "info": {}
                            }
                        }
                    ]
                }
            }
        });

        let findings = analyze_transaction(&tx, "TxSig456", 12345);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_detect_rapid_execution() {
        let make_finding = |slot: u64| TxFinding {
            signature: format!("sig_{}", slot),
            slot,
            nonce_account_used: "Nonce1".to_string(),
            nonce_authority: "Auth1".to_string(),
            payload_summary: "test".to_string(),
            risk: RiskLevel::High,
            reason: "Transaction uses durable nonce (AdvanceNonceAccount as first instruction)."
                .to_string(),
        };

        // 3 txs within 5 slots — should trigger
        let findings = vec![
            make_finding(100),
            make_finding(103),
            make_finding(105),
            make_finding(200), // gap > 10, separate
        ];

        let rapid = detect_rapid_execution(&findings);
        assert_eq!(rapid.len(), 1);
        assert_eq!(rapid[0].risk, RiskLevel::Critical);
        assert!(rapid[0].reason.contains("3 durable nonce transactions"));
    }

    #[test]
    fn test_detect_rapid_execution_no_cluster() {
        let make_finding = |slot: u64| TxFinding {
            signature: format!("sig_{}", slot),
            slot,
            nonce_account_used: "Nonce1".to_string(),
            nonce_authority: "Auth1".to_string(),
            payload_summary: "test".to_string(),
            risk: RiskLevel::High,
            reason: "Transaction uses durable nonce (AdvanceNonceAccount as first instruction)."
                .to_string(),
        };

        // All txs >10 slots apart
        let findings = vec![make_finding(100), make_finding(200), make_finding(300)];
        let rapid = detect_rapid_execution(&findings);
        assert!(rapid.is_empty());
    }

    #[test]
    fn test_summarize_payload() {
        let instructions = vec![
            json!({ "program": "system", "parsed": { "type": "advanceNonceAccount" } }),
            json!({ "program": "spl-token", "parsed": { "type": "transfer" } }),
            json!({ "programId": "CustomProgram123" }),
        ];

        let summary = summarize_payload(&instructions);
        assert_eq!(summary, "spl-token:transfer → CustomProgram123");
    }
}
