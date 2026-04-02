use anyhow::{bail, Context, Result};

use crate::rpc::{Filter, RpcClient};
use crate::types::{MemberInfo, NonceAccountInfo, NonceFinding, RiskLevel, SignerInfo};

/// System Program ID — owner of all nonce accounts.
const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";

/// Nonce account data size in bytes.
const NONCE_ACCOUNT_SIZE: u64 = 80;

/// Authority field offset in nonce account data.
const AUTHORITY_OFFSET: u64 = 8;

/// Find all initialized durable nonce accounts where `authority` is the authority.
pub async fn find_nonce_accounts(
    rpc: &RpcClient,
    authority: &str,
) -> Result<Vec<NonceAccountInfo>> {
    let filters = vec![
        Filter::DataSize(NONCE_ACCOUNT_SIZE),
        Filter::Memcmp {
            offset: AUTHORITY_OFFSET,
            bytes: authority.to_string(),
        },
    ];

    let accounts = rpc
        .get_program_accounts(SYSTEM_PROGRAM, filters)
        .await
        .context("Failed to query nonce accounts via getProgramAccounts")?;

    let mut nonces = Vec::new();
    for (pubkey, data) in accounts {
        match decode_nonce_account(&data, &pubkey) {
            Ok(info) => {
                // Only include initialized nonce accounts (state == 1)
                if info.state == 1 {
                    nonces.push(info);
                }
            }
            Err(e) => {
                eprintln!("Warning: failed to decode nonce account {}: {}", pubkey, e);
            }
        }
    }

    Ok(nonces)
}

/// Decode a 80-byte nonce account.
///
/// Layout:
///   [0..4]   version (u32 LE) — 0 = Current
///   [4..8]   state (u32 LE) — 0 = Uninitialized, 1 = Initialized
///   [8..40]  authority (Pubkey, 32 bytes)
///   [40..72] nonce_value (Hash, 32 bytes)
///   [72..80] lamports_per_signature (u64 LE)
pub fn decode_nonce_account(data: &[u8], address: &str) -> Result<NonceAccountInfo> {
    if data.len() < 80 {
        bail!(
            "Nonce account data too short: {} bytes (expected 80)",
            data.len()
        );
    }

    let version = u32::from_le_bytes(data[0..4].try_into().unwrap());
    let state = u32::from_le_bytes(data[4..8].try_into().unwrap());
    let authority = bs58::encode(&data[8..40]).into_string();
    let nonce_value = bs58::encode(&data[40..72]).into_string();
    let lamports_per_signature = u64::from_le_bytes(data[72..80].try_into().unwrap());

    Ok(NonceAccountInfo {
        address: address.to_string(),
        version,
        state,
        authority,
        nonce_value,
        lamports_per_signature,
    })
}

/// Determine who created a nonce account by finding its earliest transaction.
/// Returns the fee payer (first signer) of the creation transaction.
async fn determine_nonce_creator(
    rpc: &RpcClient,
    nonce_address: &str,
) -> Result<Option<String>> {
    // Get the oldest signature for this nonce account
    let sigs = rpc.get_signatures_for_address(nonce_address, 1).await?;

    let sig = match sigs.last() {
        Some(s) => &s.signature,
        None => return Ok(None),
    };

    let tx = rpc.get_transaction(sig).await?;

    // The fee payer is the first account key in the transaction
    let fee_payer = tx["transaction"]["message"]["accountKeys"]
        .as_array()
        .and_then(|keys| keys.first())
        .and_then(|k| {
            // jsonParsed format: accountKeys can be objects with "pubkey" field or plain strings
            k.as_str()
                .map(|s| s.to_string())
                .or_else(|| k["pubkey"].as_str().map(|s| s.to_string()))
        });

    Ok(fee_payer)
}

/// Scan all multisig signers for nonce accounts. Returns (signer_infos, nonce_findings).
pub async fn scan_all_signers(
    rpc: &RpcClient,
    members: &[MemberInfo],
) -> Result<(Vec<SignerInfo>, Vec<NonceFinding>)> {
    let member_pubkeys: Vec<&str> = members.iter().map(|m| m.pubkey.as_str()).collect();

    let mut signer_infos = Vec::new();
    let mut nonce_findings = Vec::new();

    for member in members {
        let nonces = find_nonce_accounts(rpc, &member.pubkey).await?;
        let count = nonces.len() as u32;

        let mut is_suspicious = false;

        for nonce in &nonces {
            // Determine who created this nonce account
            let created_by = determine_nonce_creator(rpc, &nonce.address).await?;

            // Assess risk based on creator
            let (risk, reason) = match &created_by {
                Some(creator) if member_pubkeys.contains(&creator.as_str()) => (
                    RiskLevel::High,
                    format!(
                        "Durable nonce account found with authority {}. Created by known signer {}.",
                        &member.pubkey[..12],
                        &creator[..12.min(creator.len())]
                    ),
                ),
                Some(creator) => {
                    is_suspicious = true;
                    (
                        RiskLevel::Critical,
                        format!(
                            "Durable nonce account created by UNKNOWN wallet {} for signer {}. \
                             This may indicate an attacker staging a pre-signed transaction attack.",
                            creator,
                            &member.pubkey[..12]
                        ),
                    )
                }
                None => (
                    RiskLevel::High,
                    format!(
                        "Durable nonce account found for signer {} but creation history unavailable.",
                        &member.pubkey[..12]
                    ),
                ),
            };

            nonce_findings.push(NonceFinding {
                nonce_account: nonce.address.clone(),
                authority: nonce.authority.clone(),
                created_by,
                creation_slot: None, // Could be populated from the tx
                nonce_value: nonce.nonce_value.clone(),
                risk,
                reason,
            });
        }

        signer_infos.push(SignerInfo {
            pubkey: member.pubkey.clone(),
            nonce_accounts_found: count,
            is_suspicious,
        });
    }

    Ok((signer_infos, nonce_findings))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_nonce_account_valid() {
        let mut data = vec![0u8; 80];
        // version = 0 (Current)
        data[0..4].copy_from_slice(&0u32.to_le_bytes());
        // state = 1 (Initialized)
        data[4..8].copy_from_slice(&1u32.to_le_bytes());
        // authority (32 bytes of 0xAA)
        data[8..40].copy_from_slice(&[0xAA; 32]);
        // nonce_value (32 bytes of 0xBB)
        data[40..72].copy_from_slice(&[0xBB; 32]);
        // lamports_per_signature = 5000
        data[72..80].copy_from_slice(&5000u64.to_le_bytes());

        let result = decode_nonce_account(&data, "TestNonce").unwrap();
        assert_eq!(result.version, 0);
        assert_eq!(result.state, 1);
        assert_eq!(result.lamports_per_signature, 5000);
        assert_eq!(result.address, "TestNonce");
        // authority should be base58 of [0xAA; 32]
        assert_eq!(result.authority, bs58::encode([0xAA; 32]).into_string());
    }

    #[test]
    fn test_decode_nonce_account_too_short() {
        let data = vec![0u8; 50];
        assert!(decode_nonce_account(&data, "Short").is_err());
    }

    #[test]
    fn test_decode_nonce_uninitialized() {
        let mut data = vec![0u8; 80];
        // state = 0 (Uninitialized)
        data[4..8].copy_from_slice(&0u32.to_le_bytes());

        let result = decode_nonce_account(&data, "Uninit").unwrap();
        assert_eq!(result.state, 0);
        // This account would be filtered out by find_nonce_accounts
    }
}
