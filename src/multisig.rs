use anyhow::{anyhow, bail, Result};

use crate::rpc::RpcClient;
use crate::types::{MemberInfo, MultisigInfo};

/// Squads v4 program ID.
const SQUADS_V4_PROGRAM: &str = "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf";

/// SPL Token program ID (owns SPL multisig accounts).
const SPL_TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

/// Expected Anchor discriminator for Squads v4 Multisig: SHA256("account:Multisig")[0..8]
const SQUADS_MULTISIG_DISCRIMINATOR: [u8; 8] = [0xd2, 0x96, 0x1d, 0xba, 0xf4, 0x4b, 0x38, 0x51];

/// Fetch and decode a multisig account, auto-detecting the program type.
pub async fn fetch_and_decode_multisig(
    rpc: &RpcClient,
    address: &str,
) -> Result<MultisigInfo> {
    let (data, owner) = rpc
        .get_account_info(address)
        .await?
        .ok_or_else(|| anyhow!("Multisig account {} not found", address))?;

    match owner.as_str() {
        SQUADS_V4_PROGRAM => decode_squads_v4(&data, address),
        SPL_TOKEN_PROGRAM => decode_spl_multisig(&data, address),
        _ => Err(anyhow!(
            "Unknown multisig program: {}. Only Squads v4 and SPL Token Multisig are supported.",
            owner
        )),
    }
}

/// Decode a Squads v4 multisig account from raw bytes.
///
/// Layout (Borsh serialized):
///   [0..8]   Anchor discriminator
///   [8..40]  create_key (Pubkey)
///   [40..72] config_authority (Pubkey)
///   [72..74] threshold (u16 LE)
///   [74..78] time_lock (u32 LE)
///   [78..86] transaction_index (u64 LE)
///   [86..94] stale_transaction_index (u64 LE)
///   [94..]   rent_collector: Option<Pubkey> (Borsh: 0x00 = None, 0x01 + 32 bytes = Some)
///   [..]     bump: u8
///   [..]     members: Vec<Member> (4-byte LE length + N * 33 bytes)
fn decode_squads_v4(data: &[u8], address: &str) -> Result<MultisigInfo> {
    if data.len() < 94 {
        bail!("Squads v4 account data too short: {} bytes", data.len());
    }

    // Validate Anchor discriminator
    let discriminator: [u8; 8] = data[0..8].try_into().unwrap();
    if discriminator != SQUADS_MULTISIG_DISCRIMINATOR {
        bail!(
            "Invalid Squads v4 discriminator: expected {:?}, got {:?}",
            SQUADS_MULTISIG_DISCRIMINATOR,
            discriminator
        );
    }

    let threshold = u16::from_le_bytes(data[72..74].try_into().unwrap());
    let time_lock = u32::from_le_bytes(data[74..78].try_into().unwrap());

    // Skip transaction_index (78..86) and stale_transaction_index (86..94)
    let mut offset = 94;

    // rent_collector: Option<Pubkey>
    if offset >= data.len() {
        bail!("Data truncated at rent_collector");
    }
    match data[offset] {
        0x00 => {
            // None
            offset += 1;
        }
        0x01 => {
            // Some(Pubkey)
            offset += 1 + 32;
        }
        v => bail!("Invalid Borsh Option tag for rent_collector: {}", v),
    }

    // bump: u8
    if offset >= data.len() {
        bail!("Data truncated at bump");
    }
    offset += 1; // skip bump

    // members: Vec<Member>
    if offset + 4 > data.len() {
        bail!("Data truncated at members length");
    }
    let member_count = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
    offset += 4;

    let expected_len = member_count * 33; // 32-byte pubkey + 1-byte permissions
    if offset + expected_len > data.len() {
        bail!(
            "Data truncated at members: need {} bytes, have {}",
            expected_len,
            data.len() - offset
        );
    }

    let mut members = Vec::with_capacity(member_count);
    for _ in 0..member_count {
        let pubkey = bs58::encode(&data[offset..offset + 32]).into_string();
        let permissions = data[offset + 32];
        members.push(MemberInfo {
            pubkey,
            permissions,
        });
        offset += 33;
    }

    Ok(MultisigInfo {
        address: address.to_string(),
        program: SQUADS_V4_PROGRAM.to_string(),
        threshold,
        time_lock,
        members,
    })
}

/// Decode an SPL Token Multisig account from raw bytes.
///
/// Layout (fixed 355 bytes):
///   [0]      m (required signers, u8)
///   [1]      n (total signers, u8)
///   [2]      is_initialized (bool, u8)
///   [3..355] 11 signer slots, each 32 bytes (only first n are valid)
fn decode_spl_multisig(data: &[u8], address: &str) -> Result<MultisigInfo> {
    if data.len() < 355 {
        bail!(
            "SPL multisig account data too short: {} bytes (expected 355)",
            data.len()
        );
    }

    let m = data[0];
    let n = data[1];
    let is_initialized = data[2];

    if is_initialized == 0 {
        bail!("SPL multisig account is not initialized");
    }

    if n > 11 {
        bail!("Invalid SPL multisig: n={} exceeds maximum of 11", n);
    }

    let mut members = Vec::with_capacity(n as usize);
    for i in 0..n as usize {
        let start = 3 + i * 32;
        let pubkey = bs58::encode(&data[start..start + 32]).into_string();
        // SPL multisig has no permissions field — all signers are equal
        members.push(MemberInfo {
            pubkey,
            permissions: 0xFF, // all permissions
        });
    }

    Ok(MultisigInfo {
        address: address.to_string(),
        program: SPL_TOKEN_PROGRAM.to_string(),
        threshold: m as u16,
        time_lock: 0, // SPL multisig has no timelock
        members,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_squads_v4_minimal() {
        // Construct a minimal valid Squads v4 multisig with 1 member
        let mut data = Vec::new();

        // Discriminator
        data.extend_from_slice(&SQUADS_MULTISIG_DISCRIMINATOR);
        // create_key (32 bytes)
        data.extend_from_slice(&[1u8; 32]);
        // config_authority (32 bytes)
        data.extend_from_slice(&[0u8; 32]);
        // threshold: 2
        data.extend_from_slice(&2u16.to_le_bytes());
        // time_lock: 3600
        data.extend_from_slice(&3600u32.to_le_bytes());
        // transaction_index: 0
        data.extend_from_slice(&0u64.to_le_bytes());
        // stale_transaction_index: 0
        data.extend_from_slice(&0u64.to_le_bytes());
        // rent_collector: None
        data.push(0x00);
        // bump
        data.push(255);
        // members: 1 member
        data.extend_from_slice(&1u32.to_le_bytes());
        // member pubkey (32 bytes)
        data.extend_from_slice(&[0xAA; 32]);
        // member permissions (Voter | Proposer = 3)
        data.push(3);

        let result = decode_squads_v4(&data, "TestAddr").unwrap();
        assert_eq!(result.threshold, 2);
        assert_eq!(result.time_lock, 3600);
        assert_eq!(result.members.len(), 1);
        assert_eq!(result.members[0].permissions, 3);
    }

    #[test]
    fn test_decode_squads_v4_with_rent_collector() {
        let mut data = Vec::new();
        data.extend_from_slice(&SQUADS_MULTISIG_DISCRIMINATOR);
        data.extend_from_slice(&[1u8; 32]); // create_key
        data.extend_from_slice(&[0u8; 32]); // config_authority
        data.extend_from_slice(&1u16.to_le_bytes()); // threshold
        data.extend_from_slice(&0u32.to_le_bytes()); // time_lock
        data.extend_from_slice(&0u64.to_le_bytes()); // transaction_index
        data.extend_from_slice(&0u64.to_le_bytes()); // stale_transaction_index
        // rent_collector: Some(Pubkey)
        data.push(0x01);
        data.extend_from_slice(&[0xBB; 32]);
        // bump
        data.push(254);
        // members: 2 members
        data.extend_from_slice(&2u32.to_le_bytes());
        data.extend_from_slice(&[0xCC; 32]);
        data.push(7); // all permissions
        data.extend_from_slice(&[0xDD; 32]);
        data.push(2); // voter only

        let result = decode_squads_v4(&data, "TestAddr2").unwrap();
        assert_eq!(result.threshold, 1);
        assert_eq!(result.members.len(), 2);
        assert_eq!(result.members[1].permissions, 2);
    }

    #[test]
    fn test_decode_squads_v4_bad_discriminator() {
        let mut data = vec![0u8; 100];
        data[0..8].copy_from_slice(&[0xFF; 8]);
        let result = decode_squads_v4(&data, "Bad");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("discriminator"));
    }

    #[test]
    fn test_decode_spl_multisig() {
        let mut data = vec![0u8; 355];
        data[0] = 2; // m = 2
        data[1] = 3; // n = 3
        data[2] = 1; // is_initialized

        // 3 signer pubkeys
        for i in 0..3 {
            let start = 3 + i * 32;
            data[start..start + 32].copy_from_slice(&[(i + 1) as u8; 32]);
        }

        let result = decode_spl_multisig(&data, "SplAddr").unwrap();
        assert_eq!(result.threshold, 2);
        assert_eq!(result.members.len(), 3);
        assert_eq!(result.program, SPL_TOKEN_PROGRAM);
    }

    #[test]
    fn test_decode_spl_multisig_not_initialized() {
        let mut data = vec![0u8; 355];
        data[0] = 1;
        data[1] = 2;
        data[2] = 0; // not initialized
        let result = decode_spl_multisig(&data, "Bad");
        assert!(result.is_err());
    }
}
