use serde::{Deserialize, Serialize};
use std::fmt;

/// Risk severity levels for audit findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RiskLevel::Info => write!(f, "Info"),
            RiskLevel::Low => write!(f, "Low"),
            RiskLevel::Medium => write!(f, "Medium"),
            RiskLevel::High => write!(f, "High"),
            RiskLevel::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Output format for reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormat {
    Json,
    Md,
}

/// Complete audit report for a multisig wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    pub multisig_address: String,
    pub multisig_program: String,
    pub threshold: u16,
    pub signers: Vec<SignerInfo>,
    pub nonce_findings: Vec<NonceFinding>,
    pub tx_findings: Vec<TxFinding>,
    pub risk_level: RiskLevel,
    pub recommendations: Vec<String>,
    pub timestamp: String,
}

/// Information about a multisig signer and their nonce exposure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerInfo {
    pub pubkey: String,
    pub nonce_accounts_found: u32,
    pub is_suspicious: bool,
}

/// A durable nonce account finding linked to a multisig signer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonceFinding {
    pub nonce_account: String,
    pub authority: String,
    pub created_by: Option<String>,
    pub creation_slot: Option<u64>,
    pub nonce_value: String,
    pub risk: RiskLevel,
    pub reason: String,
}

/// A transaction finding involving durable nonce usage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxFinding {
    pub signature: String,
    pub slot: u64,
    pub nonce_account_used: String,
    pub nonce_authority: String,
    pub payload_summary: String,
    pub risk: RiskLevel,
    pub reason: String,
}

/// Decoded multisig account information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigInfo {
    pub address: String,
    pub program: String,
    pub threshold: u16,
    pub time_lock: u32,
    pub members: Vec<MemberInfo>,
}

/// A member of a multisig with their permissions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberInfo {
    pub pubkey: String,
    pub permissions: u8,
}

/// Decoded on-chain nonce account data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonceAccountInfo {
    pub address: String,
    pub version: u32,
    pub state: u32,
    pub authority: String,
    pub nonce_value: String,
    pub lamports_per_signature: u64,
}

/// Signature info returned from getSignaturesForAddress.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureInfo {
    pub signature: String,
    pub slot: u64,
    pub err: Option<serde_json::Value>,
    #[serde(default)]
    pub memo: Option<String>,
    #[serde(default)]
    pub block_time: Option<i64>,
}
