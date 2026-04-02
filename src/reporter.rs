use anyhow::{Context, Result};
use colored::Colorize;
use std::io::Write;

use crate::types::{AuditReport, OutputFormat, RiskLevel};

/// Output an AuditReport in the specified format to file or stdout.
pub fn output_report(
    report: &AuditReport,
    format: OutputFormat,
    output_path: Option<&str>,
) -> Result<()> {
    let content = match format {
        OutputFormat::Json => to_json(report)?,
        OutputFormat::Md => to_markdown(report)?,
    };
    write_output(&content, output_path)
}

/// Output any serializable value in the specified format.
pub fn output_value<T: serde::Serialize>(
    value: &T,
    format: OutputFormat,
    output_path: Option<&str>,
) -> Result<()> {
    let content = match format {
        OutputFormat::Json => serde_json::to_string_pretty(value)
            .context("Failed to serialize to JSON")?,
        OutputFormat::Md => {
            // For non-report types, just output pretty JSON in a code block
            let json = serde_json::to_string_pretty(value)
                .context("Failed to serialize")?;
            format!("```json\n{}\n```", json)
        }
    };
    write_output(&content, output_path)
}

fn write_output(content: &str, output_path: Option<&str>) -> Result<()> {
    match output_path {
        Some(path) => {
            let mut file = std::fs::File::create(path)
                .with_context(|| format!("Failed to create output file: {}", path))?;
            file.write_all(content.as_bytes())
                .context("Failed to write output")?;
            eprintln!("Report written to {}", path);
        }
        None => {
            println!("{}", content);
        }
    }
    Ok(())
}

fn to_json(report: &AuditReport) -> Result<String> {
    serde_json::to_string_pretty(report).context("Failed to serialize report to JSON")
}

fn to_markdown(report: &AuditReport) -> Result<String> {
    let mut md = String::new();

    // Header
    md.push_str(&format!(
        "# Solana Nonce Guard — Audit Report\n\n**Generated:** {}\n\n---\n\n",
        report.timestamp
    ));

    // Overall risk
    md.push_str(&format!(
        "## Overall Risk: {}\n\n",
        risk_label(&report.risk_level)
    ));

    // Multisig Configuration
    md.push_str("## Multisig Configuration\n\n");
    md.push_str("| Field | Value |\n|-------|-------|\n");
    md.push_str(&format!("| Address | `{}` |\n", report.multisig_address));
    md.push_str(&format!("| Program | `{}` |\n", report.multisig_program));
    md.push_str(&format!(
        "| Threshold | {}/{} |\n",
        report.threshold,
        report.signers.len()
    ));
    md.push_str("\n### Signers\n\n");
    md.push_str("| Pubkey | Nonce Accounts | Suspicious |\n|--------|---------------|------------|\n");
    for s in &report.signers {
        md.push_str(&format!(
            "| `{}` | {} | {} |\n",
            s.pubkey,
            s.nonce_accounts_found,
            if s.is_suspicious { "YES" } else { "No" }
        ));
    }
    md.push('\n');

    // Nonce Findings
    md.push_str("## Nonce Account Findings\n\n");
    if report.nonce_findings.is_empty() {
        md.push_str("No durable nonce accounts found for any signers.\n\n");
    } else {
        for f in &report.nonce_findings {
            md.push_str(&format!(
                "### [{}] Nonce Account `{}`\n\n",
                risk_label(&f.risk),
                f.nonce_account
            ));
            md.push_str(&format!("- **Authority:** `{}`\n", f.authority));
            if let Some(ref creator) = f.created_by {
                md.push_str(&format!("- **Created by:** `{}`\n", creator));
            }
            md.push_str(&format!("- **Nonce Value:** `{}`\n", f.nonce_value));
            md.push_str(&format!("- **Reason:** {}\n\n", f.reason));
        }
    }

    // Transaction Findings
    md.push_str("## Transaction Findings\n\n");
    if report.tx_findings.is_empty() {
        md.push_str("No durable nonce transactions found in recent history.\n\n");
    } else {
        for f in &report.tx_findings {
            md.push_str(&format!(
                "### [{}] Slot {}\n\n",
                risk_label(&f.risk),
                f.slot
            ));
            md.push_str(&format!("- **Signature:** `{}`\n", f.signature));
            md.push_str(&format!(
                "- **Nonce Account:** `{}`\n",
                f.nonce_account_used
            ));
            md.push_str(&format!(
                "- **Authority:** `{}`\n",
                f.nonce_authority
            ));
            md.push_str(&format!("- **Payload:** {}\n", f.payload_summary));
            md.push_str(&format!("- **Reason:** {}\n\n", f.reason));
        }
    }

    // Recommendations
    md.push_str("## Recommendations\n\n");
    for (i, rec) in report.recommendations.iter().enumerate() {
        md.push_str(&format!("{}. {}\n", i + 1, rec));
    }
    md.push('\n');

    Ok(md)
}

fn risk_label(risk: &RiskLevel) -> String {
    match risk {
        RiskLevel::Critical => "CRITICAL".to_string(),
        RiskLevel::High => "HIGH".to_string(),
        RiskLevel::Medium => "MEDIUM".to_string(),
        RiskLevel::Low => "LOW".to_string(),
        RiskLevel::Info => "INFO".to_string(),
    }
}

/// Print a colored alert to stderr (used by monitor mode).
#[allow(dead_code)]
pub fn print_alert(message: &str, risk: &RiskLevel) {
    let colored_msg = match risk {
        RiskLevel::Critical => message.red().bold().to_string(),
        RiskLevel::High => message.yellow().bold().to_string(),
        RiskLevel::Medium => message.cyan().to_string(),
        RiskLevel::Low => message.white().to_string(),
        RiskLevel::Info => message.blue().to_string(),
    };
    eprintln!("{}", colored_msg);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;

    fn sample_report() -> AuditReport {
        AuditReport {
            multisig_address: "MSig111111111111111111111111111111".to_string(),
            multisig_program: "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf".to_string(),
            threshold: 2,
            signers: vec![
                SignerInfo {
                    pubkey: "Signer1111111111111111111111111111".to_string(),
                    nonce_accounts_found: 1,
                    is_suspicious: true,
                },
                SignerInfo {
                    pubkey: "Signer2222222222222222222222222222".to_string(),
                    nonce_accounts_found: 0,
                    is_suspicious: false,
                },
            ],
            nonce_findings: vec![NonceFinding {
                nonce_account: "Nonce1111111111111111111111111111".to_string(),
                authority: "Signer1111111111111111111111111111".to_string(),
                created_by: Some("UnknownWallet999999999999999999".to_string()),
                creation_slot: Some(12345),
                nonce_value: "NonceVal1111111111111111111111111".to_string(),
                risk: RiskLevel::Critical,
                reason: "Created by unknown wallet".to_string(),
            }],
            tx_findings: vec![],
            risk_level: RiskLevel::Critical,
            recommendations: vec![
                "CRITICAL: Investigate nonce accounts".to_string(),
                "MEDIUM: Raise threshold".to_string(),
            ],
            timestamp: "2026-04-02T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn test_json_output() {
        let report = sample_report();
        let json = to_json(&report).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["risk_level"], "critical");
        assert_eq!(parsed["threshold"], 2);
    }

    #[test]
    fn test_markdown_output() {
        let report = sample_report();
        let md = to_markdown(&report).unwrap();
        assert!(md.contains("# Solana Nonce Guard"));
        assert!(md.contains("CRITICAL"));
        assert!(md.contains("MSig111111111111111111111111111111"));
        assert!(md.contains("Nonce Account Findings"));
        assert!(md.contains("Recommendations"));
    }

    #[test]
    fn test_risk_label() {
        assert_eq!(risk_label(&RiskLevel::Critical), "CRITICAL");
        assert_eq!(risk_label(&RiskLevel::Info), "INFO");
    }
}
