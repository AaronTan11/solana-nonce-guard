mod multisig;
mod reporter;
mod rpc;
mod scanner;
mod tx_analyzer;
mod types;

use anyhow::Result;
use clap::{Parser, Subcommand};
use types::OutputFormat;

#[derive(Parser)]
#[command(name = "solana-nonce-guard")]
#[command(about = "Detect durable nonce attack vectors on Solana multisig wallets")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Full audit: resolve signers, scan nonces, analyze tx history
    Scan {
        /// Multisig account address
        #[arg(long)]
        multisig: String,
        /// Solana RPC URL
        #[arg(long, default_value = "https://api.mainnet-beta.solana.com")]
        rpc: String,
        /// Output format
        #[arg(long, default_value = "json")]
        format: OutputFormat,
        /// Output file path (stdout if omitted)
        #[arg(long)]
        output: Option<String>,
    },
    /// List current signers and threshold from on-chain data
    Signers {
        /// Multisig account address
        #[arg(long)]
        multisig: String,
        /// Solana RPC URL
        #[arg(long, default_value = "https://api.mainnet-beta.solana.com")]
        rpc: String,
        /// Output format
        #[arg(long, default_value = "json")]
        format: OutputFormat,
        /// Output file path (stdout if omitted)
        #[arg(long)]
        output: Option<String>,
    },
    /// Find all durable nonce accounts where a pubkey is authority
    Nonces {
        /// Public key to scan for nonce accounts
        #[arg(long)]
        pubkey: String,
        /// Solana RPC URL
        #[arg(long, default_value = "https://api.mainnet-beta.solana.com")]
        rpc: String,
        /// Output format
        #[arg(long, default_value = "json")]
        format: OutputFormat,
        /// Output file path (stdout if omitted)
        #[arg(long)]
        output: Option<String>,
    },
    /// Scan recent transactions for durable nonce usage
    TxHistory {
        /// Multisig account address
        #[arg(long)]
        multisig: String,
        /// Solana RPC URL
        #[arg(long, default_value = "https://api.mainnet-beta.solana.com")]
        rpc: String,
        /// Output format
        #[arg(long, default_value = "json")]
        format: OutputFormat,
        /// Output file path (stdout if omitted)
        #[arg(long)]
        output: Option<String>,
        /// Maximum number of transactions to scan
        #[arg(long, default_value = "100")]
        limit: usize,
    },
    /// Live WebSocket monitor for nonce-related activity
    Monitor {
        /// Multisig account address
        #[arg(long)]
        multisig: String,
        /// Solana WebSocket RPC URL
        #[arg(long, default_value = "wss://api.mainnet-beta.solana.com")]
        rpc: String,
        /// Webhook URL for POST alerts (Slack/Discord/custom)
        #[arg(long)]
        webhook: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            multisig,
            rpc,
            format,
            output,
        } => {
            cmd_scan(&multisig, &rpc, format, output.as_deref()).await?;
        }
        Commands::Signers {
            multisig,
            rpc,
            format,
            output,
        } => {
            cmd_signers(&multisig, &rpc, format, output.as_deref()).await?;
        }
        Commands::Nonces {
            pubkey,
            rpc,
            format,
            output,
        } => {
            cmd_nonces(&pubkey, &rpc, format, output.as_deref()).await?;
        }
        Commands::TxHistory {
            multisig,
            rpc,
            format,
            output,
            limit,
        } => {
            cmd_tx_history(&multisig, &rpc, format, output.as_deref(), limit).await?;
        }
        Commands::Monitor {
            multisig,
            rpc,
            webhook,
        } => {
            cmd_monitor(&multisig, &rpc, webhook.as_deref()).await?;
        }
    }

    Ok(())
}

async fn cmd_scan(
    multisig_addr: &str,
    rpc_url: &str,
    format: OutputFormat,
    output: Option<&str>,
) -> Result<()> {
    use colored::Colorize;

    eprintln!(
        "{} Scanning multisig {}...",
        "[-]".cyan(),
        multisig_addr
    );

    let client = rpc::RpcClient::new(rpc_url);

    // 1. Decode multisig
    eprintln!("{} Decoding multisig account...", "[1/4]".cyan());
    let ms = multisig::fetch_and_decode_multisig(&client, multisig_addr).await?;
    eprintln!(
        "    Program: {} | Threshold: {}/{} | TimeLock: {}s",
        ms.program,
        ms.threshold,
        ms.members.len(),
        ms.time_lock
    );

    // 2. Scan nonce accounts for each signer
    eprintln!("{} Scanning nonce accounts for {} signers...", "[2/4]".cyan(), ms.members.len());
    let (signer_infos, nonce_findings) =
        scanner::scan_all_signers(&client, &ms.members).await?;

    for si in &signer_infos {
        if si.nonce_accounts_found > 0 {
            eprintln!(
                "    {} {} — {} nonce account(s) found",
                "!".yellow(),
                &si.pubkey[..12],
                si.nonce_accounts_found
            );
        }
    }

    // 3. Scan tx history
    eprintln!("{} Analyzing transaction history...", "[3/4]".cyan());
    let tx_findings = tx_analyzer::scan_tx_history(&client, multisig_addr, 100).await?;
    if !tx_findings.is_empty() {
        eprintln!(
            "    {} {} durable nonce transaction(s) found",
            "!".yellow(),
            tx_findings.len()
        );
    }

    // 4. Build report
    eprintln!("{} Generating report...", "[4/4]".cyan());
    let risk_level = compute_overall_risk(&nonce_findings, &tx_findings, &ms);
    let recommendations = generate_recommendations(&nonce_findings, &tx_findings, &ms);

    let report = types::AuditReport {
        multisig_address: multisig_addr.to_string(),
        multisig_program: ms.program.clone(),
        threshold: ms.threshold,
        signers: signer_infos,
        nonce_findings,
        tx_findings,
        risk_level,
        recommendations,
        timestamp: chrono::Utc::now().to_rfc3339(),
    };

    reporter::output_report(&report, format, output)?;
    Ok(())
}

async fn cmd_signers(
    multisig_addr: &str,
    rpc_url: &str,
    format: OutputFormat,
    output: Option<&str>,
) -> Result<()> {
    let client = rpc::RpcClient::new(rpc_url);
    let ms = multisig::fetch_and_decode_multisig(&client, multisig_addr).await?;
    reporter::output_value(&ms, format, output)?;
    Ok(())
}

async fn cmd_nonces(
    pubkey: &str,
    rpc_url: &str,
    format: OutputFormat,
    output: Option<&str>,
) -> Result<()> {
    let client = rpc::RpcClient::new(rpc_url);
    let nonces = scanner::find_nonce_accounts(&client, pubkey).await?;
    reporter::output_value(&nonces, format, output)?;
    Ok(())
}

async fn cmd_tx_history(
    multisig_addr: &str,
    rpc_url: &str,
    format: OutputFormat,
    output: Option<&str>,
    limit: usize,
) -> Result<()> {
    let client = rpc::RpcClient::new(rpc_url);
    let findings = tx_analyzer::scan_tx_history(&client, multisig_addr, limit).await?;
    reporter::output_value(&findings, format, output)?;
    Ok(())
}

async fn cmd_monitor(
    multisig_addr: &str,
    ws_url: &str,
    webhook: Option<&str>,
) -> Result<()> {
    use colored::Colorize;
    use futures_util::StreamExt;

    eprintln!(
        "{} Monitoring {} for nonce activity...",
        "[*]".green(),
        multisig_addr
    );
    eprintln!("    Press Ctrl+C to stop.\n");

    let client = rpc::RpcClient::new(ws_url);
    let mut stream = client.logs_subscribe(multisig_addr).await?;

    let webhook_client = webhook.map(|_| reqwest::Client::new());

    while let Some(msg) = stream.next().await {
        let msg = msg?;
        let text = msg.to_text().unwrap_or_default();
        if text.is_empty() {
            continue;
        }

        let parsed: serde_json::Value = match serde_json::from_str(text) {
            Ok(v) => v,
            Err(_) => continue,
        };

        if let Some(logs) = parsed["params"]["result"]["value"]["logs"].as_array() {
            let signature = parsed["params"]["result"]["value"]["signature"]
                .as_str()
                .unwrap_or("unknown");

            let nonce_keywords = [
                "InitializeNonceAccount",
                "AuthorizeNonceAccount",
                "AdvanceNonceAccount",
            ];

            for log in logs {
                let log_str = log.as_str().unwrap_or_default();
                for keyword in &nonce_keywords {
                    if log_str.contains(keyword) {
                        let timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC");
                        let alert = format!(
                            "[{}] {} detected in tx {}",
                            timestamp, keyword, signature
                        );
                        eprintln!("{}", alert.red().bold());

                        if let (Some(url), Some(http)) = (webhook, &webhook_client) {
                            let payload = serde_json::json!({
                                "text": alert,
                                "timestamp": timestamp.to_string(),
                                "signature": signature,
                                "event": keyword,
                                "multisig": multisig_addr,
                            });
                            let _ = http.post(url).json(&payload).send().await;
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

fn compute_overall_risk(
    nonce_findings: &[types::NonceFinding],
    tx_findings: &[types::TxFinding],
    ms: &types::MultisigInfo,
) -> types::RiskLevel {
    let mut max_risk = types::RiskLevel::Info;

    for f in nonce_findings {
        if f.risk > max_risk {
            max_risk = f.risk;
        }
    }
    for f in tx_findings {
        if f.risk > max_risk {
            max_risk = f.risk;
        }
    }

    // Structural risk: low threshold
    let min_threshold = (ms.members.len() as f64 / 2.0).ceil() as u16 + 1;
    if ms.threshold < min_threshold && max_risk < types::RiskLevel::Medium {
        max_risk = types::RiskLevel::Medium;
    }

    max_risk
}

fn generate_recommendations(
    nonce_findings: &[types::NonceFinding],
    tx_findings: &[types::TxFinding],
    ms: &types::MultisigInfo,
) -> Vec<String> {
    let mut recs = Vec::new();

    // Critical: unknown nonce creators
    let unknown_creators = nonce_findings
        .iter()
        .any(|f| f.risk == types::RiskLevel::Critical);
    if unknown_creators {
        recs.push(
            "CRITICAL: Nonce accounts created by unknown wallets detected. \
             Immediately investigate and close suspicious nonce accounts."
                .to_string(),
        );
    }

    // Rapid execution pattern
    let rapid_exec = tx_findings
        .iter()
        .any(|f| f.reason.contains("rapid") || f.reason.contains("Rapid"));
    if rapid_exec {
        recs.push(
            "CRITICAL: Rapid sequential durable nonce execution detected. \
             This may indicate an active attack — freeze multisig immediately."
                .to_string(),
        );
    }

    // Durable nonce txs in history
    if !tx_findings.is_empty() {
        recs.push(
            "HIGH: Durable nonce transactions found in history. \
             Review all pending/queued transactions in Squads UI."
                .to_string(),
        );
    }

    // Threshold analysis
    let min_threshold = (ms.members.len() as f64 / 2.0).ceil() as u16 + 1;
    if ms.threshold < min_threshold {
        recs.push(format!(
            "MEDIUM: Current threshold {}/{} is below recommended minimum of {}. \
             Raise threshold to at least ceil(N/2)+1.",
            ms.threshold,
            ms.members.len(),
            min_threshold
        ));
    }

    // Timelock
    if ms.time_lock == 0 {
        recs.push(
            "MEDIUM: No timelock configured on multisig execution. \
             Add a timelock delay to provide a window for detecting malicious transactions."
                .to_string(),
        );
    }

    // General monitoring
    recs.push(
        "INFO: Set up real-time monitoring via logsSubscribe or Helius webhooks \
         to detect nonce-related activity as it happens."
            .to_string(),
    );

    recs
}
