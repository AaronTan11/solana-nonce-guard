# solana-nonce-guard

Detect durable nonce attack vectors on your Solana multisig before an attacker exploits them.

## Background

Solana's [durable transaction nonces](https://docs.solanalabs.com/implemented-proposals/durable-tx-nonces) allow transactions to be signed now and submitted later — potentially much later. This creates a class of attack against multisig wallets:

1. **Reconnaissance.** An attacker identifies the signers and threshold of a target multisig.
2. **Nonce staging.** The attacker creates durable nonce accounts whose authorities are the multisig signers. These accounts act as "parking slots" for pre-signed transactions.
3. **Social engineering.** The attacker presents seemingly legitimate transactions to each signer and convinces them to sign. Because the transactions use durable nonces instead of recent blockhashes, the signatures never expire.
4. **Deferred execution.** The attacker holds the fully-signed transactions indefinitely — days, weeks, months — then submits them all at once when conditions are most favorable (e.g., high token balances, low vigilance).

Because standard multisig workflows focus on *what* is being signed rather than *how* the transaction's lifetime is scoped, this vector is easy to miss. `solana-nonce-guard` audits your multisig for every stage of this attack pattern and flags exposures before they can be exploited.

## Installation

### From source

```bash
git clone https://github.com/AaronTan11/solana-nonce-guard.git
cd solana-nonce-guard
cargo install --path .
```

Or build without installing:

```bash
cargo build --release
# Binary at ./target/release/solana-nonce-guard
```

## Usage

### Full audit (recommended)

```bash
# Basic scan against a Squads v4 or SPL multisig
solana-nonce-guard scan --multisig <MULTISIG_ADDRESS>

# With a dedicated RPC (recommended — public RPCs rate-limit getProgramAccounts)
solana-nonce-guard scan --multisig <MULTISIG_ADDRESS> --rpc https://your-rpc.helius.xyz

# Output as a markdown report saved to file
solana-nonce-guard scan --multisig <MULTISIG_ADDRESS> --format md --output audit-report.md
```

The `scan` command runs the full pipeline: decode multisig → resolve signers → scan for nonce accounts → analyze transaction history → generate risk report.

### Individual checks

```bash
# List signers and threshold
solana-nonce-guard signers --multisig <ADDR>

# Check a specific pubkey for nonce accounts
solana-nonce-guard nonces --pubkey <SIGNER_PUBKEY>

# Scan transaction history for durable nonce usage
solana-nonce-guard tx-history --multisig <ADDR> --limit 200

# Live monitoring with webhook alerts (Slack/Discord)
solana-nonce-guard monitor \
  --multisig <ADDR> \
  --rpc wss://your-rpc.helius.xyz \
  --webhook https://hooks.slack.com/services/T00/B00/xxxx
```

### Global flags

| Flag | Default | Description |
|------|---------|-------------|
| `--rpc <URL>` | `https://api.mainnet-beta.solana.com` | RPC endpoint (HTTP for most commands, WSS for `monitor`) |
| `--format json\|md` | `json` | Output format |
| `--output <FILE>` | stdout | Write report to a file |

> **Note:** Public RPCs (`api.mainnet-beta.solana.com`) heavily rate-limit or block `getProgramAccounts`, which is the core query for nonce scanning. For production use, use a dedicated RPC provider (Helius, Triton, QuickNode).

## Subcommands

### `scan` — Full audit

Runs every check in sequence: resolve signers, scan nonces, analyze transaction history, and report structural hardening gaps.

```bash
solana-nonce-guard scan \
  --multisig 5XjFt2...abc \
  --rpc https://my-rpc.example.com \
  --format json \
  --output audit.json
```

### `signers` — List signers and threshold

```bash
solana-nonce-guard signers --multisig 5XjFt2...abc
```

### `nonces` — Find nonce accounts for a pubkey

```bash
solana-nonce-guard nonces --pubkey 9aE4Lr...xyz
```

### `tx-history` — Scan recent transactions for durable nonce usage

```bash
solana-nonce-guard tx-history --multisig 5XjFt2...abc --limit 100
```

### `monitor` — Live WebSocket monitoring

Watches for nonce-related activity in real time and optionally fires a webhook on new findings.

```bash
solana-nonce-guard monitor \
  --multisig 5XjFt2...abc \
  --rpc wss://my-rpc.example.com \
  --webhook https://hooks.slack.com/services/T00/B00/xxxx
```

## Example output

### JSON

```json
{
  "multisig_address": "5XjFt2...abc",
  "multisig_program": "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf",
  "threshold": 2,
  "signers": [
    {
      "pubkey": "9aE4Lr...xyz",
      "nonce_accounts_found": 3,
      "is_suspicious": true
    },
    {
      "pubkey": "HkP72m...def",
      "nonce_accounts_found": 0,
      "is_suspicious": false
    }
  ],
  "nonce_findings": [
    {
      "nonce_account": "BpF1x9...n01",
      "authority": "9aE4Lr...xyz",
      "created_by": "CZRBcH...unknown",
      "nonce_value": "7Kp2x9...hash",
      "risk": "critical",
      "reason": "Durable nonce account created by UNKNOWN wallet CZRBcH...unknown for signer 9aE4Lr...xyz. This may indicate an attacker staging a pre-signed transaction attack."
    }
  ],
  "tx_findings": [],
  "risk_level": "critical",
  "recommendations": [
    "CRITICAL: Nonce accounts created by unknown wallets detected. Immediately investigate and close suspicious nonce accounts.",
    "MEDIUM: Current threshold 2/5 is below recommended minimum of 4. Raise threshold to at least ceil(N/2)+1.",
    "MEDIUM: No timelock configured on multisig execution. Add a timelock delay.",
    "INFO: Set up real-time monitoring via logsSubscribe or Helius webhooks."
  ],
  "timestamp": "2026-04-02T12:00:00Z"
}
```

### Markdown

```markdown
# Solana Nonce Guard — Audit Report

**Generated:** 2026-04-02T12:00:00Z

## Overall Risk: CRITICAL

## Multisig Configuration

| Field | Value |
|-------|-------|
| Address | `5XjFt2...abc` |
| Program | `SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf` |
| Threshold | 2/5 |

## Nonce Account Findings

### [CRITICAL] Nonce Account `BpF1x9...n01`

- **Authority:** `9aE4Lr...xyz`
- **Created by:** `CZRBcH...unknown`
- **Reason:** Durable nonce account created by UNKNOWN wallet for signer.

## Recommendations

1. CRITICAL: Immediately investigate and close suspicious nonce accounts.
2. MEDIUM: Raise threshold from 2/5 to at least 4/5.
3. MEDIUM: Add a timelock delay to multisig execution.
4. INFO: Set up real-time monitoring.
```

## How it works

`solana-nonce-guard` maps its analysis directly to the stages of a durable nonce attack:

| Attack stage | Tool stage | What it checks |
|---|---|---|
| Reconnaissance | **Signer resolution** | Enumerates all signers and the approval threshold. Flags if threshold is dangerously low (`< ceil(N/2)+1`). |
| Nonce staging | **Nonce scanning** | For each signer, queries the chain for durable nonce accounts where the signer is the authority. Flags accounts not created by known signers. |
| Execution | **Tx history analysis** | Scans recent multisig transactions for `AdvanceNonceAccount` as first instruction. Detects rapid sequential execution patterns. |
| Structural gaps | **Configuration audit** | Checks for timelocks, threshold adequacy, and monitoring setup. |

## Architecture

The tool uses raw JSON-RPC calls via [reqwest](https://crates.io/crates/reqwest) — no `solana-sdk` or `solana-client` dependency. This keeps the binary small and compile times fast.

```
src/
├── main.rs          # CLI entrypoint (clap v4), subcommand orchestration
├── rpc.rs           # Thin JSON-RPC client (HTTP + WebSocket)
├── scanner.rs       # Nonce account discovery via getProgramAccounts
├── tx_analyzer.rs   # Transaction history analysis, rapid execution detection
├── multisig.rs      # Squads v4 + SPL Token Multisig decoders
├── reporter.rs      # JSON + Markdown output formatting
└── types.rs         # Shared types (AuditReport, NonceFinding, TxFinding, etc.)
```

## Claude skill integration

The `solana-nonce-guard-skill/` directory contains a Claude skill for guided remediation workflows.

- **Claude Code:** The skill is automatically available when working in this repo. Claude can interpret audit reports, explain findings, and walk through remediation steps.
- **Claude.ai:** Upload the `solana-nonce-guard-skill/` directory via *Settings > Capabilities > Skills* for interactive audit guidance.

The skill supports two modes: CLI-assisted (interprets `scan` output) and manual (walks through the full audit process step-by-step using Solscan and RPC queries).

## Contributing

Contributions are welcome. Please open an issue before submitting large changes so the approach can be discussed.

```bash
git clone https://github.com/AaronTan11/solana-nonce-guard.git
cd solana-nonce-guard
cargo test
```

## License

MIT
