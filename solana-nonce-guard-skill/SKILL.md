---
name: solana-nonce-guard-skill
description: >
  Guides users through auditing Solana multisig wallets for durable nonce attack
  vectors — pre-signed transactions that bypass blockhash expiry and enable delayed
  execution exploits. Use when someone asks about: Solana multisig security, durable
  nonce risks, multisig audit, checking for pre-signed transactions, detecting social
  engineering against multisig signers, Squads multisig hardening, protecting DeFi
  protocol admin keys, nonce account scanning, or pre-signed transaction risk.
  Do NOT use for general Solana transaction debugging, wallet balance queries, token
  transfer help, or non-multisig security topics.
compatibility: >
  Requires either: (a) solana-nonce-guard CLI tool with Solana RPC access, or
  (b) access to Solscan/Solana Explorer and optionally the Solana CLI. Works in
  Claude.ai, Claude Code, and API.
metadata:
  author: AaronTan11
  version: 1.0.0
  category: security
  tags: [solana, multisig, security, audit, durable-nonce]
---

# Solana Nonce Guard Skill

## Overview

Durable nonce attacks exploit a Solana mechanism originally designed for offline signing. Normal Solana transactions expire after ~90 seconds because they reference a recent blockhash, but transactions built with a durable nonce replace that blockhash with a nonce value that never expires on its own. An attacker who tricks multisig co-signers into approving a nonce-based transaction can hold that fully-signed transaction indefinitely and submit it at the most damaging moment -- days, weeks, or months later. This is especially dangerous for multisig wallets controlling protocol treasuries, upgrade authorities, or DeFi admin keys. This skill walks you through a structured audit to detect existing durable nonce exposure, identify pre-signed transactions waiting to be executed, and harden multisig configurations against this attack vector.

## Instructions

Determine which mode to use based on whether the user has the `solana-nonce-guard` CLI installed.

### Mode A: With CLI (Recommended)

If the CLI tool is available, run a single scan command to automate Phases 1-3:

```bash
solana-nonce-guard scan \
  --multisig <MULTISIG_ADDRESS> \
  --rpc <RPC_URL> \
  --format json
```

**Interpreting the JSON output:**

- `multisig_config` -- Verify the program type (Squads v3/v4, SPL Governance, etc.), threshold, and signer list match expectations.
- `nonce_accounts` -- Each entry shows the nonce authority, stored nonce value, and lamport balance. Flag any nonce account whose authority is a known signer of the multisig.
- `pending_transactions` -- Pre-signed transactions referencing a durable nonce. The `risk_level` field (critical/high/medium/low) reflects how dangerous the transaction payload is.
- `recommendations` -- Prioritized remediation steps.

After reviewing the JSON output, skip directly to Phase 4 (Signer Hygiene) below to complete the conversational portions of the audit.

### Mode B: Without CLI (Manual Fallback)

Walk the user through all six phases sequentially. At each step provide the exact command or URL so they can execute it themselves.

---

#### Phase 1: Inventory -- Multisig Configuration Verification

**Goal:** Confirm the multisig program, threshold, and signer set.

**Using Solscan:**

Direct the user to:
```
https://solscan.io/account/<MULTISIG_ADDRESS>
```
Look at the "Account Data" tab. Identify the owning program to determine the multisig type.

**Using the Solana CLI:**

```bash
solana account <MULTISIG_ADDRESS> --url <RPC_URL> --output json
```

**What to verify:**
- Owning program matches expected multisig program (e.g., `SMPLecH534NA9acpos4G6x7uf3LWbCAwZQE9e8ZekMu` for Squads v3, `SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf` for Squads v4).
- Threshold value (M of N). Record it.
- Complete list of signer public keys. Record all of them.
- Any time-lock or execution delay settings.

Ask the user to confirm: "Does this signer list and threshold match your expectations?"

---

#### Phase 2: Nonce Account Scan

**Goal:** Find all durable nonce accounts whose authority is one of the multisig signers.

**Using getProgramAccounts RPC call:**

For each signer pubkey, query for nonce accounts they control:

```bash
curl -s <RPC_URL> -X POST -H "Content-Type: application/json" -d '{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "getProgramAccounts",
  "params": [
    "11111111111111111111111111111111",
    {
      "encoding": "jsonParsed",
      "dataSlice": null,
      "filters": [
        { "dataSize": 80 },
        { "memcmp": { "offset": 8, "bytes": "<SIGNER_PUBKEY>" } }
      ]
    }
  ]
}'
```

Replace `<SIGNER_PUBKEY>` with each signer's base58 address. The filter works because nonce accounts are exactly 80 bytes and the authority pubkey starts at byte offset 8.

**Using Solscan (limited):**

Search for each signer address and look for associated system program accounts with exactly 80 bytes of data:
```
https://solscan.io/account/<SIGNER_PUBKEY>#portfolioTokenAccounts
```

**What to record for each nonce account found:**
- Nonce account address
- Authority (which signer controls it)
- Stored nonce value (the blockhash substitute)
- Lamport balance
- Whether the nonce has been advanced recently (check transaction history)

If no nonce accounts are found, note this as a positive finding but continue the audit -- nonce accounts could exist under addresses not yet identified.

---

#### Phase 3: Pending Transaction Audit

**Goal:** Detect any pre-signed transactions that reference a durable nonce.

**For Squads multisig users:**

Direct the user to the Squads UI:
```
https://app.squads.so/squads/<MULTISIG_ADDRESS>/transactions
```
Review all pending (unexecuted) transactions. For each pending transaction:
- Check if the first instruction is `AdvanceNonceAccount` (indicator of durable nonce usage).
- Identify what the transaction does (token transfer, program upgrade, authority change, etc.).
- Note how many signatures are already collected.
- Check if remaining signatures would meet the threshold.

**Using the Solana CLI to inspect a specific transaction:**

```bash
solana confirm <TX_SIGNATURE> --url <RPC_URL> -v
```

Look for `AdvanceNonceAccount` as the first instruction in the decoded output.

**Risk classification for pending transactions:**
- **Critical:** Authority transfers, program upgrades, large token movements referencing a durable nonce with threshold-1 signatures already collected.
- **High:** Any fully-signed durable nonce transaction not yet submitted.
- **Medium:** Durable nonce transactions with partial signatures and benign payloads.
- **Low:** Nonce accounts exist but no pending transactions reference them.

---

#### Phase 4: Signer Hygiene Assessment

**Goal:** Evaluate operational security practices of each signer.

Ask the user the following questions and record the answers:

1. **Hardware wallet usage:** Does each signer use a hardware wallet (Ledger, Trezor) for their multisig key? Signing on a hot wallet makes key extraction and social engineering far easier.
2. **Transaction simulation:** Do signers simulate transactions before signing? Tools like `solana simulate` or Squads' built-in simulation should be standard practice.
3. **Communication security:** How do signers coordinate? Verify they use authenticated channels (Signal, not Discord DMs or email) and have an out-of-band confirmation process for unexpected signing requests.
4. **Signer key rotation:** When was the last time the signer set was reviewed? Have any signers left the organization?
5. **Blind signing:** Do any signers approve transactions without verifying the decoded instructions on their hardware wallet screen?

**Red flags to highlight:**
- Any signer using a browser extension wallet without hardware backing.
- No simulation step before signing.
- Coordination over unencrypted or unauthenticated channels.
- Former team members still in the signer set.
- History of signing transactions without reviewing the full instruction set.

---

#### Phase 5: Structural Hardening Recommendations

**Goal:** Recommend configuration changes to reduce attack surface.

**Threshold:**
- Minimum recommended: `ceil(N/2) + 1` where N is total signers.
- For high-value wallets (>$1M): consider `ceil(2*N/3)` or higher.
- Example: 5 signers should have at least a 4-of-5 threshold, not 2-of-5.

**Timelock / Execution Delay:**
- Recommend adding a timelock of at least 24 hours for high-impact operations (program upgrades, authority transfers, large withdrawals).
- Squads v4 supports configurable time locks natively.

**Monitoring:**
- Set up alerts for nonce account creation by any signer using a monitoring service or custom script:
```bash
# Example: poll for new nonce accounts every hour
solana-nonce-guard watch \
  --signers <SIGNER1>,<SIGNER2>,<SIGNER3> \
  --rpc <RPC_URL> \
  --alert-webhook <WEBHOOK_URL>
```
- If the CLI is unavailable, recommend setting up a cron job that runs the `getProgramAccounts` query from Phase 2 and diffs against a known-good baseline.

**Additional hardening:**
- Rotate the multisig to remove any signer who has left the organization.
- Require all signers to verify decoded instructions on a hardware wallet screen.
- Document an incident response plan for unauthorized nonce account creation.
- Consider using a fresh multisig address if compromise is suspected rather than trying to "fix" the existing one.

---

#### Phase 6: Remediation Summary

**Goal:** Deliver a prioritized action plan.

Organize findings into three tiers:

**Critical (act within 24 hours):**
- Fully-signed durable nonce transactions awaiting execution.
- Nonce accounts controlled by unknown or former-team authorities.
- Active multisig with threshold of 1 (single signer can execute).

**High (act within 1 week):**
- Nonce accounts controlled by current signers without documented purpose.
- Threshold below `ceil(N/2) + 1`.
- Any signer using a hot wallet without hardware backing.
- No transaction simulation process in place.

**Medium (act within 1 month):**
- No monitoring or alerting for nonce account creation.
- No timelock on high-impact operations.
- Signer communication over non-secure channels.
- Missing incident response documentation.

For each finding, provide the specific remediation command or action. For example:

```bash
# Advance a nonce to invalidate any pre-signed transactions referencing it
solana nonce advance <NONCE_ACCOUNT> \
  --nonce-authority <AUTHORITY_KEYPAIR> \
  --url <RPC_URL>

# Close a nonce account entirely
solana nonce close <NONCE_ACCOUNT> \
  --nonce-authority <AUTHORITY_KEYPAIR> \
  --url <RPC_URL>
```

---

## Examples

### Example 1: Full Audit with CLI

**User:** "Audit my Squads multisig at `5abc...xyz` for durable nonce risks."

**Steps:**
1. Run the CLI scan:
   ```bash
   solana-nonce-guard scan \
     --multisig 5abc...xyz \
     --rpc https://api.mainnet-beta.solana.com \
     --format json
   ```
2. Review JSON output: confirm 3-of-5 threshold, 5 known signers.
3. CLI found 2 nonce accounts -- one controlled by signer #2, one by an unknown address.
4. Proceed to Phase 4: ask about hardware wallets and signing practices.
5. Phase 5: threshold is 3-of-5 which meets `ceil(5/2)+1 = 4` -- recommend increasing to 4-of-5.
6. Deliver Phase 6 report: Critical finding (unknown nonce authority), High (threshold below recommendation), Medium (no monitoring).

### Example 2: Quick Nonce Check Without CLI

**User:** "Can you check if any of our 5 signers have nonce accounts? Here are the pubkeys: `Signer1...`, `Signer2...`, `Signer3...`, `Signer4...`, `Signer5...`"

**Steps:**
1. Skip Phase 1 (user already knows the signer set).
2. For each of the 5 pubkeys, provide the `getProgramAccounts` curl command with the memcmp filter.
3. User runs the commands and shares results.
4. Interpret results: "Signer3 has 1 nonce account at address `NonceAbc...`. The stored nonce value is `HashXyz...`. Let's check if any pending transactions reference this nonce."
5. Guide user to check Squads UI or transaction history for that nonce value.
6. If clean, provide a summary: "No pre-signed transactions found referencing the nonce account. Recommend closing the nonce account if it has no legitimate purpose."

### Example 3: Post-Incident Investigation

**User:** "An unauthorized transaction drained our treasury. We suspect a pre-signed durable nonce transaction. Help us investigate."

**Steps:**
1. Get the transaction signature of the unauthorized transfer.
2. Inspect it:
   ```bash
   solana confirm <TX_SIGNATURE> --url <RPC_URL> -v
   ```
3. Check if the first instruction is `AdvanceNonceAccount`. If yes, extract the nonce account address.
4. Query the nonce account to find its authority:
   ```bash
   solana nonce-account <NONCE_ACCOUNT> --url <RPC_URL>
   ```
5. Cross-reference the authority with the signer list. Determine when the transaction was originally signed vs. when it was submitted.
6. Immediately advance or close all remaining nonce accounts controlled by the compromised signer.
7. Recommend rotating the multisig to a new address with the compromised signer removed.
8. Deliver an incident report with timeline, root cause, and prevention steps.

### Example 4: Preventive Hardening for New Multisig

**User:** "We're setting up a new 7-signer Squads multisig for our protocol treasury. What should we do to prevent durable nonce attacks?"

**Steps:**
1. Recommend threshold: `ceil(7/2) + 1 = 5`, so at minimum 5-of-7.
2. Require all signers to use hardware wallets.
3. Enable Squads v4 time lock (minimum 24h for transfers above a set threshold).
4. Set up monitoring from day one:
   ```bash
   solana-nonce-guard watch \
     --signers <ALL_7_PUBKEYS> \
     --rpc <RPC_URL> \
     --alert-webhook <WEBHOOK_URL>
   ```
5. Establish a signing protocol: all signers must simulate, verify decoded instructions on hardware wallet, and confirm via Signal before approving.
6. Document incident response: if a nonce account appears, immediately advance it and convene all signers.
7. Deliver a hardening checklist the team can use as an onboarding document for new signers.

---

## Troubleshooting

### Problem: getProgramAccounts returns empty results

**Cause:** Many public RPC endpoints (including `api.mainnet-beta.solana.com`) disable `getProgramAccounts` to reduce load.

**Solution:**
- Use a dedicated RPC provider that supports `getProgramAccounts`: Helius, QuickNode, Triton, or a private validator.
- Example with Helius:
  ```bash
  curl -s https://mainnet.helius-rpc.com/?api-key=<YOUR_KEY> \
    -X POST -H "Content-Type: application/json" \
    -d '{ ... same query ... }'
  ```
- Alternatively, use the CLI tool which handles RPC selection automatically:
  ```bash
  solana-nonce-guard scan --multisig <ADDR> --rpc https://mainnet.helius-rpc.com/?api-key=<KEY>
  ```

### Problem: CLI scan times out with too many transactions

**Cause:** Multisig wallets with long histories can have thousands of transactions to scan.

**Solution:**
- Use the `--since` flag to limit the scan window:
  ```bash
  solana-nonce-guard scan \
    --multisig <ADDR> \
    --rpc <RPC_URL> \
    --since 2025-01-01 \
    --format json
  ```
- Increase the timeout:
  ```bash
  solana-nonce-guard scan \
    --multisig <ADDR> \
    --rpc <RPC_URL> \
    --timeout 300 \
    --format json
  ```
- For very large histories, scan in date ranges and merge results.

### Problem: Cannot decode multisig account (custom program)

**Cause:** The multisig uses a custom or unrecognized program, not Squads or SPL Governance.

**Solution:**
- Identify the owning program:
  ```bash
  solana account <MULTISIG_ADDRESS> --url <RPC_URL> --output json | jq '.owner'
  ```
- Check if the program has a published IDL on Anchor:
  ```bash
  anchor idl fetch <PROGRAM_ID> --provider.cluster <RPC_URL>
  ```
- If no IDL is available, fall back to raw account data analysis. The nonce account scan (Phase 2) still works regardless of multisig program type because nonce accounts are system program accounts.
- Ask the user if they have the program's source code or documentation for manual decoding.

### Problem: Nonce accounts found but unclear if malicious

**Cause:** Durable nonce accounts have legitimate uses (offline signing, scheduled payments, etc.).

**Solution -- distinguish legitimate from suspicious:**

| Indicator | Legitimate | Suspicious |
|-----------|-----------|------------|
| Authority | Known signer with documented reason | Unknown address or former team member |
| Creation timing | Before or during known offline signing event | No corresponding operational need |
| Nonce advances | Regular advances matching known transactions | Stale nonce (never advanced or advanced once long ago) |
| Balance | Minimum rent-exempt (0.00144768 SOL) | Unusually high balance |
| Associated txs | Matching completed transactions in history | No completed transactions, or pending txs with sensitive payloads |

If the purpose is unclear:
1. Ask the team if anyone created the nonce account and why.
2. Check the nonce account's transaction history on Solscan for context.
3. As a precaution, advance the nonce to invalidate any pre-signed transactions, then monitor for re-creation.

---

## Output Format

The final audit report should contain six sections:

1. **Multisig Configuration Summary** -- Program type, address, threshold (M-of-N), full signer list with labels (if known), and any time lock settings.

2. **Nonce Account Inventory** -- Table of all discovered nonce accounts with columns: Address, Authority, Stored Nonce Value, Balance (SOL), Last Activity Date, Status (active/stale/closed).

3. **Pending Transaction Analysis** -- List of pre-signed durable nonce transactions with: Transaction description, nonce account referenced, signatures collected vs. threshold, risk level (Critical/High/Medium/Low), and recommended action.

4. **Signer Hygiene Assessment** -- Per-signer evaluation covering wallet type, simulation practices, communication channel, and any red flags.

5. **Structural Recommendations** -- Prioritized list of configuration changes (threshold adjustment, timelock addition, monitoring setup, signer rotation) with specific commands or steps to implement each.

6. **Remediation Action Plan** -- All findings organized by severity (Critical/High/Medium) with assigned owners (if known), deadlines, and exact commands to execute.

When the audit is complete, offer to format the report as shareable markdown that the user can distribute to their team or attach to a governance proposal.

---

## References

For deeper technical context on how durable nonces work at the protocol level, nonce account data layout, and the mechanics of the AdvanceNonceAccount instruction, see `references/durable-nonce-technical.md`.
