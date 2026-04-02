# Durable Nonce Technical Reference

Technical reference for the solana-nonce-guard skill. Covers the mechanics of Solana durable nonce transactions, on-chain data layouts, detection techniques, RPC auditing methods, monitoring infrastructure, and attack patterns.

---

## 1. How Durable Nonce Transactions Work

Standard Solana transactions include a `recentBlockhash` drawn from a recent slot. The network rejects any transaction whose blockhash is older than roughly 150 slots (~60-90 seconds). This short validity window prevents replay attacks but also means a pre-signed transaction becomes unusable almost immediately.

Durable nonce transactions replace that mechanism entirely. Instead of a recent blockhash, the transaction's `recentBlockhash` field is set to a **stored nonce value** held in a dedicated on-chain nonce account. This nonce value does not expire with time. It only changes when the `AdvanceNonceAccount` instruction is executed against that account. As a result, a transaction signed today can be submitted and executed days, weeks, or even months later, as long as the nonce value has not been advanced in the interim.

Key behavioral differences from normal transactions:

| Property | Normal Transaction | Durable Nonce Transaction |
|---|---|---|
| Blockhash source | Recent slot blockhash | Stored nonce value from nonce account |
| Validity window | ~60-90 seconds | Indefinite (until nonce is advanced) |
| First instruction | Any | Must be `AdvanceNonceAccount` |
| Replay protection | Blockhash expiry | Nonce advances on execution |

---

## 2. Nonce Account Data Layout

Nonce accounts are owned by the **System Program** (`11111111111111111111111111111111`) and contain exactly **80 bytes** of data.

```
Offset   Size    Type              Field              Description
------   ----    ----              -----              -----------
0-3      4       u32 (LE)          Version            Account version. 0 = Current.
4-7      4       u32 (LE)          State              0 = Uninitialized, 1 = Initialized.
8-39     32      Pubkey (bytes)    Authority          The pubkey authorized to advance,
                                                      authorize, or withdraw.
40-71    32      Hash (bytes)      Nonce Value        The stored blockhash substitute.
                                                      This is what goes into the tx's
                                                      recentBlockhash field.
72-79    8       u64 (LE)          FeeCalculator      lamports_per_signature at the time
                                                      of the last advance.
```

**Total: 80 bytes**

To decode raw account data (base64), parse these fields at their byte offsets. Example in pseudocode:

```
data = base64_decode(account.data[0])
version   = u32_le(data[0..4])
state     = u32_le(data[4..8])
authority = pubkey(data[8..40])
nonce     = bs58_encode(data[40..72])
fee       = u64_le(data[72..80])
```

---

## 3. Nonce Instructions

All nonce instructions are processed by the **System Program** (`11111111111111111111111111111111`). Each has a specific instruction discriminator within the System Program's instruction set.

### InitializeNonceAccount

Creates a nonce account and sets its initial authority.

- **Accounts**: `[writable] nonce_account`, `[] recent_blockhashes_sysvar`, `[] rent_sysvar`
- **Data**: Authority pubkey (32 bytes)
- **Effect**: Sets state to `Initialized`, stores current blockhash as the nonce value, records the authority.
- **Prerequisite**: The account must already be created (via `CreateAccount`) with at least 80 bytes of space and enough lamports for rent exemption, owned by the System Program.

### AdvanceNonceAccount

Updates the stored nonce value to the most recent blockhash.

- **Accounts**: `[writable] nonce_account`, `[] recent_blockhashes_sysvar`, `[signer] nonce_authority`
- **Data**: None (beyond the instruction discriminator)
- **Effect**: Replaces the stored nonce value with the current blockhash. Updates the fee calculator.
- **Constraint**: When used in a durable nonce transaction, this **must be instruction index 0** (the very first instruction). The runtime enforces this.

### AuthorizeNonceAccount

Changes the authority pubkey on the nonce account.

- **Accounts**: `[writable] nonce_account`, `[signer] current_nonce_authority`
- **Data**: New authority pubkey (32 bytes)
- **Effect**: Overwrites the authority field at offset 8-39 with the new pubkey.
- **Security note**: After this instruction executes, the previous authority loses all control. This is a critical operation in attack scenarios.

### WithdrawNonceAccount

Withdraws SOL from the nonce account. Can close the account entirely.

- **Accounts**: `[writable] nonce_account`, `[writable] recipient`, `[] recent_blockhashes_sysvar`, `[] rent_sysvar`, `[signer] nonce_authority`
- **Data**: Lamports to withdraw (u64)
- **Effect**: Transfers lamports to the recipient. If the withdrawal brings the balance below rent-exempt minimum, the account is closed (state reset to `Uninitialized`, data zeroed).

---

## 4. Constructing a Durable Nonce Transaction

Building a valid durable nonce transaction requires four conditions:

### 4.1 AdvanceNonceAccount as First Instruction

The `AdvanceNonceAccount` instruction must be placed at **index 0** in the transaction's instruction list. The Solana runtime checks for this and will reject the transaction otherwise. All other instructions (transfers, program calls, etc.) follow after it.

### 4.2 Nonce Value as recentBlockhash

The transaction's `recentBlockhash` field must contain the **current stored nonce value** from the nonce account (the 32-byte hash at offset 40-71), not an actual recent blockhash from a slot. Fetch this via `getAccountInfo` before constructing the transaction.

### 4.3 Nonce Authority Must Sign

The nonce authority (the pubkey at offset 8-39 of the nonce account) must be included as a signer on the transaction. This is enforced by the `AdvanceNonceAccount` instruction.

### 4.4 Automatic Nonce Advancement on Execution

When the transaction is successfully executed, the `AdvanceNonceAccount` instruction fires first, replacing the stored nonce value with the current blockhash. This means the same nonce value can never be used twice, providing replay protection equivalent to normal blockhash expiry.

### Construction Pseudocode

```
nonce_account_data = rpc.getAccountInfo(nonce_account_pubkey)
stored_nonce = decode_nonce_value(nonce_account_data)

tx = new Transaction()
tx.recentBlockhash = stored_nonce
tx.add(SystemProgram.nonceAdvance({
    noncePubkey: nonce_account_pubkey,
    authorizedPubkey: nonce_authority
}))
tx.add(... other instructions ...)
tx.sign(nonce_authority, ... other signers ...)
```

---

## 5. Detection Signatures

### 5.1 Parsed Transaction Inspection

When fetching a transaction with `jsonParsed` encoding, a durable nonce transaction has this structure:

```json
{
  "transaction": {
    "message": {
      "instructions": [
        {
          "program": "system",
          "parsed": {
            "type": "advanceNonceAccount",
            "info": {
              "nonceAccount": "<NONCE_ACCOUNT_PUBKEY>",
              "nonceAuthority": "<AUTHORITY_PUBKEY>",
              "recentBlockhashesSysvar": "SysvarRecentB1telephones11111111111111111111"
            }
          }
        }
      ]
    }
  }
}
```

The primary detection check:

```
instructions[0].program == "system"
  && instructions[0].parsed.type == "advanceNonceAccount"
```

### 5.2 Blockhash Mismatch

The `recentBlockhash` in a durable nonce transaction will not match any blockhash from recent slots. If you query `getRecentBlockhash` or `getLatestBlockhash` and compare, a durable nonce transaction's blockhash will not appear in any recent slot's history. This serves as a secondary detection signal but is less reliable than checking instruction[0].

### 5.3 Raw (Non-Parsed) Detection

If working with binary/base64 transaction data rather than parsed JSON:

1. Deserialize the transaction message.
2. Check if the first instruction references the System Program (`11111111111111111111111111111111`).
3. Check if the instruction data starts with the `AdvanceNonceAccount` discriminator (bytes `04 00 00 00` -- instruction index 4 in the System Program enum, encoded as u32 LE).

---

## 6. RPC Methods for Auditing

### 6.1 getAccountInfo -- Decode Nonce Account Data

Fetch raw nonce account data for inspection.

```json
{
  "method": "getAccountInfo",
  "params": [
    "<NONCE_ACCOUNT_PUBKEY>",
    { "encoding": "base64" }
  ]
}
```

Parse the 80-byte data buffer per the layout in Section 2. Key fields to extract:
- **Authority** (offset 8-39): Who controls this nonce account.
- **Nonce value** (offset 40-71): The current stored hash. If a pre-signed transaction exists using this value, it is still valid and executable.

### 6.2 getProgramAccounts -- Find All Nonce Accounts for an Authority

Query the System Program for all nonce accounts controlled by a specific authority pubkey.

```json
{
  "method": "getProgramAccounts",
  "params": [
    "11111111111111111111111111111111",
    {
      "encoding": "base64",
      "filters": [
        { "dataSize": 80 },
        {
          "memcmp": {
            "offset": 8,
            "bytes": "<AUTHORITY_PUBKEY_BASE58>"
          }
        }
      ]
    }
  ]
}
```

This returns every nonce account where the given pubkey is the authority. Useful for:
- Discovering nonce accounts an attacker may have staged.
- Auditing how many nonce accounts a particular signer controls.

### 6.3 getTransaction -- Inspect Parsed Transaction Data

Fetch a transaction with full parsed instruction detail.

```json
{
  "method": "getTransaction",
  "params": [
    "<TX_SIGNATURE>",
    { "encoding": "jsonParsed", "maxSupportedTransactionVersion": 0 }
  ]
}
```

Check `instructions[0]` for `advanceNonceAccount` type to confirm durable nonce usage. Inspect the `info` fields to identify the nonce account and authority involved.

### 6.4 getSignaturesForAddress -- Paginated Transaction History

Retrieve historical transaction signatures involving a specific address (e.g., a nonce account or multisig address).

```json
{
  "method": "getSignaturesForAddress",
  "params": [
    "<ADDRESS>",
    { "limit": 100, "before": "<LAST_TX_SIGNATURE>" }
  ]
}
```

Paginate through results using the `before` field set to the last signature from the previous batch. For each signature, call `getTransaction` to check for durable nonce usage.

---

## 7. Monitoring Setup

### 7.1 Helius Webhooks

Helius provides enhanced transaction type classification. Set up a webhook filtering for these transaction types:

- `INITIALIZE_NONCE` -- Fires when a new nonce account is created. Indicates someone is setting up durable nonce infrastructure.
- `AUTHORIZE_NONCE` -- Fires when a nonce account's authority changes. A critical alert: an attacker who gains authority over a nonce account controls whether pre-signed transactions can execute.
- `ADVANCE_NONCE` -- Fires when a nonce value is updated. In isolation this is routine, but correlate with other activity.

Webhook configuration:

```json
{
  "webhookURL": "https://your-endpoint.example.com/nonce-events",
  "transactionTypes": [
    "INITIALIZE_NONCE",
    "AUTHORIZE_NONCE",
    "ADVANCE_NONCE"
  ],
  "accountAddresses": ["<MULTISIG_ADDRESS>", "<KNOWN_NONCE_ACCOUNTS>"]
}
```

### 7.2 Solana logsSubscribe WebSocket

Subscribe to transaction logs mentioning the multisig address via the native Solana WebSocket API.

```json
{
  "method": "logsSubscribe",
  "params": [
    { "mentions": ["<MULTISIG_ADDRESS>"] },
    { "commitment": "confirmed" }
  ]
}
```

Parse incoming log messages for nonce-related keywords and program invocations:
- Look for System Program invocations (`11111111111111111111111111111111`) in the log's account keys.
- Check for instruction data patterns matching nonce operations.
- Correlate with the detection signatures from Section 5.

Combine both approaches for defense in depth: Helius webhooks provide classified, high-level alerts, while `logsSubscribe` gives raw, real-time log streams for detailed analysis.

---

## 8. Attack Timeline Pattern

A durable nonce attack against a multisig follows a deliberate, phased approach. Each phase may be separated by days or weeks, making detection difficult without continuous monitoring.

### Phase 1: Reconnaissance

The attacker identifies and studies the target multisig:

- Maps all signer pubkeys and determines the approval threshold (e.g., 2-of-3, 3-of-5).
- Studies historical transaction patterns: what types of transactions are routine, when they typically occur, which signers are most active.
- Identifies which signers are most susceptible to social engineering based on their signing patterns and operational habits.
- Determines the multisig program being used (Squads, SPL Governance, etc.) and its specific instruction layout.

### Phase 2: Nonce Staging

The attacker creates the infrastructure for the attack:

- Creates one or more durable nonce accounts, each with an authority the attacker controls.
- Constructs unsigned transactions that use these nonce accounts' stored values as the `recentBlockhash`.
- The transactions contain the malicious payload: authority changes, fund transfers, program upgrades, or other high-impact operations.
- These nonce accounts and pre-built transactions sit dormant, leaving minimal on-chain footprint. The only visible artifact is the nonce account creation itself.

### Phase 3: Signature Collection

The attacker gathers the required number of signer approvals:

- Social engineers individual signers into signing transactions disguised as routine operations (e.g., "routine token transfer", "standard program upgrade", "config update").
- Each signer signs independently, often at different times. No single signer sees the full picture.
- Because durable nonce transactions have no expiry, the attacker can take days or weeks to collect all required signatures, approaching each signer separately.
- The attacker may use legitimate-looking front-ends or transaction descriptions to mask the true intent of the instructions.

### Phase 4: Rapid Execution

Once sufficient signatures are collected, the attacker strikes:

- Submits all pre-signed transactions within seconds or minutes of each other.
- The `AdvanceNonceAccount` instruction fires first in each transaction, consuming the nonce and executing the payload atomically.
- Common attack sequence:
  1. Transaction A: Change multisig authority/ownership to attacker-controlled keys.
  2. Transaction B: Drain treasury funds to attacker wallets.
  3. Transaction C: Revoke remaining legitimate signer access.
- By the time anyone notices the first transaction, subsequent transactions have already landed. The multisig is fully compromised before any defensive action can be taken.

### Detection Opportunities by Phase

| Phase | Observable Signal | Detection Method |
|---|---|---|
| Phase 2 (Staging) | New nonce accounts with authority linked to multisig signers | `getProgramAccounts` scan, Helius `INITIALIZE_NONCE` webhook |
| Phase 3 (Collection) | Off-chain; no on-chain signal | Out-of-band signer communication, signing request audits |
| Phase 4 (Execution) | Burst of durable nonce transactions against the multisig | `logsSubscribe` real-time monitoring, Helius webhooks |

The critical window for prevention is **Phase 2**. Once Phase 4 begins, the attack completes in seconds. Continuous monitoring for nonce account creation and authority changes tied to multisig addresses is the primary defense.
