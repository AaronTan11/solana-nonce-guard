use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::Message;

use crate::types::SignatureInfo;

/// Filter types for getProgramAccounts.
pub enum Filter {
    DataSize(u64),
    Memcmp { offset: u64, bytes: String },
}

impl Filter {
    fn to_json(&self) -> Value {
        match self {
            Filter::DataSize(size) => json!({ "dataSize": size }),
            Filter::Memcmp { offset, bytes } => {
                json!({ "memcmp": { "offset": offset, "bytes": bytes } })
            }
        }
    }
}

/// Thin Solana RPC client using reqwest for HTTP and tokio-tungstenite for WebSocket.
pub struct RpcClient {
    http: reqwest::Client,
    url: String,
}

impl RpcClient {
    pub fn new(url: &str) -> Self {
        Self {
            http: reqwest::Client::new(),
            url: url.trim_end_matches('/').to_string(),
        }
    }

    /// Generic JSON-RPC 2.0 call.
    async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });

        let resp = self
            .http
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("RPC request to {} failed", method))?;

        let json: Value = resp
            .json()
            .await
            .with_context(|| format!("Failed to parse {} response", method))?;

        if let Some(err) = json.get("error") {
            return Err(anyhow!(
                "RPC error in {}: {}",
                method,
                serde_json::to_string(err).unwrap_or_default()
            ));
        }

        Ok(json["result"].clone())
    }

    /// Fetch account data (base64-decoded bytes) and owner program ID.
    /// Returns None if the account doesn't exist.
    pub async fn get_account_info(&self, pubkey: &str) -> Result<Option<(Vec<u8>, String)>> {
        let result = self
            .call(
                "getAccountInfo",
                json!([pubkey, { "encoding": "base64" }]),
            )
            .await?;

        if result.is_null() {
            return Ok(None);
        }

        let value = &result["value"];
        if value.is_null() {
            return Ok(None);
        }

        let data_arr = value["data"]
            .as_array()
            .ok_or_else(|| anyhow!("Missing data field in account info"))?;

        let b64_data = data_arr[0]
            .as_str()
            .ok_or_else(|| anyhow!("Account data is not a string"))?;

        let bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            b64_data,
        )
        .context("Failed to decode base64 account data")?;

        let owner = value["owner"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing owner field"))?
            .to_string();

        Ok(Some((bytes, owner)))
    }

    /// Query getProgramAccounts with filters. Returns (pubkey, decoded data bytes) pairs.
    pub async fn get_program_accounts(
        &self,
        program_id: &str,
        filters: Vec<Filter>,
    ) -> Result<Vec<(String, Vec<u8>)>> {
        let filter_json: Vec<Value> = filters.iter().map(|f| f.to_json()).collect();

        let result = self
            .call(
                "getProgramAccounts",
                json!([
                    program_id,
                    {
                        "encoding": "base64",
                        "filters": filter_json,
                    }
                ]),
            )
            .await?;

        let accounts = result
            .as_array()
            .ok_or_else(|| anyhow!("getProgramAccounts did not return an array"))?;

        let mut out = Vec::with_capacity(accounts.len());
        for acct in accounts {
            let pubkey = acct["pubkey"]
                .as_str()
                .ok_or_else(|| anyhow!("Missing pubkey in program account"))?
                .to_string();

            let data_arr = acct["account"]["data"]
                .as_array()
                .ok_or_else(|| anyhow!("Missing data in program account"))?;

            let b64 = data_arr[0]
                .as_str()
                .ok_or_else(|| anyhow!("Account data is not a string"))?;

            let bytes = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                b64,
            )
            .context("Failed to decode program account data")?;

            out.push((pubkey, bytes));
        }

        Ok(out)
    }

    /// Fetch transaction signatures for an address, paginated up to `limit`.
    pub async fn get_signatures_for_address(
        &self,
        address: &str,
        limit: usize,
    ) -> Result<Vec<SignatureInfo>> {
        let mut all_sigs = Vec::new();
        let mut before: Option<String> = None;
        let batch_size = limit.min(1000);

        loop {
            let remaining = limit - all_sigs.len();
            if remaining == 0 {
                break;
            }
            let fetch = remaining.min(batch_size);

            let mut params = json!({ "limit": fetch });
            if let Some(ref b) = before {
                params["before"] = json!(b);
            }

            let result = self
                .call(
                    "getSignaturesForAddress",
                    json!([address, params]),
                )
                .await?;

            let sigs: Vec<SignatureInfo> = serde_json::from_value(result)
                .context("Failed to parse signatures response")?;

            if sigs.is_empty() {
                break;
            }

            before = Some(sigs.last().unwrap().signature.clone());
            all_sigs.extend(sigs);

            if all_sigs.len() >= limit {
                break;
            }

            // Rate limiting for public RPCs
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        all_sigs.truncate(limit);
        Ok(all_sigs)
    }

    /// Fetch a transaction with jsonParsed encoding.
    pub async fn get_transaction(&self, signature: &str) -> Result<Value> {
        self.call(
            "getTransaction",
            json!([
                signature,
                {
                    "encoding": "jsonParsed",
                    "maxSupportedTransactionVersion": 0
                }
            ]),
        )
        .await
    }

    /// Connect to WebSocket and subscribe to logs mentioning the given address.
    /// Returns the WebSocket stream for consuming messages.
    pub async fn logs_subscribe(
        &self,
        address: &str,
    ) -> Result<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    > {
        let ws_url = http_to_ws(&self.url);

        let (mut ws, _) = tokio_tungstenite::connect_async(&ws_url)
            .await
            .with_context(|| format!("Failed to connect WebSocket to {}", ws_url))?;

        let subscribe_msg = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "logsSubscribe",
            "params": [
                { "mentions": [address] },
                { "commitment": "confirmed" }
            ]
        });

        use futures_util::SinkExt;
        ws.send(Message::Text(subscribe_msg.to_string()))
            .await
            .context("Failed to send logsSubscribe")?;

        Ok(ws)
    }
}

/// Convert HTTP(S) URL to WS(S) URL.
fn http_to_ws(url: &str) -> String {
    if url.starts_with("wss://") || url.starts_with("ws://") {
        return url.to_string();
    }
    if url.starts_with("https://") {
        return url.replacen("https://", "wss://", 1);
    }
    if url.starts_with("http://") {
        return url.replacen("http://", "ws://", 1);
    }
    // Default: assume wss
    format!("wss://{}", url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_to_ws_conversions() {
        assert_eq!(
            http_to_ws("https://api.mainnet-beta.solana.com"),
            "wss://api.mainnet-beta.solana.com"
        );
        assert_eq!(
            http_to_ws("http://localhost:8899"),
            "ws://localhost:8899"
        );
        assert_eq!(
            http_to_ws("wss://api.mainnet-beta.solana.com"),
            "wss://api.mainnet-beta.solana.com"
        );
    }
}
