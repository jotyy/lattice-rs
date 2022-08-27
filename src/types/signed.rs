use serde::{Deserialize, Serialize};

use super::transaction::TransactionRequest;

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct SignedTransaction {
  /// Transaction type
  #[serde(rename = "type")]
  pub transaction_type: String,
  /// Index number
  #[serde(skip_serializing_if = "Option::is_none")]
  pub number: Option<u128>,
  /// Parent block hash
  #[serde(skip_serializing_if = "Option::is_none")]
  #[serde(rename = "parentHash")]
  pub parent_hash: Option<String>,
  /// Daemon block hash
  #[serde(skip_serializing_if = "Option::is_none")]
  #[serde(rename = "daemonHash")]
  pub daemon_hash: Option<String>,
  /// From address
  pub owner: String,
  /// To address
  pub linker: Option<String>,
  /// Transaction amount
  #[serde(skip_serializing_if = "Option::is_none")]
  pub amount: Option<u128>,
  /// Transaction joule cost
  #[serde(skip_serializing_if = "Option::is_none")]
  pub joule: Option<u128>,
  /// Access list
  pub hub: Vec<String>,
  /// Transaction type
  pub timestamp: u64,
  /// Code
  #[serde(skip_serializing_if = "Option::is_none")]
  pub code: Option<String>,
  /// Payload
  #[serde(skip_serializing_if = "Option::is_none")]
  pub payload: Option<String>,
  /// Proof of work
  #[serde(skip_serializing_if = "Option::is_none")]
  #[serde(rename = "proofOfWork")]
  pub proof_of_work: Option<String>,
  /// Signature
  #[serde(skip_serializing_if = "Option::is_none")]
  pub sign: Option<String>,
}

impl SignedTransaction {
  pub fn from_signature_request(req: TransactionRequest, pow: String, signature: String) -> Self {
    SignedTransaction {
      transaction_type: req.transaction_type,
      number: req.number,
      parent_hash: req.parent_hash,
      daemon_hash: req.daemon_hash,
      owner: req.owner,
      linker: req.linker,
      amount: req.amount,
      joule: req.joule,
      hub: match req.hub {
        Some(value) => value,
        None => [].to_vec(),
      },
      timestamp: req.timestamp,
      code: req.code,
      payload: match req.payload {
        Some(value) => {
          if value == "" {
            Some("0x".to_string())
          } else {
            Some(value)
          }
        }
        None => Some("0x".to_string()),
      },
      proof_of_work: Some(format!("0x{}", pow)),
      sign: Some(signature),
    }
  }
}
