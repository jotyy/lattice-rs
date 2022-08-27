use crate::{
  signing::{self, hash_message, Cryptography, KeyPair},
  types::{signed::SignedTransaction, transaction::TransactionRequest},
};

#[derive(Debug, Clone)]
pub struct Accounts {}

impl Accounts {
  pub fn hash_message<S>(&self, message: S, crypto: Cryptography) -> String
  where
    S: AsRef<[u8]>,
  {
    let message = message.as_ref();

    let mut ltc_message = format!("\x19ZLattice Signed Message:\n{}", message.len()).into_bytes();

    ltc_message.extend_from_slice(message);

    signing::hash_message(&message, crypto)
  }

  pub fn sign_transaction(
    &self,
    tx: TransactionRequest,
    key: &[u8],
    chain_id: u64,
    crypto: Cryptography,
  ) -> SignedTransaction {
    let key_pair = KeyPair::from_secret_key(key, crypto);

    let (pow, encoded) = tx.encode(chain_id, crypto);
    let hash = hash_message(&encoded, crypto);
    let data = hex::decode(hash).unwrap();
    let signature = key_pair.sign(&data);
    SignedTransaction::from_signature_request(tx, hex::encode(pow.to_bytes_be()), signature)
  }
}
