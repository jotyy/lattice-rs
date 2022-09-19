#![deny(clippy::all)]
pub mod api;
pub mod signing;
pub mod types;
use api::{accounts::Accounts, file_key::FileKey};
use napi::bindgen_prelude::*;
use signing::Cryptography;
use types::transaction::TransactionRequest;

#[macro_use]
extern crate napi_derive;

#[napi(object)]
pub struct Decrypted {
  pub private_key: String,
  pub is_gm: bool,
}

#[napi(object)]
pub struct Signed {
  pub pow: String,
  pub sign: String,
}

#[napi]
pub fn decrypt_filekey(filekey: String, password: String) -> Result<Decrypted> {
  let fk = serde_json::from_str::<FileKey>(&filekey).unwrap();
  let key_pair = fk.as_key_pair(&password.as_bytes());

  let res = match key_pair {
    Ok(value) => Ok(Decrypted {
      private_key: hex::encode(value.sk.to_bytes_be()),
      is_gm: fk.is_gm,
    }),
    Err(_) => Err(Error::new(Status::InvalidArg, "wrong password".to_owned())),
  };
  res
}

#[napi]
pub fn encrypt_filekey(private_key: String, password: String, is_gm: bool) -> String {
  let crypto = if is_gm {
    Cryptography::GM
  } else {
    Cryptography::NIST
  };
  let sk = hex::decode(private_key).unwrap();
  let file_key = FileKey::from_secret_key(&sk, password.as_bytes(), crypto);
  let res = serde_json::to_string(&file_key).unwrap();
  res
}

#[napi]
pub fn sign_transaction(
  transaction: String,
  private_key: String,
  chain_id: u32,
  is_gm: bool,
) -> Signed {
  let crypto = if is_gm {
    Cryptography::GM
  } else {
    Cryptography::NIST
  };
  let account = Accounts {};
  let sk = hex::decode(private_key).unwrap();
  let tx = serde_json::from_str::<TransactionRequest>(&transaction).unwrap();

  let signed = account.sign_transaction(tx, &sk, chain_id, crypto);

  return Signed {
    pow: signed.proof_of_work.unwrap(),
    sign: signed.sign.unwrap(),
  };
}
