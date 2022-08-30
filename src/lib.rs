#![deny(clippy::all)]
pub mod api;
pub mod signing;
pub mod types;
use api::file_key::FileKey;
use napi::bindgen_prelude::*;
use signing::Cryptography;

#[macro_use]
extern crate napi_derive;

#[napi(object)]
pub struct Decrypted {
  pub private_key: String,
  pub is_gm: bool,
}

#[napi]
pub fn decrypt_filekey(filekey: String, password: String) -> Result<Decrypted> {
  let fk = serde_json::from_str::<FileKey>(&filekey).unwrap();
  let key_pair = fk.as_key_pair(&password.as_bytes());

  let res = match key_pair {
    Ok(value) => Ok(Decrypted {
      private_key: value.sk.to_str_radix(16),
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
  let file_key = FileKey::from_secret_key(private_key.as_bytes(), password.as_bytes(), crypto);
  let res = serde_json::to_string(&file_key).unwrap();
  res
}
