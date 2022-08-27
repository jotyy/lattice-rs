#![deny(clippy::all)]
pub mod api;
pub mod signing;
pub mod types;
use api::file_key::FileKey;

#[macro_use]
extern crate napi_derive;

#[napi]
pub fn parse_filekey(filekey: String, password: String) -> String {
  let fk = serde_json::from_str::<FileKey>(&filekey).unwrap();
  let key_pair = fk.as_key_pair(&password.as_bytes());

  let res = match key_pair {
    Ok(value) => value.sk.to_str_radix(16),
    Err(_) => "密码不正确".to_string(),
  };
  res
}
