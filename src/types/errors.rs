use std::fmt;

#[derive(Copy, Clone, Debug)]
pub struct IncorrectPassword;

impl fmt::Display for IncorrectPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str("Password Error")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for IncorrectPassword {}
