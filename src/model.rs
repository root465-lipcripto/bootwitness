use std::{collections::BTreeMap, io};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub fields: BTreeMap<String, String>,
    pub events: Vec<String>,
    pub notes: Vec<String>,
}

#[derive(Debug)]
pub struct BwError(pub String);

impl std::fmt::Display for BwError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<io::Error> for BwError {
    fn from(error: io::Error) -> Self {
        Self(error.to_string())
    }
}
