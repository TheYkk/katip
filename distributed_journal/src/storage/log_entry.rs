use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct LogEntry {
    pub offset: u64,
    pub timestamp: u64,
    pub key_length: u32,
    pub value_length: u32,
    pub checksum: u32,
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}
