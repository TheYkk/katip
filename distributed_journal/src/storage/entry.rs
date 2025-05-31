use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LogEntry {
    pub offset: u64,
    pub timestamp: u64,
    pub key_length: u32,
    pub value_length: u32,
    pub checksum: u32, // CRC32 checksum of key + value
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_log_entry_serialization_deserialization() {
        let original_entry = LogEntry {
            offset: 123,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            key_length: 3,
            value_length: 5,
            checksum: 0, // Checksum is calculated on append in segment, so initial value doesn't matter for this test
            key: b"key".to_vec(),
            value: b"value".to_vec(),
        };

        let serialized = bincode::serialize(&original_entry).expect("Failed to serialize LogEntry");
        let deserialized: LogEntry = bincode::deserialize(&serialized).expect("Failed to deserialize LogEntry");

        assert_eq!(original_entry.offset, deserialized.offset);
        assert_eq!(original_entry.timestamp, deserialized.timestamp);
        assert_eq!(original_entry.key_length, deserialized.key_length);
        assert_eq!(original_entry.value_length, deserialized.value_length);
        // Checksum is not compared as it's set by segment, not part of intrinsic LogEntry state for this test
        assert_eq!(original_entry.key, deserialized.key);
        assert_eq!(original_entry.value, deserialized.value);
    }
}
