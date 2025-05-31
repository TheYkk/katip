use std::fs::{File, OpenOptions};
use std::io::{self, Write, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, Duration}; // Added SystemTime, Duration
 // Required for LogEntry if not directly used here
use crc32fast::Hasher;

use crate::storage::entry::LogEntry;
use crate::Error; // Assuming Error enum is in crate root or crate::errors

const DEFAULT_MAX_SEGMENT_SIZE: u64 = 1024 * 1024 * 16; // 16MB, placeholder

#[derive(Debug)]
pub struct LogSegment {
    pub base_offset: u64,
    pub file_path: PathBuf,
    // Using BufWriter could improve performance, but start simple
    pub file: File,
    pub current_size: u64,
    pub max_segment_size: u64,
    // Index: (absolute_offset, file_position_start_of_entry)
    pub index: Vec<(u64, u64)>,
    pub(crate) created_at: SystemTime, // Made pub(crate) for testing access if needed
    max_segment_duration: Option<Duration>,
    num_entries: u64,
}

impl LogSegment {
    pub fn new(dir: &Path, base_offset: u64, max_segment_size: Option<u64>, max_duration: Option<Duration>) -> Result<Self, Error> {
        let segment_file_name = format!("{}.log", base_offset);
        let file_path = dir.join(segment_file_name);

        let file = OpenOptions::new()
            .create(true) // Create if it doesn't exist
            .append(true) // Open in append mode for writes initially
            .read(true)   // Need read for recovery and reading entries
            .open(&file_path)?;

        // In a real scenario, we might need to rebuild index if file exists
        // For now, new segment means new file or empty existing one for simplicity.
        // If loading existing segments, this logic would be different.
        Ok(LogSegment {
            base_offset,
            file_path,
            file,
            current_size: 0, // Assuming new segment starts empty or we'd load its size
            max_segment_size: max_segment_size.unwrap_or(DEFAULT_MAX_SEGMENT_SIZE),
            index: Vec::new(),
            created_at: SystemTime::now(),
            max_segment_duration: max_duration,
            num_entries: 0,
        })
    }

    pub fn append(&mut self, entry: &mut LogEntry) -> Result<u64, Error> {
        // 1. Finalize entry details
        entry.offset = self.base_offset + self.num_entries;
        // entry.timestamp is set by caller (Log struct)

        // 2. Calculate checksum
        let mut hasher = Hasher::new();
        hasher.update(&entry.key);
        hasher.update(&entry.value);
        entry.checksum = hasher.finalize();

        entry.key_length = entry.key.len() as u32;
        entry.value_length = entry.value.len() as u32;

        // 3. Serialize entry header (fixed size part) and then data
        // For simplicity, let's serialize the whole LogEntry with bincode.
        // A more optimized version might write fixed-size parts directly.
        let serialized_entry = bincode::serialize(entry).map_err(Error::Serialization)?;
        let entry_len = serialized_entry.len() as u64;

        if self.current_size + entry_len > self.max_segment_size && !self.index.is_empty() {
            // Do not append if it exceeds max size, unless it's the very first entry.
            return Err(Error::SegmentFull);
        }

        let file_position = self.current_size; // Or self.file.seek(SeekFrom::End(0))? if not strictly append

        self.file.write_all(&serialized_entry)?;
        self.file.flush()?; // Ensure it's written to disk

        // 4. Update index and current_size
        self.index.push((entry.offset, file_position));
        self.current_size += entry_len;
        self.num_entries += 1;

        Ok(entry.offset)
    }

    pub fn read(&mut self, relative_offset_in_segment: u64) -> Result<Option<LogEntry>, Error> {
        // This method expects an offset *relative to the segment's base_offset*
        // The Log struct will find the right segment and calculate this.
        // However, our index stores *absolute* offsets. So we search for absolute offset.
        let target_absolute_offset = self.base_offset + relative_offset_in_segment;

        // Find in index: (absolute_offset, file_position)
        if let Some((_offset, file_position)) = self.index.iter().find(|&&(o, _)| o == target_absolute_offset).copied() {
            self.file.seek(SeekFrom::Start(file_position))?;

            // This is tricky: how much to read?
            // If we stored entry length on disk before the entry, we could read that first.
            // Or, if all entries are LogEntry serialized, and we know where the *next* entry starts (or EOF)
            // For now, let's assume bincode handles "read to end of object" if we deserialize from the stream.
            // This might be inefficient or error-prone if file contains more data / garbage.
            // A robust way: store length of serialized_entry before the entry itself.
            // u32: length | data

            // Simplified approach: bincode::deserialize_from will read as much as it needs.
            // This requires the file cursor to be exactly at the start of a serialized LogEntry.
            let entry: LogEntry = bincode::deserialize_from(&mut self.file).map_err(Error::Deserialization)?;

            // Verify checksum
            let mut hasher = Hasher::new();
            hasher.update(&entry.key);
            hasher.update(&entry.value);
            if hasher.finalize() != entry.checksum {
                return Err(Error::ChecksumMismatch);
            }

            // Verify offset matches (sanity check)
            if entry.offset != target_absolute_offset {
                // This would indicate a bug in indexing or file corruption
                eprintln!("Offset mismatch: expected {}, found {}", target_absolute_offset, entry.offset);
                return Err(Error::OffsetNotFound); // Or a more specific error
            }

            Ok(Some(entry))
        } else {
            Ok(None) // Offset not found in this segment's index
        }
    }

    // Load an existing segment file. Populate index.
    pub fn load_existing(file_path: PathBuf, base_offset: u64, max_segment_size: Option<u64>, max_duration: Option<Duration>) -> Result<Self, Error> {
        let mut file = OpenOptions::new()
            .read(true)
            .append(true) // Still need append for future writes if it becomes active
            .open(&file_path)?;

        let mut current_pos = 0u64;
        let mut index = Vec::new();
        let mut entries_count_in_segment = 0;

        // Read entries one by one to rebuild index
        // This assumes entries are tightly packed and bincode can deserialize them sequentially.
        // And that LogEntry also contains its own offset.
        loop {
            // Attempt to deserialize. If it fails, assume EOF or corruption.
            match bincode::deserialize_from::<&mut File, LogEntry>(&mut file) {
                Ok(entry) => {
                    // Verify expected offset if possible, or trust the entry's offset
                    // For now, we trust entry.offset relative to base_offset
                    if entry.offset != base_offset + entries_count_in_segment {
                        // This indicates potential corruption or out-of-order entries
                        // For a robust system, handle this (e.g., truncate or error)
                        return Err(Error::InitializationError(format!(
                            "Offset mismatch during segment load: file {:?}, expected offset {}, found {}. Corruption?",
                            file_path, base_offset + entries_count_in_segment, entry.offset
                        )));
                    }

                    // Verify checksum
                    let mut hasher = Hasher::new();
                    hasher.update(&entry.key);
                    hasher.update(&entry.value);
                    if hasher.finalize() != entry.checksum {
                         return Err(Error::InitializationError(format!(
                            "Checksum mismatch during segment load: file {:?}, offset {}. Corruption?",
                            file_path, entry.offset
                        )));
                    }

                    let entry_file_start_pos = current_pos;
                    // To get entry_len, we'd ideally have it stored.
                    // Or, seek current pos, serialize, get len, then seek back. (inefficient)
                    // Or, after deserializing, tell() gives end pos. entry_len = end_pos - current_pos
                    let entry_end_pos = file.seek(SeekFrom::Current(0))?;
                    let entry_len = entry_end_pos - current_pos;

                    index.push((entry.offset, entry_file_start_pos));
                    current_pos += entry_len;
                    entries_count_in_segment += 1; // This becomes self.num_entries
                }
                Err(e) => {
                    if let bincode::ErrorKind::Io(io_err) = e.as_ref() {
                        if io_err.kind() == io::ErrorKind::UnexpectedEof {
                            // Reached end of file, expected if file is properly terminated.
                            break;
                        }
                    }
                    // Any other deserialization error is problematic.
                    // This could also be an EOF if the file is truncated.
                    // For now, we break, assuming it's a clean EOF.
                    // A production system would log this error.
                    eprintln!("Deserialization error during segment load (file: {:?}): {:?}. Assuming EOF or truncated segment.", file_path, e);
                    break;
                }
            }
        }

        Ok(LogSegment {
            base_offset,
            file_path,
            file,
            current_size: current_pos,
            max_segment_size: max_segment_size.unwrap_or(DEFAULT_MAX_SEGMENT_SIZE),
            index,
            created_at: SystemTime::now(), // For a loaded segment, its "age" for expiration effectively starts now.
                                         // Or, try to parse from filename/metadata if that scheme is adopted later.
            max_segment_duration: max_duration,
            num_entries: entries_count_in_segment,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.num_entries == 0
    }

    pub fn has_expired(&self) -> bool {
        if let Some(duration) = self.max_segment_duration {
            // An empty segment can still be considered expired if it's old.
            // The decision not to rotate an empty active segment is up to the Log struct.
            match SystemTime::now().duration_since(self.created_at) {
                Ok(age) => age > duration,
                Err(_) => false, // Clock went backwards, assume not expired for safety
            }
        } else {
            false
        }
    }

    // Getter for num_entries field
    pub fn num_entries(&self) -> u64 {
        self.num_entries
    }

    // Getter for created_at field
    pub(crate) fn created_at(&self) -> SystemTime { // pub(crate) for tests
        self.created_at
    }

    // Getter for base_offset
    pub fn base_offset(&self) -> u64 {
        self.base_offset
    }

    // Getter for file_path
    pub fn file_path(&self) -> &Path {
        &self.file_path
    }


    pub fn is_full(&self) -> bool {
        self.current_size >= self.max_segment_size
    }

    // Close is mostly handled by Drop, but explicit flush can be useful.
    pub fn close(mut self) -> Result<(), Error> {
        self.file.flush()?;
        // File is closed when `self` is dropped.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use crate::storage::entry::LogEntry; // Explicit import for clarity in tests
    use std::io::{Write, Seek, SeekFrom};
    use assert_matches::assert_matches;


    // Helper to create a LogEntry for testing
    fn create_test_log_entry(offset: u64, key: &[u8], value: &[u8]) -> LogEntry {
        // In actual use, timestamp, checksum, key_length, value_length are set by Log/LogSegment
        LogEntry {
            offset,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            key_length: key.len() as u32,
            value_length: value.len() as u32,
            checksum: 0, // Will be calculated by segment.append
            key: key.to_vec(),
            value: value.to_vec(),
        }
    }

    // Helper for tests needing a segment
    fn create_test_segment(dir_path: &Path, base_offset: u64, max_size: Option<u64>, max_duration: Option<Duration>) -> LogSegment {
        LogSegment::new(dir_path, base_offset, max_size, max_duration).unwrap()
    }


    #[test]
    fn test_segment_new_creates_file() {
        let dir = tempdir().unwrap();
        let segment = create_test_segment(dir.path(), 0, Some(1024), None);
        assert!(segment.file_path().exists());
        assert_eq!(segment.base_offset(), 0);
        assert_eq!(segment.current_size, 0);
        assert!(segment.index.is_empty());
        assert_eq!(segment.num_entries(), 0);
    }

    #[test]
    fn test_segment_append_and_read_single_entry() {
        let dir = tempdir().unwrap();
        let mut segment = create_test_segment(dir.path(), 0, Some(1024), None);

        let mut entry = create_test_log_entry(0, b"key1", b"value1");
        let original_key = entry.key.clone();
        let original_value = entry.value.clone();

        let offset = segment.append(&mut entry).unwrap();
        assert_eq!(offset, 0); // First entry in a new segment, relative offset is 0, absolute is base_offset + 0
        assert_eq!(segment.num_entries(), 1);
        assert!(segment.current_size > 0);
        assert_eq!(segment.index[0], (0, 0)); // Offset 0, file position 0

        // Check entry fields were updated
        assert_eq!(entry.offset, 0); // Absolute offset
        assert_ne!(entry.checksum, 0); // Checksum should be calculated
        assert_eq!(entry.key_length, original_key.len() as u32);
        assert_eq!(entry.value_length, original_value.len() as u32);


        let read_entry = segment.read(0).unwrap().expect("Failed to read entry");
        assert_eq!(read_entry.offset, 0); // Absolute offset
        assert_eq!(read_entry.key, original_key);
        assert_eq!(read_entry.value, original_value);
        assert_eq!(read_entry.checksum, entry.checksum);
    }

    #[test]
    fn test_segment_append_and_read_multiple_entries() {
        let dir = tempdir().unwrap();
        let mut segment = LogSegment::new(dir.path(), 100, Some(2048), None).unwrap(); // base_offset 100, Added None for max_duration

        let mut entry1 = create_test_log_entry(100, b"key1", b"value1");
        let offset1 = segment.append(&mut entry1).unwrap();
        assert_eq!(offset1, 100);

        let mut entry2 = create_test_log_entry(101, b"key2", b"value2_long");
        let offset2 = segment.append(&mut entry2).unwrap();
        assert_eq!(offset2, 101);

        assert_eq!(segment.num_entries(), 2);

        let read_entry1 = segment.read(0).unwrap().expect("Failed to read entry 1"); // relative offset 0
        assert_eq!(read_entry1.offset, 100);
        assert_eq!(read_entry1.key, b"key1");

        let read_entry2 = segment.read(1).unwrap().expect("Failed to read entry 2"); // relative offset 1
        assert_eq!(read_entry2.offset, 101);
        assert_eq!(read_entry2.value, b"value2_long");
    }

    #[test]
    fn test_segment_is_full() {
        let dir = tempdir().unwrap();
        // Max size enough for approx one entry, to easily test fullness
        let mut segment = create_test_segment(dir.path(), 0, Some(100), None);

        let mut entry1 = create_test_log_entry(0, b"key1", b"this is a relatively long value to fill segment");
        segment.append(&mut entry1).unwrap();

        // Depending on bincode overhead, this might make it full or not.
        // If not, append another small one.
        if !segment.is_full() {
            let mut entry2 = create_test_log_entry(1, b"k2", b"v2");
             // This append might fail if the first entry already made it "full" for the next one
            let res = segment.append(&mut entry2);
            if res.is_ok() {
                 assert!(segment.is_full(), "Segment should be full after two entries if entry2 fit and made it full");
            } else {
                assert_matches!(res, Err(Error::SegmentFull));
                // If entry2 failed due to SegmentFull, current_size is unchanged from after entry1.
                // is_full() reflects state after entry1. It is not necessarily true.
                // The assertion here was likely too strong.
                // We've asserted that res is Err(SegmentFull). That's the main check for this path.
                // We can check that current_size + size_of_entry2 > max_segment_size
                // For now, let's remove the possibly incorrect assert!(segment.is_full()).
                // The crucial part is that entry2 was rejected as expected.
            }
        } else { // Segment was already full after entry1
            assert!(segment.is_full(), "Segment should be full after one large entry if it alone exceeded max_size");
        }

        let mut entry3 = create_test_log_entry(2, b"key3", b"value3");
        let result = segment.append(&mut entry3);
        assert_matches!(result, Err(Error::SegmentFull));
    }

    #[test]
    fn test_segment_read_offset_out_of_bounds() {
        let dir = tempdir().unwrap();
        let mut segment = create_test_segment(dir.path(), 0, Some(1024), None);
        let mut entry = create_test_log_entry(0, b"key1", b"value1");
        segment.append(&mut entry).unwrap();

        let result = segment.read(1); // Relative offset 1, but only entry 0 exists
        assert!(result.unwrap().is_none());

        let result2 = segment.read(100); // Way out of bounds
        assert!(result2.unwrap().is_none());
    }

    #[test]
    fn test_segment_reload_and_read() {
        let dir = tempdir().unwrap();
        let segment_path = dir.path().join("0.log");
        let max_size = Some(1024u64);

        let mut entry1_orig = create_test_log_entry(0, b"key_reload_1", b"value_reload_1");
        let entry1_key = entry1_orig.key.clone();
        let entry1_val = entry1_orig.value.clone();

        let mut entry2_orig = create_test_log_entry(1, b"key_reload_2", b"value_reload_2_longer");
        let entry2_key = entry2_orig.key.clone();
        let entry2_val = entry2_orig.value.clone();

        {
            let mut segment = create_test_segment(dir.path(), 0, max_size, None);
            segment.append(&mut entry1_orig).unwrap();
            segment.append(&mut entry2_orig).unwrap();
            // Segment goes out of scope, file is flushed and closed (due to Drop on File)
        }

        let mut reloaded_segment = LogSegment::load_existing(segment_path, 0, max_size, None).unwrap();

        assert_eq!(reloaded_segment.num_entries(), 2);
        assert!(reloaded_segment.current_size > 0);
        assert_eq!(reloaded_segment.base_offset, 0);

        let read_entry1 = reloaded_segment.read(0).unwrap().expect("Failed to read entry 1 after reload");
        assert_eq!(read_entry1.offset, 0);
        assert_eq!(read_entry1.key, entry1_key);
        assert_eq!(read_entry1.value, entry1_val);

        let read_entry2 = reloaded_segment.read(1).unwrap().expect("Failed to read entry 2 after reload");
        assert_eq!(read_entry2.offset, 1);
        assert_eq!(read_entry2.key, entry2_key);
        assert_eq!(read_entry2.value, entry2_val);
    }

    #[test]
    fn test_segment_checksum_error_on_load() {
        let dir = tempdir().unwrap();
        let segment_path = dir.path().join("0.log");
        let max_size = Some(1024u64);
        let base_offset = 0u64;

        let mut entry_good = create_test_log_entry(base_offset, b"good_key", b"good_value");

        // Manually serialize and corrupt an entry
        let mut entry_bad = create_test_log_entry(base_offset + 1, b"bad_key", b"bad_value");
        // Calculate its correct checksum first
        let mut hasher = Hasher::new();
        hasher.update(&entry_bad.key);
        hasher.update(&entry_bad.value);
        entry_bad.checksum = hasher.finalize();
        entry_bad.key_length = entry_bad.key.len() as u32;
        entry_bad.value_length = entry_bad.value.len() as u32;

        let mut serialized_bad_entry = bincode::serialize(&entry_bad).unwrap();
        // Corrupt by flipping a byte in the value part (need to be careful not to corrupt length fields)
        // Find where value bytes start: offset, timestamp, key_len, value_len, checksum, key...
        // Simplest: corrupt last byte of serialized data, likely part of value or key.
        if !serialized_bad_entry.is_empty() {
            let last_idx = serialized_bad_entry.len() - 1;
            serialized_bad_entry[last_idx] = !serialized_bad_entry[last_idx];
        }


        {
            let mut segment_file = OpenOptions::new().create(true).read(true).write(true).open(&segment_path).unwrap();

            // Write a good entry
            let _ = segment_file.seek(SeekFrom::Start(0)); // Ensure starting at 0 for this manual write
            let mut temp_segment_writer = create_test_segment(dir.path(), base_offset, max_size, None); // Use its append logic
            temp_segment_writer.append(&mut entry_good).unwrap();
            // Good entry is written. temp_segment_writer is dropped, file closed.

            // Re-open to append corrupted data manually
            let mut file_appender = OpenOptions::new().append(true).open(&segment_path).unwrap();
            file_appender.write_all(&serialized_bad_entry).unwrap();
            file_appender.flush().unwrap();
        } // file_appender is dropped

        // Now try to load the segment. It should detect the checksum error on the second entry.
        match LogSegment::load_existing(segment_path.clone(), base_offset, max_size, None) {
            Ok(segment) => {
                // Depending on how load_existing handles errors (stops or skips),
                // this might pass if it loads only the first good entry.
                // The current load_existing returns Err on first corruption.
                panic!("Segment load should have failed due to checksum mismatch, but succeeded. Loaded {} entries.", segment.num_entries());
            }
            Err(Error::InitializationError(msg)) => {
                assert!(msg.contains("Checksum mismatch during segment load"));
            }
            Err(e) => {
                panic!("Expected InitializationError with checksum message, got {:?}", e);
            }
        }
    }

    #[test]
    fn test_segment_has_expired() {
        let dir = tempdir().unwrap();
        let short_duration = Duration::from_millis(50);
        let long_duration = Duration::from_secs(3600);

        // Segment with duration, initially not expired
        let mut seg_with_short_ttl = create_test_segment(dir.path(), 0, Some(1024), Some(short_duration));
        let mut entry = create_test_log_entry(0, b"k", b"v");
        seg_with_short_ttl.append(&mut entry).unwrap(); // Add an entry so it's not considered "active empty" by some interpretations
        assert!(!seg_with_short_ttl.has_expired(), "Segment should not be expired immediately after creation");

        // Segment without duration
        let seg_no_ttl = create_test_segment(dir.path(), 1, Some(1024), None);
        assert!(!seg_no_ttl.has_expired(), "Segment without max_duration should never expire");

        // Segment with long duration
        let seg_with_long_ttl = create_test_segment(dir.path(), 2, Some(1024), Some(long_duration));
        assert!(!seg_with_long_ttl.has_expired(), "Segment with long TTL should not be expired soon");

        // Wait for short_duration to pass
        std::thread::sleep(short_duration + Duration::from_millis(20)); // Sleep a bit longer

        assert!(seg_with_short_ttl.has_expired(), "Segment should be expired after short_duration");
        assert!(!seg_no_ttl.has_expired(), "Segment without max_duration should still not expire");
        assert!(!seg_with_long_ttl.has_expired(), "Segment with long TTL should still not be expired");
    }
     #[test]
    fn test_segment_has_expired_empty_active_rule() {
        let dir = tempdir().unwrap();
        let short_duration = Duration::from_millis(10);
        let mut seg = LogSegment {
            base_offset: 0,
            file_path: dir.path().join("0.log"),
            file: OpenOptions::new().create(true).read(true).write(true).open(dir.path().join("0.log")).unwrap(),
            current_size: 0,
            max_segment_size: 1024,
            index: Vec::new(),
            created_at: SystemTime::now() - short_duration * 2, // Created in the past
            max_segment_duration: Some(short_duration),
            num_entries: 0, // Explicitly empty
        };
        // The rule "Don't expire empty segments that are active" is subtle.
        // has_expired() itself doesn't know if it's active.
        // If num_entries is 0, the current has_expired() returns false.
        // If an empty segment is old enough, it has expired.
        assert!(seg.has_expired(), "Old empty segment should report as expired");

        // If it has entries and is old, it should also expire
        seg.num_entries = 1;
        assert!(seg.has_expired(), "Non-empty old segment should report as expired");

        // If it's new, it shouldn't expire
        seg.created_at = SystemTime::now();
        seg.num_entries = 0;
        assert!(!seg.has_expired(), "New empty segment should not be expired");
        seg.num_entries = 1;
        assert!(!seg.has_expired(), "New non-empty segment should not be expired");
    }
}
