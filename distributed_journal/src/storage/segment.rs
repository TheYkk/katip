// src/storage/segment.rs
use crate::storage::index::Index;
use crate::storage::log_entry::LogEntry;
use bincode::{deserialize_from, serialize};
use crc32fast::Hasher;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf}; // Added Index import

// Represents a single segment file in the log.
pub struct Segment {
    pub base_offset: u64,
    // Renamed current_offset_in_segment to current_relative_offset for clarity with index
    pub current_relative_offset: u64,
    pub file_path: PathBuf, // Path to the .log file
    file: File,             // The .log data file
    index: Index,           // The associated .index file
    max_segment_bytes: u64,
    current_data_bytes: u64, // Tracks the byte size of data in the .log file (excluding headers of future entries)
}

impl Segment {
    // Creates a new segment or opens an existing one.
    // Initializes the data file (.log) and the index file (.index).
    pub fn new<P: AsRef<Path>>(
        dir: P,
        base_offset: u64,
        max_segment_bytes: u64,
    ) -> io::Result<Self> {
        let file_path = dir.as_ref().join(format!("{}.log", base_offset));
        let data_file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true) // Need write access for appends and potential truncation
            .open(&file_path)?;

        // Create or open the associated index file
        let index_module = crate::storage::index::Index::new(dir.as_ref(), base_offset)?;

        Ok(Segment {
            base_offset,
            current_relative_offset: 0, // Initialized to 0, will be updated by load_or_initialize
            file_path,
            file: data_file,
            index: index_module,
            max_segment_bytes,
            current_data_bytes: 0, // Initialized to 0, will be updated by load_or_initialize
        })
    }

    // Loads an existing segment's index and scans the data file (.log)
    // to ensure consistency and determine the next writable position and relative offset.
    // If inconsistencies are found (e.g. index points beyond data, or data entry checksum fails),
    // it may truncate the data file and rebuild the index from available valid entries.
    pub fn load_or_initialize(&mut self) -> io::Result<()> {
        self.index.load()?; // Load existing index entries into memory

        self.current_data_bytes = 0; // Reset before scan
        self.current_relative_offset = 0;

        let mut scan_start_pos_in_log: u64 = 0;
        let mut next_expected_relative_offset: u64 = 0;

        // Try to find a consistent point to start scanning the log file from, based on the index
        if let Some(last_indexed_rel_offset) = self.index.get_last_relative_offset() {
            if let Some(pos_of_last_idx_entry_data) =
                self.index.find_position(last_indexed_rel_offset)
            {
                // Check if this position is valid in the log file
                self.file
                    .seek(SeekFrom::Start(pos_of_last_idx_entry_data))?;
                let mut len_bytes_header = [0u8; 4];
                if self.file.read_exact(&mut len_bytes_header).is_ok() {
                    let data_len = u32::from_be_bytes(len_bytes_header) as u64;
                    // Check if the full entry (header + data) is within file bounds (if we knew file size)
                    // For now, we assume if we can read header, we can attempt to read data
                    scan_start_pos_in_log = pos_of_last_idx_entry_data + 4 + data_len;
                    next_expected_relative_offset = last_indexed_rel_offset + 1;
                } else {
                    // Failed to read the log entry data for the last indexed offset.
                    // This suggests the log file is shorter than the index implies.
                    eprintln!("Segment {}: .log file is shorter than index {:?} implies (last indexed rel_offset: {} at pos {}). Rebuilding index for this segment.",
                        self.base_offset, self.index.file_path, last_indexed_rel_offset, pos_of_last_idx_entry_data);
                    // Recreate index, effectively clearing it for rebuild
                    self.index = Index::new(
                        self.file_path.parent().unwrap_or_else(|| Path::new(".")),
                        self.base_offset,
                    )?;
                    scan_start_pos_in_log = 0; // Rescan log from start
                    next_expected_relative_offset = 0;
                }
            } else {
                // This case (last_indexed_rel_offset exists but find_position returns None) should ideally not happen with current Index impl.
                eprintln!("Segment {}: Index internal inconsistency for {:?} (last_rel_offset {} position lookup failed). Rebuilding index.", self.base_offset, self.index.file_path, last_indexed_rel_offset);
                self.index = Index::new(
                    self.file_path.parent().unwrap_or_else(|| Path::new(".")),
                    self.base_offset,
                )?;
                scan_start_pos_in_log = 0;
                next_expected_relative_offset = 0;
            }
        }

        // Position file pointer and set internal counters for scanning from determined point
        self.file.seek(SeekFrom::Start(scan_start_pos_in_log))?;
        self.current_data_bytes = scan_start_pos_in_log;
        self.current_relative_offset = next_expected_relative_offset;

        // Scan the .log file from scan_start_pos_in_log to the end or max_segment_bytes
        loop {
            let current_pos_in_log = self.file.stream_position()?;
            // Stop if we are at or beyond the max segment size (for writing, reading might be different)
            if current_pos_in_log >= self.max_segment_bytes {
                break;
            }

            let mut len_bytes = [0u8; 4];
            match self.file.read_exact(&mut len_bytes) {
                Ok(_) => {
                    let data_len = u32::from_be_bytes(len_bytes) as u64;

                    // Check for partial write: if entry + header exceeds max_segment_bytes or file length
                    if current_pos_in_log + 4 + data_len > self.max_segment_bytes {
                        eprintln!("Segment {}: Found partial entry at end of segment (pos {}). Truncating .log file.", self.base_offset, current_pos_in_log);
                        self.file.set_len(current_pos_in_log)?; // Truncate file
                        break;
                    }
                    // At this point, we expect to read a full entry.
                    // If this relative offset is not in the index OR if it is but points to a different log position,
                    // then the index is out of sync or corrupt.
                    let current_entry_is_indexed_correctly =
                        self.index.find_position(self.current_relative_offset)
                            == Some(current_pos_in_log);

                    if !current_entry_is_indexed_correctly {
                        // If find_position was None, it means index is missing this entry.
                        // If find_position was Some(other_pos), it means index is pointing wrong for this entry.
                        // In a more robust system, we might try to validate the entry here (checksum) before adding to index.
                        // For now, if it's not indexed correctly, we add/overwrite it.
                        // If we are rebuilding (because index was cleared earlier), this will add all entries.
                        self.index
                            .add_entry(self.current_relative_offset, current_pos_in_log)?;
                    }

                    // Skip over the entry's data to get to the next header
                    if self.file.seek(SeekFrom::Current(data_len as i64)).is_err() {
                        // Could not seek, implies partial write of data itself.
                        eprintln!("Segment {}: .log file ended unexpectedly after reading entry header at {}. Truncating.", self.base_offset, current_pos_in_log);
                        self.file.set_len(current_pos_in_log)?; // Truncate before this partially written entry
                        break;
                    }
                    self.current_data_bytes = current_pos_in_log + 4 + data_len;
                    self.current_relative_offset += 1;
                }
                Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    // Clean end of file, all read.
                    break;
                }
                Err(e) => return Err(e), // Other I/O error
            }
        }
        // After scan, ensure file pointer is at the end of valid data for subsequent appends
        self.file.seek(SeekFrom::Start(self.current_data_bytes))?;
        self.index.sync_all()?; // Persist any new index entries from scan/rebuild
        Ok(())
    }

    // Appends a LogEntry to this segment.
    pub fn append(&mut self, key: Vec<u8>, value: Vec<u8>) -> io::Result<Option<u64>> {
        let absolute_offset = self.base_offset + self.current_relative_offset;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let key_length = key.len() as u32;
        let value_length = value.len() as u32;

        // Prepare data for checksum
        let mut csum_data = Vec::new();
        csum_data.extend_from_slice(&absolute_offset.to_be_bytes());
        csum_data.extend_from_slice(&timestamp.to_be_bytes());
        csum_data.extend_from_slice(&key_length.to_be_bytes());
        csum_data.extend_from_slice(&value_length.to_be_bytes());
        csum_data.extend_from_slice(&key);
        csum_data.extend_from_slice(&value);
        let mut hasher = Hasher::new();
        hasher.update(&csum_data);
        let checksum = hasher.finalize();

        let entry = LogEntry {
            offset: absolute_offset,
            timestamp,
            key_length,
            value_length,
            checksum,
            key,
            value,
        };
        let serialized_entry =
            serialize(&entry).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let entry_len_on_disk = serialized_entry.len() as u64;

        // Check if segment has space for this entry (4 bytes for length prefix + entry data)
        if self.current_data_bytes + 4 + entry_len_on_disk > self.max_segment_bytes {
            return Ok(None); // Segment is full
        }

        let position_before_write = self.current_data_bytes; // This is where the entry's length header will start

        // Ensure writer is at the end of the segment data file
        self.file.seek(SeekFrom::Start(position_before_write))?;
        // Write length prefix, then the entry
        self.file
            .write_all(&(entry_len_on_disk as u32).to_be_bytes())?;
        self.file.write_all(&serialized_entry)?;
        // self.file.flush()?; // Optional: flush per entry, or rely on higher level flush / OS caching

        // Add entry to index
        self.index
            .add_entry(self.current_relative_offset, position_before_write)?;

        // Update segment state
        self.current_data_bytes += 4 + entry_len_on_disk;
        self.current_relative_offset += 1;

        Ok(Some(absolute_offset))
    }

    // Reads an entry by its relative offset *within this segment*.
    pub fn read_entry_by_relative_offset(
        &mut self,
        target_relative_offset: u64,
    ) -> io::Result<Option<LogEntry>> {
        match self.index.find_position(target_relative_offset) {
            Some(position) => {
                self.file.seek(SeekFrom::Start(position))?;
                let mut len_bytes = [0u8; 4];
                self.file.read_exact(&mut len_bytes)?; // Read the length prefix
                let len = u32::from_be_bytes(len_bytes);

                let mut entry_buf = vec![0; len as usize];
                self.file.read_exact(&mut entry_buf)?; // Read the entry data

                let entry: LogEntry = deserialize_from(&*entry_buf)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

                // Sanity check: does the deserialized entry's own offset match what we expected?
                if entry.offset != self.base_offset + target_relative_offset {
                    return Err(io::Error::new(io::ErrorKind::InvalidData,
                        format!("Segment {}: Index-Log offset mismatch. Read entry for abs_offset {} (key: {:?}), but expected abs_offset {} (rel_offset {}). Index pointed to byte {}.",
                        self.base_offset, entry.offset, String::from_utf8_lossy(&entry.key), self.base_offset + target_relative_offset, target_relative_offset, position)));
                }

                // Verify checksum
                let mut csum_data = Vec::new();
                csum_data.extend_from_slice(&entry.offset.to_be_bytes());
                csum_data.extend_from_slice(&entry.timestamp.to_be_bytes());
                csum_data.extend_from_slice(&entry.key_length.to_be_bytes());
                csum_data.extend_from_slice(&entry.value_length.to_be_bytes());
                csum_data.extend_from_slice(&entry.key);
                csum_data.extend_from_slice(&entry.value);
                let mut hasher = Hasher::new();
                hasher.update(&csum_data);
                if hasher.finalize() != entry.checksum {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "Segment {}: Checksum mismatch for entry at abs_offset {}",
                            self.base_offset, entry.offset
                        ),
                    ));
                }
                Ok(Some(entry))
            }
            None => Ok(None), // Not found in index
        }
    }

    pub fn is_full(&self) -> bool {
        // A more robust check might consider a small minimum entry size.
        // If current_data_bytes is very close to max_segment_bytes, it's likely full.
        // The append method does the exact check against the incoming entry's size.
        self.current_data_bytes >= self.max_segment_bytes
    }

    // Flushes both data file and index file to disk.
    pub fn flush_all(&mut self) -> io::Result<()> {
        self.file.flush()?;
        self.index.sync_all()
    }

    // Gets the next relative offset for this segment.
    pub fn get_current_relative_offset(&self) -> u64 {
        self.current_relative_offset
    }

    #[allow(dead_code)]
    pub fn get_current_data_bytes(&self) -> u64 {
        self.current_data_bytes
    }

    // Renamed from original flush() to avoid confusion with flush_all()
    // This is specific to the data file, used before by Log's roll_segment.
    // Now flush_all is preferred.
    #[allow(dead_code)]
    pub fn flush_data_file(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}
