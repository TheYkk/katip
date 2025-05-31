// src/storage/log.rs
use crate::storage::log_entry::LogEntry;
use crate::storage::segment::Segment;
use std::collections::BTreeMap;
use std::fs;
use std::io::{self};
use std::path::{Path, PathBuf};

const DEFAULT_MAX_SEGMENT_BYTES: u64 = 1024 * 1024 * 16; // 16MB example

pub struct Log {
    log_dir: PathBuf,
    active_segment: Segment,
    segments: BTreeMap<u64, Segment>, // Stores finalized (non-active) segments
    max_segment_bytes: u64,
    // next_global_offset is removed as it's now derived from active_segment's state
}

impl Log {
    pub fn new<P: AsRef<Path>>(log_dir: P) -> io::Result<Self> {
        Self::with_max_segment_bytes(log_dir, DEFAULT_MAX_SEGMENT_BYTES)
    }

    pub fn with_max_segment_bytes<P: AsRef<Path>>(
        log_dir_p: P,
        max_segment_bytes: u64,
    ) -> io::Result<Self> {
        let log_dir = log_dir_p.as_ref();
        fs::create_dir_all(log_dir)?;

        let mut found_segments_map = BTreeMap::new();
        let mut max_seen_base_offset = 0u64;
        let mut max_segment_end_offset = 0u64; // Tracks the end of the segment with the highest offset

        for entry_res in fs::read_dir(log_dir)? {
            let entry = entry_res?;
            let entry_path = entry.path();
            // Ensure we are only trying to load .log files as segments
            if entry_path.is_file() && entry_path.extension().map_or(false, |ext| ext == "log") {
                if let Some(name_str) = entry_path.file_stem().and_then(|name| name.to_str()) {
                    if let Ok(base_offset) = name_str.parse::<u64>() {
                        let mut segment = Segment::new(log_dir, base_offset, max_segment_bytes)?;
                        segment.load_or_initialize()?; // This now loads index and scans log

                        max_seen_base_offset = max_seen_base_offset.max(base_offset);
                        max_segment_end_offset = max_segment_end_offset
                            .max(segment.base_offset + segment.get_current_relative_offset());
                        found_segments_map.insert(base_offset, segment);
                    }
                }
            }
        }

        let active_segment;
        if let Some((&last_base_offset, _)) = found_segments_map.last_key_value() {
            // get the segment with largest base_offset
            // This segment was loaded and scanned by load_or_initialize.
            // We need to check if it's full to decide if it can be active.
            let last_segment_state = found_segments_map.get(&last_base_offset).unwrap();

            if last_segment_state.is_full() {
                // Last known segment is full, create a new one.
                // The new base offset should be the end of the fullest, highest-offset segment.
                let new_segment_base = max_segment_end_offset;
                let mut new_active = Segment::new(log_dir, new_segment_base, max_segment_bytes)?;
                new_active.load_or_initialize()?; // Initialize (creates empty files, loads empty index)
                active_segment = new_active;
            } else {
                // Last segment is not full, make it active.
                // Remove it from found_segments_map as it's now the active_segment.
                active_segment = found_segments_map.remove(&last_base_offset).unwrap();
            }
        } else {
            // No segments found, create a new active segment starting at offset 0.
            let mut new_active = Segment::new(log_dir, 0, max_segment_bytes)?;
            new_active.load_or_initialize()?; // Initialize
            active_segment = new_active;
        }

        Ok(Log {
            log_dir: log_dir.to_path_buf(),
            active_segment,
            segments: found_segments_map, // Contains all non-active segments
            max_segment_bytes,
        })
    }

    // append_entry is preferred
    #[deprecated(
        note = "Use append_entry which has clearer semantics on data ownership for retries"
    )]
    pub fn append(&mut self, key: Vec<u8>, value: Vec<u8>) -> io::Result<u64> {
        self.append_entry(key, value)
    }

    pub fn append_entry(&mut self, key: Vec<u8>, value: Vec<u8>) -> io::Result<u64> {
        if self.active_segment.is_full() {
            self.roll_segment()?;
        }

        // Try to append. If it returns None, it means the segment is full (e.g. entry too large for remaining space).
        match self.active_segment.append(key, value)? {
            Some(offset) => Ok(offset),
            None => {
                // This implies the entry was too large for the current active segment's remaining space,
                // or the segment became full exactly at this moment.
                // We should roll the segment and try appending to the new one.
                self.roll_segment()?;
                // Retry append on the new active segment.
                // Note: This recursive call or retry logic needs careful handling of key/value.
                // If `append` consumes key/value, they must be cloned or passed again.
                // The current Segment::append takes ownership. For simplicity, this example
                // assumes the caller might need to handle retry with fresh key/value if this second attempt fails.
                // A robust version would clone key/value for the retry.
                // For this subtask, we'll assume the second attempt is with the original data (which is problematic if consumed).
                // Let's return an error to indicate caller should retry with data.
                Err(io::Error::new(io::ErrorKind::WriteZero, "Segment rolled after initial append attempt failed due to space. Caller should retry append with data on the new segment."))
            }
        }
    }

    fn roll_segment(&mut self) -> io::Result<()> {
        self.active_segment.flush_all()?; // Ensure data and index of old active segment are synced

        let old_segment_base_offset = self.active_segment.base_offset;
        // New segment starts immediately after the last entry of the old one.
        let next_base_for_new_segment =
            self.active_segment.base_offset + self.active_segment.get_current_relative_offset();

        let mut new_active_segment = Segment::new(
            &self.log_dir,
            next_base_for_new_segment,
            self.max_segment_bytes,
        )?;
        new_active_segment.load_or_initialize()?; // Initialize the new segment (creates files, empty index)

        // Replace the current active_segment with the new one, moving the old one to the segments map.
        let old_active_segment = std::mem::replace(&mut self.active_segment, new_active_segment);
        self.segments
            .insert(old_segment_base_offset, old_active_segment); // Store the now-finalized segment

        Ok(())
    }

    pub fn read_at_global_offset(&mut self, global_offset: u64) -> io::Result<Option<LogEntry>> {
        // Check active segment first
        let active_base = self.active_segment.base_offset;
        // Calculate end offset for active segment (exclusive)
        let active_end = active_base + self.active_segment.get_current_relative_offset();

        if global_offset >= active_base && global_offset < active_end {
            let relative_offset = global_offset - active_base;
            return self
                .active_segment
                .read_entry_by_relative_offset(relative_offset);
        }

        // Check historical segments (BTreeMap is sorted by base_offset)
        // Iterate in reverse to check newer segments first, though find_position in index is efficient.
        for (&segment_base, segment) in self.segments.iter_mut().rev() {
            // Calculate end offset for this historical segment (exclusive)
            let segment_end = segment.base_offset + segment.get_current_relative_offset();
            if global_offset >= segment_base && global_offset < segment_end {
                let relative_offset = global_offset - segment_base;
                return segment.read_entry_by_relative_offset(relative_offset);
            }
        }
        Ok(None) // Not found in active or any historical segment
    }

    // Returns the next global offset that will be assigned to a new entry.
    pub fn get_next_global_offset(&self) -> u64 {
        self.active_segment.base_offset + self.active_segment.get_current_relative_offset()
    }

    // Flushes all data (active segment and historical segments) to disk.
    pub fn flush_all_data(&mut self) -> io::Result<()> {
        self.active_segment.flush_all()?;
        for segment in self.segments.values_mut() {
            segment.flush_all()?;
        }
        Ok(())
    }
}
