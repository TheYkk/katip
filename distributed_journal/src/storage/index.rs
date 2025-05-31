// src/storage/index.rs
use bincode;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexEntry {
    pub relative_offset: u64,
    pub position: u64,
}

pub struct Index {
    pub(crate) file_path: PathBuf,
    file: File,
    entries: Vec<IndexEntry>,
    entry_size: usize,
}

impl Index {
    pub fn new<P: AsRef<Path>>(dir: P, segment_base_offset: u64) -> io::Result<Self> {
        let file_path = dir.as_ref().join(format!("{}.index", segment_base_offset));
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&file_path)?;

        let dummy_entry = IndexEntry {
            relative_offset: 0,
            position: 0,
        };
        let entry_size = bincode::serialized_size(&dummy_entry).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to get serialized size of IndexEntry: {}", e),
            )
        })? as usize;

        if entry_size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "IndexEntry serialized size is zero, cannot proceed.",
            ));
        }

        Ok(Index {
            file_path,
            file,
            entries: Vec::new(),
            entry_size,
        })
    }

    pub fn load(&mut self) -> io::Result<()> {
        self.file.seek(SeekFrom::Start(0))?;
        self.entries.clear();

        if self.entry_size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "entry_size is 0, cannot load index",
            ));
        }

        // Explicitly define the u8 value to avoid potential parsing issues with 0u8 directly in vec! macro
        let zero_fill_value: u8 = 0;
        let mut entry_buf = vec![zero_fill_value; self.entry_size];

        loop {
            match self.file.read_exact(&mut entry_buf) {
                Ok(_) => match bincode::deserialize(&entry_buf) {
                    Ok(entry) => self.entries.push(entry),
                    Err(e) => {
                        eprintln!("Warning: Failed to deserialize index entry from {:?}. Error: {:?}. Assuming end of valid entries.", self.file_path, e);
                        break;
                    }
                },
                Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    pub fn add_entry(&mut self, relative_offset: u64, position: u64) -> io::Result<()> {
        let entry = IndexEntry {
            relative_offset,
            position,
        };
        let encoded: Vec<u8> =
            bincode::serialize(&entry).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        if encoded.len() != self.entry_size {
            return Err(io::Error::new(io::ErrorKind::Other,
                format!("Serialized IndexEntry size mismatch for {:?}. Expected {}, got {}. Entry: {:?}", self.file_path, self.entry_size, encoded.len(), entry)));
        }

        self.file.write_all(&encoded)?;
        self.entries.push(entry);
        Ok(())
    }

    pub fn find_position(&self, target_relative_offset: u64) -> Option<u64> {
        match self
            .entries
            .binary_search_by_key(&target_relative_offset, |e| e.relative_offset)
        {
            Ok(idx) => Some(self.entries[idx].position),
            Err(_) => None,
        }
    }

    #[allow(dead_code)]
    pub fn find_position_for_scan(&self, target_relative_offset: u64) -> Option<u64> {
        if self.entries.is_empty() {
            return None;
        }
        match self
            .entries
            .binary_search_by_key(&target_relative_offset, |e| e.relative_offset)
        {
            Ok(idx) => Some(self.entries[idx].position),
            Err(idx) => {
                if idx > 0 {
                    Some(self.entries[idx - 1].position)
                } else {
                    None
                }
            }
        }
    }

    #[allow(dead_code)]
    pub fn get_entry_count(&self) -> usize {
        self.entries.len()
    }
    pub fn get_last_relative_offset(&self) -> Option<u64> {
        self.entries.last().map(|e| e.relative_offset)
    }
    pub fn sync_all(&mut self) -> io::Result<()> {
        self.file.sync_all()
    }
}
