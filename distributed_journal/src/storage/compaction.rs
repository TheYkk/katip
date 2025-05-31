use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq)] // Added PartialEq
pub enum CompactionPolicy {
    Disabled,
    RetainMinSegments(usize), // Keep at least N segments
    RetainTotalSize(u64),   // Keep total log size under X bytes (approx)
    RetainDuration(Duration), // Keep segments younger than X duration
}

impl Default for CompactionPolicy {
    fn default() -> Self {
        CompactionPolicy::Disabled
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CompactionOptions {
    pub policy: CompactionPolicy,
    // pub target_segment_size: Option<u64>, // For future actual compaction
    // pub cleanup_interval: Option<Duration>, // For periodic triggering
}
