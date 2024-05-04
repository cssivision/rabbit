use std::time::Duration;

pub use crate::copy::copy_bidirectional;
pub use crate::read_exact::read_exact;
pub use crate::write_all::write_all;

pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
pub const DEFAULT_CHECK_INTERVAL: Duration = Duration::from_secs(3);
