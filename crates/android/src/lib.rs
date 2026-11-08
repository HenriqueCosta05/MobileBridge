//! Android platform adapter: device access through adb and the Android instrumentation providers.
//!
//! Everything works on non-rooted devices with USB debugging enabled (AND-007, NFR-011).

pub mod adapter;
pub mod adb;
pub mod package;
pub mod parse;
pub mod providers;

pub use adapter::{AndroidAdapter, AndroidDevice, PackageScope};
pub use adb::{Adb, AdbError};
pub use package::PackageName;
