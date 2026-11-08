//! Pure parsers for the text output of Android device tools. They never touch a device, so they are
//! tested against captured fixtures.

pub mod devices;
pub mod logcat;
pub mod packages;
pub mod permissions;
pub mod processes;
pub mod properties;
