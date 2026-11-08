//! Parsing of logcat lines (AND-003, MON-005).
//!
//! Collection uses `logcat -v threadtime -v epoch` on Android 7+ (API 24), which gives an unambiguous UTC
//! timestamp. Older releases only support `threadtime`, whose timestamp is device-local time without a
//! year or zone; it is kept as text and no device time is claimed for it.

use std::sync::LazyLock;

use chrono::{DateTime, Utc};
use mobile_bridge_core::event::Severity;
use regex::{Captures, Regex};

#[derive(Debug, Clone, PartialEq)]
pub struct LogRecord {
    pub time: LogTime,
    pub pid: u32,
    pub tid: u32,
    pub severity: Severity,
    pub tag: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum LogTime {
    Utc(DateTime<Utc>),
    /// `MM-DD HH:MM:SS.mmm` in the device's local time zone.
    DeviceLocal(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum LogLine {
    Record(LogRecord),
    /// `--------- beginning of main` and similar buffer headers.
    BufferStart(String),
    Unrecognized,
}

static EPOCH_LINE: LazyLock<Regex> = LazyLock::new(|| {
    compiled(r"^\s*(\d+)\.(\d+)\s+(\d+)\s+(\d+)\s+([VDIWEFS])\s+(.*?)\s*:(?: (.*))?$")
});
static THREADTIME_LINE: LazyLock<Regex> = LazyLock::new(|| {
    compiled(
        r"^(\d\d-\d\d \d\d:\d\d:\d\d\.\d+)\s+(\d+)\s+(\d+)\s+([VDIWEFS])\s+(.*?)\s*:(?: (.*))?$",
    )
});

/// Patterns are constants covered by tests, so failing to compile one is a programming error.
fn compiled(pattern: &str) -> Regex {
    Regex::new(pattern)
        .unwrap_or_else(|error| panic!("invalid built-in pattern {pattern}: {error}"))
}

pub fn parse_log_line(line: &str) -> LogLine {
    let line = line.trim_end_matches(['\r', '\n']);
    if let Some(buffer) = line.strip_prefix("--------- beginning of ") {
        return LogLine::BufferStart(buffer.trim().to_string());
    }
    parse_epoch_line(line)
        .or_else(|| parse_threadtime_line(line))
        .map_or(LogLine::Unrecognized, LogLine::Record)
}

fn parse_epoch_line(line: &str) -> Option<LogRecord> {
    let captures = EPOCH_LINE.captures(line)?;
    let seconds: i64 = captures[1].parse().ok()?;
    let time = DateTime::from_timestamp(seconds, fraction_to_nanos(&captures[2]))?;
    record_from(&captures, LogTime::Utc(time), 3)
}

fn parse_threadtime_line(line: &str) -> Option<LogRecord> {
    let captures = THREADTIME_LINE.captures(line)?;
    record_from(&captures, LogTime::DeviceLocal(captures[1].to_string()), 2)
}

/// Builds a record from the pid, tid, level, tag and message groups, which start at `first_group`.
fn record_from(captures: &Captures<'_>, time: LogTime, first_group: usize) -> Option<LogRecord> {
    let group = |offset: usize| {
        captures
            .get(first_group + offset)
            .map_or("", |m| m.as_str())
    };
    Some(LogRecord {
        time,
        pid: group(0).parse().ok()?,
        tid: group(1).parse().ok()?,
        // Logcat's level letters match the severity letters; `S` (silent) is treated as verbose.
        severity: group(2).parse().unwrap_or(Severity::Verbose),
        tag: group(3).to_string(),
        message: group(4).to_string(),
    })
}

/// Converts the digits after the decimal point (milliseconds or microseconds) to nanoseconds.
fn fraction_to_nanos(fraction: &str) -> u32 {
    fraction
        .bytes()
        .chain(std::iter::repeat(b'0'))
        .take(9)
        .fold(0, |nanos, digit| {
            nanos * 10 + u32::from(digit.wrapping_sub(b'0')).min(9)
        })
}

/// Fields of an event-log entry such as `am_proc_start: [0,1234,10123,com.example,activity,{...}]`.
/// Splits on commas; fields after free-text ones (exception messages) may be split further, so callers
/// only rely on leading positions.
pub fn event_log_fields(message: &str) -> Vec<&str> {
    let inner = message.trim().trim_start_matches('[').trim_end_matches(']');
    inner.split(',').map(str::trim).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(line: &str) -> LogRecord {
        match parse_log_line(line) {
            LogLine::Record(record) => record,
            other => panic!("expected a record, got {other:?}"),
        }
    }

    #[test]
    fn parses_epoch_lines_with_utc_time() {
        let parsed = record("1700000000.123  1234  1240 W ActivityManager: Slow operation: 120ms");
        assert_eq!(
            parsed.time,
            LogTime::Utc(DateTime::from_timestamp(1_700_000_000, 123_000_000).expect("time"))
        );
        assert_eq!((parsed.pid, parsed.tid), (1234, 1240));
        assert_eq!(parsed.severity, Severity::Warning);
        assert_eq!(parsed.tag, "ActivityManager");
        assert_eq!(parsed.message, "Slow operation: 120ms");
    }

    #[test]
    fn keeps_padded_tags_and_microsecond_precision() {
        let parsed =
            record("  1700000000.123456   77    77 E chromium    : [ERROR:x.cc(1)] failed");
        assert_eq!(parsed.tag, "chromium");
        assert_eq!(parsed.message, "[ERROR:x.cc(1)] failed");
        let LogTime::Utc(time) = parsed.time else {
            panic!("utc time expected")
        };
        assert_eq!(time.timestamp_subsec_nanos(), 123_456_000);
    }

    #[test]
    fn accepts_empty_messages() {
        assert_eq!(record("1700000000.000  1  1 I Tag:").message, "");
    }

    #[test]
    fn legacy_lines_keep_device_local_time_as_text() {
        let parsed = record("02-14 10:15:30.250  1234  1240 I MyApp: hello");
        assert_eq!(
            parsed.time,
            LogTime::DeviceLocal("02-14 10:15:30.250".into())
        );
        assert_eq!(parsed.message, "hello");
    }

    #[test]
    fn recognizes_buffer_headers_and_rejects_garbage() {
        assert_eq!(
            parse_log_line("--------- beginning of crash"),
            LogLine::BufferStart("crash".into())
        );
        assert_eq!(
            parse_log_line("read: unexpected EOF!"),
            LogLine::Unrecognized
        );
    }

    #[test]
    fn splits_event_log_fields() {
        assert_eq!(
            event_log_fields("[0,5678,10123,com.example,activity,{com.example/.Main}]"),
            [
                "0",
                "5678",
                "10123",
                "com.example",
                "activity",
                "{com.example/.Main}"
            ]
        );
    }
}
