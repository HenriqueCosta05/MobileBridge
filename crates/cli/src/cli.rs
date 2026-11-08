//! Command-line grammar (CLI-001). Commands are `noun verb` pairs; global options apply everywhere.

use std::path::PathBuf;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;
use mobile_bridge_core::event::{Domain, Severity};

#[derive(Debug, Parser)]
#[command(
    name = "mobile-bridge",
    version,
    about = "Record and analyze OS-level diagnostic evidence from physical mobile devices",
    long_about = "Record and analyze OS-level diagnostic evidence from physical mobile devices.\n\n\
        Data stays on this computer: sessions are stored locally and nothing is uploaded.",
    after_help = "Start with 'mobile-bridge doctor' to check the host and the connected device."
)]
pub struct Cli {
    #[command(flatten)]
    pub global: GlobalOptions,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Args)]
pub struct GlobalOptions {
    /// Serial of the device to use (see 'devices list'); required when several are connected
    #[arg(short, long, global = true, env = "MOBILE_BRIDGE_DEVICE")]
    pub device: Option<String>,
    /// Output format
    #[arg(long, global = true, value_enum, default_value_t = OutputFormat::Human)]
    pub format: OutputFormat,
    /// Directory where sessions are stored
    #[arg(long, global = true, env = "MOBILE_BRIDGE_DATA_DIR")]
    pub data_dir: Option<PathBuf>,
    /// Configuration file (default: the user configuration directory's mobile-bridge/config.toml)
    #[arg(long, global = true, env = "MOBILE_BRIDGE_CONFIG")]
    pub config: Option<PathBuf>,
    /// Never prompt or read from standard input (implied when stdin is not a terminal)
    #[arg(long, global = true)]
    pub no_input: bool,
    /// Print diagnostic messages about mobile-bridge itself to stderr
    #[arg(short, long, global = true)]
    pub verbose: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Human,
    Json,
    Jsonl,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Check the host setup, adb and the connected device
    Doctor,
    /// Discover and inspect devices
    #[command(subcommand)]
    Devices(DevicesCommand),
    /// Discover applications and processes
    #[command(subcommand)]
    Apps(AppsCommand),
    /// Record a diagnostic session
    Record(RecordArgs),
    /// Inspect, analyze, export and delete recorded sessions
    #[command(subcommand)]
    Sessions(SessionsCommand),
    /// Print a shell completion script
    Completions {
        #[arg(value_enum)]
        shell: Shell,
    },
}

#[derive(Debug, Subcommand)]
pub enum DevicesCommand {
    /// List connected devices and their authorization state
    List {
        /// Keep running and report connections, disconnections and state changes
        #[arg(long)]
        watch: bool,
    },
    /// Show metadata and instrumentation capabilities of a device
    Show {
        /// Also check capabilities that need a target application
        #[arg(long)]
        app: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum AppsCommand {
    /// List installed applications
    List {
        /// Only applications installed by the user (exclude system apps)
        #[arg(long)]
        third_party: bool,
        /// Only applications with at least one running process
        #[arg(long)]
        running: bool,
        /// Only package names containing this text
        #[arg(long)]
        filter: Option<String>,
    },
    /// List running processes
    Processes {
        /// Only processes belonging to this application
        #[arg(long)]
        app: Option<String>,
    },
}

#[derive(Debug, Args)]
pub struct RecordArgs {
    /// Package name of the application to investigate
    #[arg(short, long)]
    pub app: Option<String>,
    /// Stop after this long (for example 30s, 5m, 1h); without it, stop with Ctrl-C
    #[arg(short = 't', long, value_parser = parse_duration)]
    pub duration: Option<Duration>,
    /// Collectors to run, comma separated [default: all available]
    #[arg(long, value_delimiter = ',', value_name = "COLLECTOR")]
    pub collectors: Vec<String>,
    /// Human-friendly label for the session
    #[arg(long)]
    pub name: Option<String>,
    /// Keep log lines of every process, not only those of the target application
    #[arg(long)]
    pub all_logs: bool,
    /// Store values as collected, without redacting credentials, tokens or e-mail addresses
    #[arg(long)]
    pub no_redact: bool,
    /// Do not print events while recording
    #[arg(long)]
    pub no_stream: bool,
    /// Only print events of at least this severity while recording (all are still saved)
    #[arg(long)]
    pub stream_severity: Option<Severity>,
    /// How often processes, CPU and memory are sampled
    #[arg(long, value_parser = parse_duration)]
    pub sample_interval: Option<Duration>,
}

#[derive(Debug, Subcommand)]
pub enum SessionsCommand {
    /// List recorded sessions
    List,
    /// Show the metadata of a session
    Show { session: String },
    /// Print the events of a session in collection order
    Events {
        session: String,
        #[command(flatten)]
        filter: FilterArgs,
    },
    /// Print the events of a session in chronological order
    Timeline {
        session: String,
        #[command(flatten)]
        filter: FilterArgs,
    },
    /// Report crashes, ANRs and collection gaps, with the events that support them
    Analyze { session: String },
    /// Export a session for sharing or archiving
    Export {
        session: String,
        /// Export format
        #[arg(long = "as", value_enum, default_value_t = ExportFormat::Archive)]
        export_format: ExportFormat,
        /// Destination file
        #[arg(short, long)]
        output: PathBuf,
        /// Replace the destination if it exists (json and jsonl only)
        #[arg(long)]
        force: bool,
    },
    /// Permanently delete a session and its artifacts
    Delete {
        session: String,
        /// Do not ask for confirmation
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ExportFormat {
    /// Manifest, events and raw artifacts in a .tar.gz archive
    Archive,
    /// Manifest and events as one JSON document
    Json,
    /// Events only, one JSON object per line
    Jsonl,
}

/// Event filters shared by event-listing commands (EVT-007, MON-013).
#[derive(Debug, Args, Default)]
pub struct FilterArgs {
    /// Only events of this application (repeatable)
    #[arg(long = "app")]
    pub apps: Vec<String>,
    /// Only events of this process id (repeatable)
    #[arg(long = "pid")]
    pub pids: Vec<u32>,
    /// Only events with this subsystem, such as a logcat tag (repeatable)
    #[arg(long = "subsystem", alias = "tag")]
    pub subsystems: Vec<String>,
    /// Only events in this domain (repeatable)
    #[arg(long = "domain")]
    pub domains: Vec<Domain>,
    /// Only events of this kind, such as app_crash (repeatable)
    #[arg(long = "kind")]
    pub kinds: Vec<String>,
    /// Only events of at least this severity
    #[arg(long)]
    pub min_severity: Option<Severity>,
    /// Only events whose message contains this text (case-insensitive)
    #[arg(long)]
    pub grep: Option<String>,
    /// Print at most this many events
    #[arg(long)]
    pub limit: Option<usize>,
}

/// Upper bound for durations, far beyond any useful recording and safe for time arithmetic.
const MAX_DURATION: Duration = Duration::from_secs(30 * 86_400);

/// Parses `90`, `90s`, `500ms`, `5m` or `1h`. A bare number means seconds.
pub fn parse_duration(text: &str) -> Result<Duration, String> {
    let text = text.trim();
    let split = text
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(text.len());
    let (number, unit) = text.split_at(split);
    let value: u64 = number
        .parse()
        .map_err(|_| format!("'{text}' is not a duration (examples: 30s, 5m, 1h)"))?;
    let seconds_per_unit = match unit {
        "ms" => None,
        "" | "s" => Some(1),
        "m" => Some(60),
        "h" => Some(3600),
        _ => {
            return Err(format!(
                "unknown duration unit '{unit}' (use ms, s, m or h)"
            ));
        }
    };
    let duration = match seconds_per_unit {
        None => Some(Duration::from_millis(value)),
        Some(factor) => value.checked_mul(factor).map(Duration::from_secs),
    };
    match duration {
        Some(duration) if duration.is_zero() => {
            Err("the duration must be greater than zero".to_string())
        }
        Some(duration) if duration <= MAX_DURATION => Ok(duration),
        _ => Err(format!(
            "'{text}' is longer than the maximum of {} days",
            MAX_DURATION.as_secs() / 86_400
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn the_command_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn durations_accept_common_units() {
        assert_eq!(parse_duration("90"), Ok(Duration::from_secs(90)));
        assert_eq!(parse_duration("500ms"), Ok(Duration::from_millis(500)));
        assert_eq!(parse_duration("5m"), Ok(Duration::from_secs(300)));
        assert_eq!(parse_duration("1h"), Ok(Duration::from_secs(3600)));
    }

    #[test]
    fn durations_reject_zero_unknown_units_and_garbage() {
        assert!(parse_duration("0s").is_err());
        assert!(parse_duration("5d").is_err());
        assert!(parse_duration("soon").is_err());
        assert!(parse_duration("99999999999999999h").is_err());
        assert!(parse_duration("31d").is_err());
        assert!(parse_duration("744h").is_err());
    }

    #[test]
    fn global_options_are_accepted_after_the_subcommand() {
        let cli = Cli::try_parse_from(["mobile-bridge", "sessions", "list", "--format", "json"])
            .expect("parse");
        assert_eq!(cli.global.format, OutputFormat::Json);
    }
}
