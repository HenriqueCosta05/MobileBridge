//! Parsing of `ps` output (APP-002, APP-004) and of `/proc` samples (MON-004).

use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProcessInfo {
    pub pid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ppid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    pub name: String,
}

/// Parses `ps` output using its header, so both toybox (`ps -A -o PID,PPID,USER,NAME`, Android 8+)
/// and legacy toolbox `ps` layouts work. The process name is always the last column.
pub fn parse_process_list(output: &str) -> Vec<ProcessInfo> {
    let mut lines = output.lines().filter(|line| !line.trim().is_empty());
    let Some(header) = lines.next() else {
        return Vec::new();
    };
    let columns: Vec<&str> = header.split_whitespace().collect();
    let position = |name: &str| columns.iter().position(|column| *column == name);
    let Some(pid_column) = position("PID") else {
        return Vec::new();
    };
    let ppid_column = position("PPID");
    let user_column = position("USER");

    lines
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let field = |index: Option<usize>| index.and_then(|index| fields.get(index).copied());
            Some(ProcessInfo {
                pid: field(Some(pid_column))?.parse().ok()?,
                ppid: field(ppid_column).and_then(|value| value.parse().ok()),
                user: field(user_column).map(str::to_string),
                name: (*fields.last()?).to_string(),
            })
        })
        .collect()
}

/// CPU time and memory of one process at one instant.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ProcessSample {
    pub pid: u32,
    /// User plus system CPU time, in clock ticks.
    pub cpu_ticks: u64,
    pub threads: Option<u32>,
    pub rss_kb: Option<u64>,
}

/// Samples taken together with the device uptime, so CPU usage can be derived between two samples.
#[derive(Debug, Clone, PartialEq)]
pub struct ResourceSnapshot {
    pub uptime_seconds: f64,
    pub samples: Vec<ProcessSample>,
    /// Processes whose `/proc` entries could not be read (exited, or not accessible).
    pub unreadable: Vec<u32>,
}

/// Separator printed before each process section by the sampling command.
pub const SECTION_PREFIX: &str = "@pid ";

/// Shell command producing the input of [`parse_resource_snapshot`]. Only integers are interpolated.
pub fn resource_sampling_command(pids: &[u32]) -> String {
    let pids: Vec<String> = pids.iter().map(u32::to_string).collect();
    format!(
        "cat /proc/uptime; for p in {}; do echo \"{SECTION_PREFIX}$p\"; cat /proc/$p/stat 2>/dev/null; \
         grep -E '^VmRSS:' /proc/$p/status 2>/dev/null; done",
        pids.join(" ")
    )
}

pub fn parse_resource_snapshot(output: &str) -> Option<ResourceSnapshot> {
    let mut lines = output.lines();
    let uptime_seconds = lines.next()?.split_whitespace().next()?.parse().ok()?;
    let mut snapshot = ResourceSnapshot {
        uptime_seconds,
        samples: Vec::new(),
        unreadable: Vec::new(),
    };
    let mut current: Option<(u32, Option<ProcessSample>)> = None;
    for line in lines {
        if let Some(pid) = line.strip_prefix(SECTION_PREFIX) {
            finish_section(&mut snapshot, current.take());
            current = pid.trim().parse().ok().map(|pid| (pid, None));
        } else if let Some((pid, sample)) = current.as_mut() {
            if let Some(rss) = line.strip_prefix("VmRSS:") {
                if let Some(sample) = sample.as_mut() {
                    sample.rss_kb = rss.split_whitespace().next().and_then(|kb| kb.parse().ok());
                }
            } else if sample.is_none() {
                *sample = parse_stat_line(*pid, line);
            }
        }
    }
    finish_section(&mut snapshot, current);
    Some(snapshot)
}

fn finish_section(snapshot: &mut ResourceSnapshot, section: Option<(u32, Option<ProcessSample>)>) {
    match section {
        Some((_, Some(sample))) => snapshot.samples.push(sample),
        Some((pid, None)) => snapshot.unreadable.push(pid),
        None => {}
    }
}

/// Parses `/proc/<pid>/stat`. The command name may contain spaces and parentheses, so fields are
/// counted from the last `)`. Field numbers below follow proc(5).
fn parse_stat_line(pid: u32, line: &str) -> Option<ProcessSample> {
    let after_name = &line[line.rfind(')')? + 1..];
    let fields: Vec<&str> = after_name.split_whitespace().collect();
    // fields[0] is field 3 (state), so field N is at index N - 3.
    let field = |number: usize| {
        fields
            .get(number - 3)
            .and_then(|value| value.parse::<u64>().ok())
    };
    let user_ticks = field(14)?;
    let system_ticks = field(15)?;
    Some(ProcessSample {
        pid,
        cpu_ticks: user_ticks + system_ticks,
        threads: field(20).and_then(|threads| u32::try_from(threads).ok()),
        rss_kb: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_toybox_ps_output() {
        let output = "\
  PID  PPID USER           NAME
    1     0 root           init
12345   678 u0_a123        com.example
12400   678 u0_a123        com.example:remote
";
        let processes = parse_process_list(output);
        assert_eq!(processes.len(), 3);
        assert_eq!(processes[1].pid, 12345);
        assert_eq!(processes[1].ppid, Some(678));
        assert_eq!(processes[1].user.as_deref(), Some("u0_a123"));
        assert_eq!(processes[2].name, "com.example:remote");
    }

    #[test]
    fn parses_legacy_toolbox_ps_output_with_an_unlabeled_state_column() {
        let output = "\
USER     PID   PPID  VSIZE  RSS     WCHAN    PC        NAME
root      1     0     8904   780   ffffffff 00000000 S /init
u0_a77    2345  190   912344 61200 ffffffff 00000000 S com.example
";
        let processes = parse_process_list(output);
        assert_eq!(processes[1].pid, 2345);
        assert_eq!(processes[1].name, "com.example");
    }

    #[test]
    fn output_without_a_pid_header_yields_nothing() {
        assert!(parse_process_list("bad option -A\n").is_empty());
    }

    #[test]
    fn sampling_command_only_contains_integers_and_constants() {
        assert_eq!(
            resource_sampling_command(&[12, 34]),
            "cat /proc/uptime; for p in 12 34; do echo \"@pid $p\"; cat /proc/$p/stat 2>/dev/null; \
             grep -E '^VmRSS:' /proc/$p/status 2>/dev/null; done"
        );
    }

    #[test]
    fn parses_resource_snapshots_and_reports_unreadable_processes() {
        let output = "\
3600.50 7000.00
@pid 12345
12345 (com.example) S 678 678 0 0 -1 1077952832 1000 0 0 0 250 50 0 0 10 -10 42 0 900 1000000 5000
VmRSS:\t  81234 kB
@pid 999
";
        let snapshot = parse_resource_snapshot(output).expect("snapshot");
        assert!((snapshot.uptime_seconds - 3600.5).abs() < f64::EPSILON);
        assert_eq!(
            snapshot.samples,
            vec![ProcessSample {
                pid: 12345,
                cpu_ticks: 300,
                threads: Some(42),
                rss_kb: Some(81234),
            }]
        );
        assert_eq!(snapshot.unreadable, vec![999]);
    }

    #[test]
    fn stat_lines_with_parentheses_in_the_name_parse_correctly() {
        let line = "77 (Binder:77 (x)) S 1 1 0 0 -1 0 0 0 0 0 10 5 0 0 20 0 3 0 1 1 1";
        let sample = parse_stat_line(77, line).expect("sample");
        assert_eq!(sample.cpu_ticks, 15);
        assert_eq!(sample.threads, Some(3));
    }
}
