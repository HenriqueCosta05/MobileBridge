//! Export of sessions as JSON, JSONL or a portable archive (EVT-010, SES-008).

use std::fs;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

use flate2::Compression;
use flate2::write::GzEncoder;
use serde::Serialize;

use crate::event::Event;
use crate::private_fs;
use crate::session::SessionManifest;

pub const EXPORT_FORMAT_VERSION: u32 = 1;

#[derive(Serialize)]
struct SessionDocument<'a> {
    export_format_version: u32,
    manifest: &'a SessionManifest,
    events: &'a [Event],
}

/// Writes the manifest and every event as one JSON document.
pub fn write_json(
    manifest: &SessionManifest,
    events: &[Event],
    output: impl Write,
) -> io::Result<()> {
    let document = SessionDocument {
        export_format_version: EXPORT_FORMAT_VERSION,
        manifest,
        events,
    };
    let mut output = BufWriter::new(output);
    serde_json::to_writer_pretty(&mut output, &document)?;
    writeln!(output)?;
    output.flush()
}

/// Writes one event per line.
pub fn write_jsonl<'e>(
    events: impl IntoIterator<Item = &'e Event>,
    output: impl Write,
) -> io::Result<()> {
    let mut output = BufWriter::new(output);
    for event in events {
        serde_json::to_writer(&mut output, event)?;
        writeln!(output)?;
    }
    output.flush()
}

/// Packs a whole session directory (manifest, events and raw artifacts) into a `.tar.gz` archive.
/// Entries are added in sorted order under a `<session-id>/` prefix. Refuses to overwrite `destination`.
pub fn write_archive(session_dir: &Path, session_id: &str, destination: &Path) -> io::Result<()> {
    let file = private_fs::create_new(destination)?;
    let mut archive = tar::Builder::new(GzEncoder::new(file, Compression::default()));
    for path in sorted_files(session_dir)? {
        let relative = path.strip_prefix(session_dir).map_err(io::Error::other)?;
        archive.append_path_with_name(&path, Path::new(session_id).join(relative))?;
    }
    archive.into_inner()?.finish()?.sync_all()
}

fn sorted_files(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(current) = pending.pop() {
        for entry in fs::read_dir(&current)? {
            let path = entry?.path();
            if path.is_dir() {
                pending.push(path);
            } else {
                files.push(path);
            }
        }
    }
    files.sort();
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::test_support::event_at;
    use crate::event::{Domain, Observation, kinds};
    use crate::session::SessionStore;
    use crate::session::test_support::manifest;
    use flate2::read::GzDecoder;
    use std::fs::File;

    fn events() -> Vec<Event> {
        (0..3)
            .map(|sequence| {
                event_at(
                    sequence,
                    0,
                    Observation::new(Domain::Log, kinds::LOG, "line"),
                )
            })
            .collect()
    }

    #[test]
    fn jsonl_round_trips_one_event_per_line() {
        let mut output = Vec::new();
        write_jsonl(&events(), &mut output).expect("export");
        let parsed: Vec<Event> = String::from_utf8(output)
            .expect("utf8")
            .lines()
            .map(|line| serde_json::from_str(line).expect("event"))
            .collect();
        assert_eq!(parsed, events());
    }

    #[test]
    fn json_document_contains_manifest_and_events() {
        let mut output = Vec::new();
        write_json(&manifest("s1", 0), &events(), &mut output).expect("export");
        let document: serde_json::Value = serde_json::from_slice(&output).expect("json");
        assert_eq!(document["manifest"]["id"], "s1");
        assert_eq!(document["events"].as_array().map(Vec::len), Some(3));
    }

    #[test]
    fn archive_contains_the_session_files_and_never_overwrites() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = SessionStore::new(dir.path().join("sessions"));
        let mut writer = store.create(&manifest("s1", 0)).expect("create");
        writer.append(&events()[0]).expect("append");
        fs::write(writer.artifact_dir().join("trace.bin"), b"trace").expect("artifact");
        let destination = dir.path().join("s1.tar.gz");

        write_archive(&store.session_dir("s1"), "s1", &destination).expect("archive");

        let mut archive =
            tar::Archive::new(GzDecoder::new(File::open(&destination).expect("open")));
        let names: Vec<String> = archive
            .entries()
            .expect("entries")
            .map(|entry| {
                entry
                    .expect("entry")
                    .path()
                    .expect("path")
                    .display()
                    .to_string()
            })
            .collect();
        assert_eq!(
            names,
            vec![
                "s1/artifacts/trace.bin",
                "s1/events.jsonl",
                "s1/session.json"
            ]
        );
        let second = write_archive(&store.session_dir("s1"), "s1", &destination);
        assert_eq!(
            second.map_err(|error| error.kind()),
            Err(io::ErrorKind::AlreadyExists)
        );
    }
}
