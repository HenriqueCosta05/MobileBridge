//! Parsing of permission state from `dumpsys package <name>` (MON-003).

use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PermissionKind {
    /// Granted at install time (normal and signature permissions).
    Install,
    /// Granted by the user at runtime (dangerous permissions).
    Runtime,
}

impl PermissionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Runtime => "runtime",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionState {
    pub kind: PermissionKind,
    pub granted: bool,
}

/// Permission name to state, as listed in the "install permissions" and "runtime permissions" sections.
pub type PermissionTable = BTreeMap<String, PermissionState>;

pub fn parse_permissions(dumpsys_package: &str) -> PermissionTable {
    let mut table = PermissionTable::new();
    let mut section: Option<PermissionKind> = None;
    for line in dumpsys_package.lines().map(str::trim) {
        match line {
            "install permissions:" => section = Some(PermissionKind::Install),
            "runtime permissions:" => section = Some(PermissionKind::Runtime),
            _ => {
                let Some(kind) = section else { continue };
                match parse_grant_line(line) {
                    Some((name, granted)) => {
                        table.insert(name.to_string(), PermissionState { kind, granted });
                    }
                    None => section = None,
                }
            }
        }
    }
    table
}

/// Parses `android.permission.CAMERA: granted=false, flags=[ USER_SET ]`.
fn parse_grant_line(line: &str) -> Option<(&str, bool)> {
    let (name, rest) = line.split_once(": granted=")?;
    let granted = rest.starts_with("true");
    Some((name, granted))
}

/// A permission whose state differs between two snapshots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionChange {
    pub name: String,
    pub before: Option<PermissionState>,
    pub after: Option<PermissionState>,
}

pub fn permission_changes(
    before: &PermissionTable,
    after: &PermissionTable,
) -> Vec<PermissionChange> {
    let mut names: Vec<&String> = before.keys().chain(after.keys()).collect();
    names.sort();
    names.dedup();
    names
        .into_iter()
        .filter(|name| before.get(*name) != after.get(*name))
        .map(|name| PermissionChange {
            name: name.clone(),
            before: before.get(name).cloned(),
            after: after.get(name).cloned(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const DUMPSYS: &str = "\
Packages:
  Package [com.example] (a1b2c3):
    requested permissions:
      android.permission.INTERNET
      android.permission.CAMERA
    install permissions:
      android.permission.INTERNET: granted=true
    User 0: ceDataInode=123 installed=true
      runtime permissions:
        android.permission.CAMERA: granted=false, flags=[ USER_SET|USER_SENSITIVE_WHEN_GRANTED ]
        android.permission.POST_NOTIFICATIONS: granted=true, flags=[ USER_SET ]
      disabledComponents:
";

    #[test]
    fn reads_install_and_runtime_grants() {
        let table = parse_permissions(DUMPSYS);
        assert_eq!(table.len(), 3);
        assert_eq!(
            table["android.permission.INTERNET"],
            PermissionState {
                kind: PermissionKind::Install,
                granted: true
            }
        );
        assert_eq!(
            table["android.permission.CAMERA"],
            PermissionState {
                kind: PermissionKind::Runtime,
                granted: false
            }
        );
    }

    #[test]
    fn requested_permissions_without_grant_state_are_not_reported() {
        let table =
            parse_permissions("    requested permissions:\n      android.permission.CAMERA\n");
        assert!(table.is_empty());
    }

    #[test]
    fn detects_granted_revoked_and_added_permissions() {
        let before = parse_permissions(DUMPSYS);
        let after_text = DUMPSYS
            .replace("CAMERA: granted=false", "CAMERA: granted=true")
            .replace(
                "        android.permission.POST_NOTIFICATIONS: granted=true, flags=[ USER_SET ]\n",
                "",
            );
        let changes = permission_changes(&before, &parse_permissions(&after_text));
        let names: Vec<&str> = changes.iter().map(|change| change.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "android.permission.CAMERA",
                "android.permission.POST_NOTIFICATIONS"
            ]
        );
        assert_eq!(changes[1].after, None);
    }
}
