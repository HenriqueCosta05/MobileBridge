//! Parsing of `pm list packages` (APP-001, APP-003).

use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InstalledPackage {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_code: Option<u64>,
}

/// Parses lines such as `package:com.example versionCode:42 uid:10123`.
pub fn parse_package_list(output: &str) -> Vec<InstalledPackage> {
    let mut packages: Vec<InstalledPackage> =
        output.lines().filter_map(parse_package_line).collect();
    packages.sort_by(|a, b| a.name.cmp(&b.name));
    packages
}

fn parse_package_line(line: &str) -> Option<InstalledPackage> {
    let mut tokens = line.split_whitespace();
    let name = tokens.next()?.strip_prefix("package:")?.to_string();
    let mut package = InstalledPackage {
        name,
        uid: None,
        version_code: None,
    };
    for token in tokens {
        if let Some(uid) = token.strip_prefix("uid:") {
            // Packages sharing a user id list several, comma separated; the first is the package's own.
            package.uid = uid.split(',').next().and_then(|value| value.parse().ok());
        } else if let Some(version) = token.strip_prefix("versionCode:") {
            package.version_code = version.parse().ok();
        }
    }
    Some(package)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_names_uids_and_versions_sorted_by_name() {
        let output = "package:com.zeta versionCode:7 uid:10200\npackage:com.alpha uid:1000,10001\n";
        let packages = parse_package_list(output);
        assert_eq!(packages[0].name, "com.alpha");
        assert_eq!(packages[0].uid, Some(1000));
        assert_eq!(packages[0].version_code, None);
        assert_eq!(packages[1].version_code, Some(7));
    }

    #[test]
    fn ignores_lines_that_are_not_packages() {
        assert!(parse_package_list("Error: unknown option\n\n").is_empty());
    }
}
