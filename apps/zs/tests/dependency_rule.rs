#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

const MAP: &[&str] = &[
    "zs-vectors",
    "zs-diag",
    "zs-identity",
    "zs-credential",
    "zs-protocol",
    "zs-policy",
    "zs-grant",
    "zs-upstream",
    "zs-wire",
    "zs-proto-http",
    "zs-proto-postgres",
    "zs-proto-mysql",
    "zs-proto-mongo",
    "zs-proto-redis",
    "zs-materializer",
    "zs-audit",
    "zs-mitm",
];

const MEMBERS: &[&str] = &[
    "crates/zs-vectors",
    "crates/zs-diag",
    "crates/zs-identity",
    "crates/zs-credential",
    "crates/zs-policy",
    "crates/zs-grant",
    "crates/zs-protocol",
    "crates/zs-upstream",
    "crates/zs-wire",
    "crates/zs-proto-http",
    "crates/zs-proto-postgres",
    "crates/zs-proto-mysql",
    "crates/zs-proto-mongo",
    "crates/zs-proto-redis",
    "crates/zs-materializer",
    "crates/zs-audit",
    "crates/zs-mitm",
    "crates/zs-test-keychain",
    "crates/zs-test-idp",
    "crates/zs-test-aws",
    "crates/zs-conformance",
    "apps/zs",
    "tools/zs-verify",
];

/// Workspace members that are not published. A tree may lack them; when one is present it is
/// checked like a member of `MEMBERS`.
const PRIVATE_MEMBERS: &[&str] = &["apps/zs-control-tests"];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

/// `MEMBERS`, then each member of `PRIVATE_MEMBERS` that this tree has.
fn checked_members(root: &Path) -> Vec<&'static str> {
    MEMBERS
        .iter()
        .chain(
            PRIVATE_MEMBERS
                .iter()
                .filter(|member| root.join(member).join("Cargo.toml").exists()),
        )
        .copied()
        .collect()
}

fn path_deps(manifest: &Path) -> Vec<String> {
    let content = std::fs::read_to_string(manifest).unwrap_or_default();
    let mut out = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("zs-") {
            let name = format!("zs-{}", rest.split(['=', '.']).next().unwrap_or("").trim());
            if MAP.contains(&name.as_str())
                && (trimmed.contains("path") || trimmed.contains("workspace"))
            {
                out.push(name);
            }
        }
    }
    out
}

#[test]
fn map_is_a_topological_sort_of_the_real_graph() {
    let root = workspace_root();
    let mut violations = Vec::new();
    for (index, crate_name) in MAP.iter().enumerate() {
        let manifest = root.join("crates").join(crate_name).join("Cargo.toml");
        for dep in path_deps(&manifest) {
            let dep_index = MAP.iter().position(|m| m == &dep).unwrap();
            if dep_index >= index {
                violations.push(format!(
                    "{crate_name} (index {index}) depends on {dep} (index {dep_index}); \
                     a dependency must appear strictly earlier in MAP"
                ));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "MAP is not a topological sort:\n{}",
        violations.join("\n")
    );
}

#[test]
fn map_names_only_crates_that_exist() {
    let root = workspace_root();
    let missing: Vec<&str> = MAP
        .iter()
        .copied()
        .filter(|name| !root.join("crates").join(name).join("Cargo.toml").exists())
        .collect();
    assert!(
        missing.is_empty(),
        "MAP names crates that do not exist: {missing:?}"
    );
}

#[test]
fn every_workspace_member_is_checked() {
    let root = workspace_root();
    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).unwrap();
    let declared: Vec<String> = manifest
        .lines()
        .map(|l| l.trim().trim_end_matches(',').trim_matches('"').to_string())
        .filter(|l| l.starts_with("crates/") || l.starts_with("apps/") || l.starts_with("tools/"))
        .collect();
    let unchecked: Vec<&String> = declared
        .iter()
        .filter(|m| !MEMBERS.contains(&m.as_str()) && !PRIVATE_MEMBERS.contains(&m.as_str()))
        .collect();
    assert!(
        unchecked.is_empty(),
        "workspace members not covered by this test: {unchecked:?}"
    );

    let mut seen = declared.clone();
    seen.sort();
    let before = seen.len();
    seen.dedup();
    assert_eq!(
        before,
        seen.len(),
        "Cargo.toml lists a workspace member more than once; cargo tolerates this silently"
    );

    let mut sorted_members: Vec<&str> = MEMBERS.to_vec();
    sorted_members.sort();
    let mut declared_public: Vec<&str> = declared
        .iter()
        .map(|s| s.as_str())
        .filter(|m| !PRIVATE_MEMBERS.contains(m))
        .collect();
    declared_public.sort();
    assert_eq!(
        declared_public, sorted_members,
        "Cargo.toml members and this test's MEMBERS list have diverged"
    );
}

#[test]
fn lints_workspace_line_is_not_read_as_a_dependency() {
    let root = workspace_root();
    let manifest = root.join("crates/zs-identity/Cargo.toml");
    let content = std::fs::read_to_string(&manifest).unwrap();
    assert!(
        content.contains("workspace = true"),
        "this test is only meaningful while zs-identity carries a [lints] table"
    );
    assert!(
        path_deps(&manifest).is_empty(),
        "the bare `workspace = true` under [lints] must not parse as a zs-* dependency"
    );
}

#[test]
fn crates_only_depend_downward_and_apps_never_become_dependencies() {
    let root = workspace_root();
    let members: Vec<PathBuf> = checked_members(&root)
        .iter()
        .map(|p| root.join(p))
        .collect();

    let mut violations = Vec::new();
    for dir in &members {
        let name = dir.file_name().unwrap().to_string_lossy().into_owned();
        let manifest = dir.join("Cargo.toml");
        for dep in path_deps(&manifest) {
            if MAP.contains(&name.as_str()) {
                let own = MAP.iter().position(|m| *m == name.as_str()).unwrap();
                let dep_idx = MAP.iter().position(|m| *m == dep.as_str()).unwrap();
                if dep_idx >= own {
                    violations.push(format!(
                        "{name} depends on {dep} which is not below it in the crate map"
                    ));
                }
            }
            let dep_dir = root.join("crates").join(&dep);
            if !dep_dir.exists() {
                violations.push(format!("{name} depends on unknown crate {dep}"));
            }
        }
    }
    for dir in &members {
        let name = dir.file_name().unwrap().to_string_lossy().into_owned();
        if name.starts_with("zs-") && dir.starts_with(root.join("crates")) {
            let content = std::fs::read_to_string(dir.join("Cargo.toml")).unwrap_or_default();
            if content.contains("../apps") || content.contains("apps/zs") {
                violations.push(format!("crate {name} depends on an app"));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "dependency rule violations:\n{}",
        violations.join("\n")
    );
}

fn section_lines<'a>(manifest: &'a str, header: &str) -> Vec<&'a str> {
    manifest
        .lines()
        .map(str::trim)
        .skip_while(|line| *line != header)
        .skip(1)
        .take_while(|line| !line.starts_with('['))
        .collect()
}

fn declares_own_edition(line: &str) -> bool {
    line.strip_prefix("edition")
        .is_some_and(|rest| rest.trim_start().starts_with('='))
}

#[test]
fn every_crate_uses_the_workspace_edition_2024() {
    let root = workspace_root();
    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).unwrap();
    assert!(
        section_lines(&manifest, "[workspace.package]").contains(&"edition = \"2024\""),
        "[workspace.package] in the root Cargo.toml must set edition = \"2024\""
    );

    let mut violations = Vec::new();
    for member in checked_members(&root) {
        let content = std::fs::read_to_string(root.join(member).join("Cargo.toml")).unwrap();
        let lines = section_lines(&content, "[package]");
        if !lines.contains(&"edition.workspace = true") {
            violations.push(format!("{member} does not set edition.workspace = true"));
        }
        if lines.iter().any(|line| declares_own_edition(line)) {
            violations.push(format!("{member} declares its own edition"));
        }
    }
    assert!(
        violations.is_empty(),
        "crates must inherit the workspace edition:\n{}",
        violations.join("\n")
    );
}

#[test]
fn dependency_rule_refuses_zs_test_crates_in_normal_dependencies() {
    let root = workspace_root();
    let mut violations = Vec::new();
    for member in checked_members(&root) {
        let manifest = root.join(member).join("Cargo.toml");
        let Ok(content) = std::fs::read_to_string(&manifest) else {
            continue;
        };
        let mut section = String::new();
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                section = trimmed.to_string();
                continue;
            }
            if trimmed.starts_with("zs-test-") && !section.contains("dev-dependencies") {
                violations.push(format!("{member} {section}: {trimmed}"));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "zs-test crates must appear only in dev-dependencies:\n{}",
        violations.join("\n")
    );
}

#[test]
fn dependency_rule_refuses_a_cargo_config_env_that_sets_the_build_variable() {
    let path = workspace_root().join(".cargo/config.toml");
    let Ok(content) = std::fs::read_to_string(path) else {
        return;
    };
    let mut in_env = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_env = trimmed == "[env]";
            continue;
        }
        if in_env
            && trimmed
                .to_ascii_uppercase()
                .starts_with("ZS_BUILD_TEST_ENDPOINTS")
        {
            panic!(".cargo/config.toml [env] sets ZS_BUILD_TEST_ENDPOINTS: {trimmed}");
        }
    }
}
