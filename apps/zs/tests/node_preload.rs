#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use zs::{NODE_PRELOAD_SOURCE, node_options_with_preload};

#[test]
fn an_absent_node_options_becomes_just_the_preload() {
    let value = node_options_with_preload(None, std::path::Path::new("/tmp/zs/preload.cjs"));
    assert_eq!(value, "--require=/tmp/zs/preload.cjs");
}

#[test]
fn an_existing_node_options_is_preserved_and_appended_to() {
    let value = node_options_with_preload(
        Some("--max-old-space-size=4096"),
        std::path::Path::new("/tmp/zs/preload.cjs"),
    );
    assert_eq!(
        value,
        "--max-old-space-size=4096 --require=/tmp/zs/preload.cjs"
    );
}

#[test]
fn a_blank_node_options_does_not_produce_a_leading_space() {
    let value = node_options_with_preload(Some("   "), std::path::Path::new("/tmp/zs/preload.cjs"));
    assert_eq!(value, "--require=/tmp/zs/preload.cjs");
}

#[test]
fn the_preload_path_is_absolute() {
    let dir = tempfile::tempdir().unwrap();
    let relative = std::path::Path::new(".zs-ca");
    std::fs::create_dir_all(dir.path().join(relative)).unwrap();
    let absolute = std::fs::canonicalize(dir.path().join(relative))
        .unwrap()
        .join("node-preload.cjs");
    let value = node_options_with_preload(None, &absolute);
    let path = value.trim_start_matches("--require=");
    assert!(
        std::path::Path::new(path).is_absolute(),
        "--require needs an absolute path, got: {path}"
    );
}

fn have_node() -> bool {
    std::process::Command::new("node")
        .arg("-v")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn plant_stub_undici(dir: &std::path::Path) {
    let module = dir.join("node_modules").join("undici");
    std::fs::create_dir_all(&module).unwrap();
    std::fs::write(
        module.join("package.json"),
        r#"{"name":"undici","version":"0.0.0-stub","main":"index.js"}"#,
    )
    .unwrap();
    std::fs::write(
        module.join("index.js"),
        r#"'use strict';
let current = { constructor: { name: 'Agent' } };
class ProxyAgent { constructor(uri) { this.uri = uri; } }
module.exports = {
  ProxyAgent,
  Agent: class Agent {},
  setGlobalDispatcher(d) { current = d; },
  getGlobalDispatcher() { return current; },
};
"#,
    )
    .unwrap();
}

fn dispatcher_after_preload(dir: &std::path::Path, proxy: Option<&str>) -> String {
    let preload = dir.join("preload.cjs");
    std::fs::write(&preload, NODE_PRELOAD_SOURCE).unwrap();
    let probe = dir.join("probe.cjs");
    std::fs::write(
        &probe,
        "const {getGlobalDispatcher}=require('undici');\
         console.log(getGlobalDispatcher().constructor.name);",
    )
    .unwrap();
    let mut cmd = std::process::Command::new("node");
    cmd.arg("--require").arg(&preload).arg(&probe);
    cmd.current_dir(dir);
    cmd.env_remove("HTTPS_PROXY").env_remove("https_proxy");
    if let Some(p) = proxy {
        cmd.env("HTTPS_PROXY", p);
    }
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "the preload must never break the process: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

#[test]
fn the_preload_installs_a_proxy_dispatcher() {
    let dir = tempfile::tempdir().unwrap();
    if !have_node() {
        eprintln!("skipping: no node");
        return;
    }
    plant_stub_undici(dir.path());
    let name = dispatcher_after_preload(dir.path(), Some("http://127.0.0.1:9"));
    assert_eq!(
        name, "ProxyAgent",
        "with HTTPS_PROXY set, undici's global dispatcher must be a ProxyAgent"
    );
}

#[test]
fn the_preload_is_inert_without_a_proxy() {
    let dir = tempfile::tempdir().unwrap();
    if !have_node() {
        eprintln!("skipping: no node");
        return;
    }
    plant_stub_undici(dir.path());
    let name = dispatcher_after_preload(dir.path(), None);
    assert_ne!(
        name, "ProxyAgent",
        "with no proxy configured the preload must not install one"
    );
}

#[test]
fn the_preload_never_breaks_a_workload_without_undici() {
    let dir = tempfile::tempdir().unwrap();
    if std::process::Command::new("node")
        .arg("-v")
        .output()
        .is_err()
    {
        eprintln!("skipping: no node");
        return;
    }
    let preload = dir.path().join("preload.cjs");
    std::fs::write(&preload, NODE_PRELOAD_SOURCE).unwrap();
    let out = std::process::Command::new("node")
        .arg("--require")
        .arg(&preload)
        .arg("-e")
        .arg("console.log('WORKLOAD_RAN')")
        .current_dir(dir.path())
        .env("HTTPS_PROXY", "http://127.0.0.1:9")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "the preload must not break a workload without undici: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("WORKLOAD_RAN"),
        "the workload must still run"
    );
}

#[test]
fn a_project_path_with_a_space_starts_node() {
    if !have_node() {
        eprintln!("skipping: no node");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join("my project");
    std::fs::create_dir_all(&project).unwrap();
    plant_stub_undici(&project);
    let preload = project.join("preload.cjs");
    std::fs::write(&preload, NODE_PRELOAD_SOURCE).unwrap();
    let options = node_options_with_preload(None, &preload);
    let probe = project.join("probe.cjs");
    std::fs::write(
        &probe,
        "const {getGlobalDispatcher}=require('undici');console.log(getGlobalDispatcher().constructor.name);",
    )
    .unwrap();

    let version = std::process::Command::new("node")
        .arg("--version")
        .env("NODE_OPTIONS", &options)
        .current_dir(&project)
        .output()
        .unwrap();
    assert!(
        version.status.success(),
        "node --version failed under NODE_OPTIONS={options:?}: {}",
        String::from_utf8_lossy(&version.stderr)
    );

    let loaded = std::process::Command::new("node")
        .arg(&probe)
        .env("NODE_OPTIONS", &options)
        .env_remove("https_proxy")
        .env("HTTPS_PROXY", "http://127.0.0.1:9")
        .current_dir(&project)
        .output()
        .unwrap();
    assert!(
        loaded.status.success(),
        "the preload did not load under NODE_OPTIONS={options:?}: {}",
        String::from_utf8_lossy(&loaded.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&loaded.stdout).trim(),
        "ProxyAgent",
        "the preload must load from a project path with a space"
    );
}

#[test]
fn the_preload_resolves_undici_from_the_workload_not_the_cwd() {
    if !have_node() {
        eprintln!("skipping: no node");
        return;
    }
    let project = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    plant_stub_undici(project.path());
    let preload = project.path().join("preload.cjs");
    std::fs::write(&preload, NODE_PRELOAD_SOURCE).unwrap();
    let probe = project.path().join("probe.cjs");
    std::fs::write(
        &probe,
        "const {getGlobalDispatcher}=require('undici');console.log(getGlobalDispatcher().constructor.name);",
    )
    .unwrap();
    let out = std::process::Command::new("node")
        .arg("--require")
        .arg(&preload)
        .arg(&probe)
        .current_dir(elsewhere.path())
        .env_remove("https_proxy")
        .env("HTTPS_PROXY", "http://127.0.0.1:9")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "ProxyAgent");
}
