#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Golden vector files.
//!
//! One format, one index, and one meta-check. A crate that owns behaviour worth pinning
//! exports it as a file next to its `vectors/` directory; the same file is read by every
//! implementation that must agree on the bytes.
//!
//! ```json
//! {"about": "...", "version": 1, "frozen": false, "context": {}, "cases": [
//!   {"name": "...", "input": {}, "expect": {}}
//! ]}
//! ```
//!
//! `INDEX.json` lists every file and its case count, so a file cannot be added or lose a
//! case without the index changing. `ZS_VECTORS_WRITE=1` fills each `expect` from the
//! runner; a file with `"frozen": true` panics instead when an `expect` would change.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde_json::{Map, Value};

/// One file and the function that decides its cases.
///
/// `case` receives the file's `context` and the case's `input`, and returns the value the
/// file must hold as `expect`. A wrong value, a missing file, a stale index or a file with
/// no runner panics.
pub struct Runner {
    pub file: &'static str,
    pub case: fn(context: &Value, input: &Value) -> Value,
}

struct Case {
    name: String,
    input: Value,
    expect: Value,
}

struct VectorFile {
    about: String,
    frozen: bool,
    context: Value,
    cases: Vec<Case>,
}

const KEYS: [&str; 5] = ["about", "version", "frozen", "context", "cases"];
const CASE_KEYS: [&str; 3] = ["name", "input", "expect"];

/// Checks every file in `dir` against `runners`, and the index against the files.
///
/// Panics on the first mismatch. With `ZS_VECTORS_WRITE=1` the runner's value replaces
/// each `expect`, every non-frozen file is rewritten, and `INDEX.json` is regenerated.
pub fn check(dir: &Path, runners: &[Runner]) {
    let write = std::env::var("ZS_VECTORS_WRITE").as_deref() == Ok("1");
    let index_path = dir.join("INDEX.json");
    let index = read_index(&index_path);
    let on_disk = json_files(dir);

    for name in &on_disk {
        if !index.contains_key(name) {
            fail(name, "the file is not listed in INDEX.json");
        }
    }
    for name in index.keys() {
        if !on_disk.iter().any(|file| file == name) {
            fail(name, "INDEX.json lists a file that does not exist");
        }
        if !runners.iter().any(|runner| runner.file == name) {
            fail(name, "INDEX.json lists a file with no runner");
        }
    }
    for runner in runners {
        if !index.contains_key(runner.file) {
            fail(runner.file, "the runner's file is not listed in INDEX.json");
        }
    }

    let mut counts = BTreeMap::new();
    for runner in runners {
        let path = dir.join(runner.file);
        let mut file = read_file(&path);

        let mut names = BTreeSet::new();
        for case in &file.cases {
            if !names.insert(case.name.clone()) {
                fail(
                    runner.file,
                    &format!("case name {:?} appears more than once", case.name),
                );
            }
        }

        if !write {
            let count = index
                .get(runner.file)
                .copied()
                .unwrap_or_else(|| fail(runner.file, "a runner with no index entry"));
            if count as usize != file.cases.len() {
                fail(
                    runner.file,
                    &format!(
                        "INDEX.json lists {count} cases, the file holds {}",
                        file.cases.len()
                    ),
                );
            }
        }

        for case in &mut file.cases {
            let computed = (runner.case)(&file.context, &case.input);
            if computed == case.expect {
                continue;
            }
            if write && !file.frozen {
                case.expect = computed;
                continue;
            }
            let why = if file.frozen {
                "the file is frozen and the runner disagrees"
            } else {
                "the runner disagrees and ZS_VECTORS_WRITE is not 1"
            };
            fail(
                runner.file,
                &format!(
                    "case {:?}: {why}\n  expect:   {}\n  computed: {}",
                    case.name, case.expect, computed
                ),
            );
        }

        counts.insert(runner.file.to_string(), file.cases.len() as u64);
        if write && !file.frozen {
            write_file(&path, &file);
        }
    }

    if write {
        write_index(&index_path, &counts);
    }
}

fn json_files(dir: &Path) -> Vec<String> {
    let entries = fs::read_dir(dir).unwrap_or_else(|error| panic!("{}: {error}", dir.display()));
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.unwrap_or_else(|error| panic!("{}: {error}", dir.display()));
        let name = entry
            .file_name()
            .into_string()
            .unwrap_or_else(|_| panic!("{}: a file name is not UTF-8", dir.display()));
        if name == "INDEX.json" || !name.ends_with(".json") {
            continue;
        }
        names.push(name);
    }
    names.sort();
    names
}

fn read_index(path: &Path) -> BTreeMap<String, u64> {
    let text = fs::read_to_string(path).unwrap_or_else(|error| {
        panic!("zs-vectors: {}: {error}", path.display());
    });
    let value: Value = serde_json::from_str(&text).unwrap_or_else(|error| {
        panic!("zs-vectors: {}: {error}", path.display());
    });
    let files = value
        .get("files")
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("zs-vectors: {}: no \"files\" object", path.display()));
    let mut index = BTreeMap::new();
    for (name, count) in files {
        let count = count.as_u64().unwrap_or_else(|| {
            panic!(
                "zs-vectors: {}: {name}: the count is not an integer",
                path.display()
            )
        });
        index.insert(name.clone(), count);
    }
    index
}

fn read_file(path: &Path) -> VectorFile {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let text = fs::read_to_string(path).unwrap_or_else(|error| {
        panic!("zs-vectors: {}: {error}", path.display());
    });
    let value: Value = serde_json::from_str(&text).unwrap_or_else(|error| {
        panic!("zs-vectors: {}: {error}", path.display());
    });
    let object = value
        .as_object()
        .unwrap_or_else(|| fail(&name, "the file is not a JSON object"));
    for key in object.keys() {
        if !KEYS.contains(&key.as_str()) {
            fail(&name, &format!("unknown top-level key {key:?}"));
        }
    }

    let about = object
        .get("about")
        .and_then(Value::as_str)
        .unwrap_or_else(|| fail(&name, "missing a string \"about\""))
        .to_string();
    let version = object
        .get("version")
        .and_then(Value::as_u64)
        .unwrap_or_else(|| fail(&name, "missing an integer \"version\""));
    if version != 1 {
        fail(&name, &format!("version {version} is not 1"));
    }
    let frozen = object
        .get("frozen")
        .and_then(Value::as_bool)
        .unwrap_or_else(|| fail(&name, "missing a boolean \"frozen\""));
    let context = object
        .get("context")
        .cloned()
        .unwrap_or_else(|| fail(&name, "missing \"context\""));
    let cases = object
        .get("cases")
        .and_then(Value::as_array)
        .unwrap_or_else(|| fail(&name, "missing an array \"cases\""));

    let mut out = Vec::with_capacity(cases.len());
    for (position, case) in cases.iter().enumerate() {
        let case = case
            .as_object()
            .unwrap_or_else(|| fail(&name, &format!("case {position} is not an object")));
        for key in case.keys() {
            if !CASE_KEYS.contains(&key.as_str()) {
                fail(&name, &format!("case {position}: unknown key {key:?}"));
            }
        }
        let case_name = case
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_else(|| {
                fail(
                    &name,
                    &format!("case {position}: missing a string \"name\""),
                )
            })
            .to_string();
        let input = case
            .get("input")
            .cloned()
            .unwrap_or_else(|| fail(&name, &format!("case {case_name:?}: missing \"input\"")));
        let expect = case
            .get("expect")
            .cloned()
            .unwrap_or_else(|| fail(&name, &format!("case {case_name:?}: missing \"expect\"")));
        out.push(Case {
            name: case_name,
            input,
            expect,
        });
    }

    VectorFile {
        about,
        frozen,
        context,
        cases: out,
    }
}

fn write_file(path: &Path, file: &VectorFile) {
    let mut root = Map::new();
    root.insert("about".into(), Value::String(file.about.clone()));
    root.insert("version".into(), Value::from(1));
    root.insert("frozen".into(), Value::Bool(file.frozen));
    root.insert("context".into(), file.context.clone());
    let cases = file
        .cases
        .iter()
        .map(|case| {
            let mut object = Map::new();
            object.insert("name".into(), Value::String(case.name.clone()));
            object.insert("input".into(), case.input.clone());
            object.insert("expect".into(), case.expect.clone());
            Value::Object(object)
        })
        .collect();
    root.insert("cases".into(), Value::Array(cases));
    let text = serde_json::to_string_pretty(&Value::Object(root))
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    fs::write(path, text + "\n").unwrap_or_else(|error| panic!("{}: {error}", path.display()));
}

fn write_index(path: &Path, counts: &BTreeMap<String, u64>) {
    let files = counts
        .iter()
        .map(|(name, count)| (name.clone(), Value::from(*count)))
        .collect();
    let mut root = Map::new();
    root.insert("files".into(), Value::Object(files));
    let text = serde_json::to_string_pretty(&Value::Object(root))
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    fs::write(path, text + "\n").unwrap_or_else(|error| panic!("{}: {error}", path.display()));
}

fn fail(file: &str, message: &str) -> ! {
    panic!("zs-vectors: {file}: {message}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::{Mutex, MutexGuard};
    use std::time::{SystemTime, UNIX_EPOCH};

    static LOCK: Mutex<()> = Mutex::new(());

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir()
                .join(format!("zs-vectors-{}-{tag}-{nanos}", std::process::id()));
            fs::create_dir_all(&path).unwrap();
            TempDir(path)
        }

        fn write(&self, name: &str, value: &Value) {
            fs::write(
                self.0.join(name),
                serde_json::to_string_pretty(value).unwrap() + "\n",
            )
            .unwrap();
        }

        fn read(&self, name: &str) -> String {
            fs::read_to_string(self.0.join(name)).unwrap()
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn forward(_context: &Value, input: &Value) -> Value {
        input.clone()
    }

    const RUNNERS: &[Runner] = &[Runner {
        file: "math.json",
        case: forward,
    }];

    fn file(cases: &[(&str, Value, Value)], frozen: bool) -> Value {
        serde_json::json!({
            "about": "test cases",
            "version": 1,
            "frozen": frozen,
            "context": {},
            "cases": cases
                .iter()
                .map(|(name, input, expect)| serde_json::json!({
                    "name": name,
                    "input": input,
                    "expect": expect,
                }))
                .collect::<Vec<_>>(),
        })
    }

    fn index(count: u64) -> Value {
        serde_json::json!({"files": {"math.json": count}})
    }

    fn serial() -> MutexGuard<'static, ()> {
        LOCK.lock().unwrap_or_else(|error| error.into_inner())
    }

    struct WriteMode {
        _guard: MutexGuard<'static, ()>,
    }

    impl WriteMode {
        fn on() -> Self {
            let guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
            unsafe { std::env::set_var("ZS_VECTORS_WRITE", "1") };
            WriteMode { _guard: guard }
        }
    }

    impl Drop for WriteMode {
        fn drop(&mut self) {
            unsafe { std::env::remove_var("ZS_VECTORS_WRITE") };
        }
    }

    fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
        payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default()
    }

    #[test]
    fn a_matching_file_passes() {
        let _guard = serial();
        let dir = TempDir::new("match");
        dir.write("INDEX.json", &index(1));
        dir.write(
            "math.json",
            &file(
                &[("one", serde_json::json!(1), serde_json::json!(1))],
                false,
            ),
        );
        let before = dir.read("math.json");
        check(&dir.0, RUNNERS);
        assert_eq!(before, dir.read("math.json"));
    }

    #[test]
    fn a_changed_expect_fails_with_the_case_name() {
        let _guard = serial();
        let dir = TempDir::new("changed");
        dir.write("INDEX.json", &index(1));
        dir.write(
            "math.json",
            &file(
                &[("one", serde_json::json!(1), serde_json::json!(2))],
                false,
            ),
        );
        let payload = std::panic::catch_unwind(|| check(&dir.0, RUNNERS)).unwrap_err();
        let message = panic_message(payload);
        assert!(message.contains("math.json"), "{message}");
        assert!(message.contains("\"one\""), "{message}");
    }

    #[test]
    fn a_file_not_in_the_index_fails() {
        let _guard = serial();
        let dir = TempDir::new("unindexed");
        dir.write("INDEX.json", &json_empty_index());
        dir.write(
            "math.json",
            &file(
                &[("one", serde_json::json!(1), serde_json::json!(1))],
                false,
            ),
        );
        let payload = std::panic::catch_unwind(|| check(&dir.0, RUNNERS)).unwrap_err();
        let message = panic_message(payload);
        assert!(message.contains("not listed in INDEX.json"), "{message}");
    }

    fn json_empty_index() -> Value {
        serde_json::json!({"files": {}})
    }

    #[test]
    fn an_index_file_without_a_runner_fails() {
        let _guard = serial();
        let dir = TempDir::new("norunner");
        dir.write("INDEX.json", &index(1));
        dir.write(
            "math.json",
            &file(
                &[("one", serde_json::json!(1), serde_json::json!(1))],
                false,
            ),
        );
        let payload = std::panic::catch_unwind(|| check(&dir.0, &[])).unwrap_err();
        let message = panic_message(payload);
        assert!(message.contains("no runner"), "{message}");
    }

    #[test]
    fn a_wrong_case_count_fails() {
        let _guard = serial();
        let dir = TempDir::new("count");
        dir.write("INDEX.json", &index(2));
        dir.write(
            "math.json",
            &file(
                &[("one", serde_json::json!(1), serde_json::json!(1))],
                false,
            ),
        );
        let payload = std::panic::catch_unwind(|| check(&dir.0, RUNNERS)).unwrap_err();
        let message = panic_message(payload);
        assert!(message.contains("lists 2 cases"), "{message}");
    }

    #[test]
    fn write_mode_fills_expect_and_the_index() {
        let _write = WriteMode::on();
        let dir = TempDir::new("write");
        dir.write(
            "math.json",
            &file(&[("one", serde_json::json!({"a": 1}), Value::Null)], false),
        );
        dir.write(
            "frozen.json",
            &file(&[("two", serde_json::json!(2), serde_json::json!(2))], true),
        );
        let index_with_frozen = serde_json::json!({"files": {"math.json": 0, "frozen.json": 1}});
        dir.write("INDEX.json", &index_with_frozen);
        let frozen_before = dir.read("frozen.json");

        let runners = [
            Runner {
                file: "math.json",
                case: forward,
            },
            Runner {
                file: "frozen.json",
                case: forward,
            },
        ];
        check(&dir.0, &runners);

        let written: Value = serde_json::from_str(&dir.read("math.json")).unwrap();
        assert_eq!(written["cases"][0]["expect"], serde_json::json!({"a": 1}));
        assert_eq!(frozen_before, dir.read("frozen.json"));
        let index: Value = serde_json::from_str(&dir.read("INDEX.json")).unwrap();
        assert_eq!(index["files"]["math.json"], serde_json::json!(1));
        assert_eq!(index["files"]["frozen.json"], serde_json::json!(1));
    }

    #[test]
    fn write_mode_refuses_to_change_a_frozen_case() {
        let _write = WriteMode::on();
        let dir = TempDir::new("frozen");
        dir.write("INDEX.json", &index(1));
        dir.write(
            "math.json",
            &file(&[("one", serde_json::json!(1), serde_json::json!(9))], true),
        );
        let before = dir.read("math.json");
        let payload = std::panic::catch_unwind(|| check(&dir.0, RUNNERS)).unwrap_err();
        let message = panic_message(payload);
        assert!(message.contains("frozen"), "{message}");
        assert!(message.contains("\"one\""), "{message}");
        assert_eq!(before, dir.read("math.json"));
    }
}
