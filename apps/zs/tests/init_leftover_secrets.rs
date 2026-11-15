#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

const PLACEHOLDER: &str = "placeholder_managed_by_zerosecret";

struct Sandbox {
    _root: tempfile::TempDir,
    ws: PathBuf,
    home: PathBuf,
}

impl Sandbox {
    fn with_env(content: &str) -> Self {
        let root = tempfile::tempdir().unwrap();
        let ws = root.path().join("proj");
        let home = root.path().join("home");
        fs::create_dir(&ws).unwrap();
        fs::create_dir(&home).unwrap();
        fs::write(ws.join(".env"), content).unwrap();
        Self {
            _root: root,
            ws,
            home,
        }
    }

    fn init(&self) -> Output {
        Command::new(env!("CARGO_BIN_EXE_zs"))
            .current_dir(&self.ws)
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .arg("init")
            .output()
            .expect("failed to execute zs init")
    }

    fn env(&self) -> String {
        fs::read_to_string(self.ws.join(".env")).unwrap()
    }

    fn credential(&self, resource: &str) -> PathBuf {
        self.home.join(".zs-credentials/proj").join(resource)
    }
}

fn printed(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn listed_as_not_brokered(printed: &str, key: &str) -> bool {
    printed
        .lines()
        .any(|line| line.starts_with(&format!("zs: not brokered, left in .env: {key} ")))
}

#[test]
fn a_brokered_password_does_not_stay_in_env_under_a_second_key() {
    const SECRET: &str = "zs-review-db-secret-1";
    let sandbox = Sandbox::with_env(&format!(
        "MYSQL_HOST=db.example.internal\n\
MYSQL_USER=app\n\
MYSQL_PASSWORD={SECRET}\n\
MYSQL_PWD={SECRET}\n"
    ));

    let output = sandbox.init();
    let printed = printed(&output);
    assert!(output.status.success(), "{printed}");
    assert_eq!(
        fs::read_to_string(sandbox.credential("mysql")).unwrap(),
        SECRET,
        "positive control: zs init brokered the password: {printed}"
    );
    let env = sandbox.env();
    assert!(
        env.contains(&format!("MYSQL_PASSWORD={PLACEHOLDER}\n")),
        "positive control: the brokered key holds the placeholder: {env}"
    );
    assert!(
        !printed.contains(SECRET),
        "negative control: no message names the value: {printed}"
    );

    assert!(
        !env.contains(SECRET) || listed_as_not_brokered(&printed, "MYSQL_PWD"),
        "the brokered password is still in .env under MYSQL_PWD, and zs init did not list \
         that key as not brokered.\n--- .env ---\n{}\n--- output ---\n{printed}",
        env.replace(SECRET, "<the brokered password>")
    );
}

#[test]
fn a_brokered_password_does_not_stay_in_env_inside_a_dsn() {
    const SECRET: &str = "zs-review-db-secret-2";
    let sandbox = Sandbox::with_env(&format!(
        "DATABASE_URL=mysql://app:{SECRET}@db.example.internal:3306/app\n\
GORM_DSN=app:{SECRET}@tcp(db.example.internal:3306)/app\n"
    ));

    let output = sandbox.init();
    let printed = printed(&output);
    assert!(output.status.success(), "{printed}");
    assert_eq!(
        fs::read_to_string(sandbox.credential("mysql-db")).unwrap(),
        SECRET,
        "positive control: zs init brokered the password: {printed}"
    );
    let env = sandbox.env();
    assert!(
        env.contains("DATABASE_URL=mysql://app@127.0.0.1:54320/app\n"),
        "positive control: the database URL lost its password: {env}"
    );
    assert!(
        !printed.contains(SECRET),
        "negative control: no message names the value: {printed}"
    );

    assert!(
        !env.contains(SECRET) || listed_as_not_brokered(&printed, "GORM_DSN"),
        "the brokered password is still in .env inside GORM_DSN, and zs init did not list \
         that key as not brokered.\n--- .env ---\n{}\n--- output ---\n{printed}",
        env.replace(SECRET, "<the brokered password>")
    );
}

#[test]
fn a_password_key_left_in_env_is_listed_as_not_brokered() {
    let sandbox = Sandbox::with_env(
        "STRIPE_SECRET_KEY=sk_live_zsreview1\n\
JWT_SECRET=zs-review-jwt-1\n\
SMTP_PASS=zs-review-smtp-1\n\
ADMIN_PWD=zs-review-admin-1\n",
    );

    let output = sandbox.init();
    let printed = printed(&output);
    assert!(output.status.success(), "{printed}");
    let env = sandbox.env();
    assert!(
        env.contains(&format!("STRIPE_SECRET_KEY={PLACEHOLDER}\n")),
        "positive control: zs init replaced a secret: {env}"
    );
    assert!(
        listed_as_not_brokered(&printed, "JWT_SECRET"),
        "positive control: a secret that stays is listed: {printed}"
    );
    for key in ["SMTP_PASS", "ADMIN_PWD"] {
        assert!(
            env.lines()
                .any(|line| line.starts_with(&format!("{key}=zs-review-"))),
            "control: {key} keeps its value: {env}"
        );
    }

    let unlisted: Vec<&str> = ["SMTP_PASS", "ADMIN_PWD"]
        .into_iter()
        .filter(|key| !listed_as_not_brokered(&printed, key))
        .collect();
    assert!(
        unlisted.is_empty(),
        "these password keys stay in .env, and zs init did not list them as not brokered: \
         {unlisted:?}\n{printed}"
    );
}

#[cfg(unix)]
#[test]
fn a_credential_file_reported_as_0600_is_0600() {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    const KEY: &str = "sk_live_zsreview2";
    const LINE: &str = "zs: credential ~/.zs-credentials/proj/stripe written (0600)";
    let mode = |sandbox: &Sandbox| {
        fs::metadata(sandbox.credential("stripe"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    };

    let fresh = Sandbox::with_env(&format!("STRIPE_SECRET_KEY={KEY}\n"));
    let output = fresh.init();
    assert!(output.status.success(), "{}", printed(&output));
    assert_eq!(
        mode(&fresh),
        0o600,
        "positive control: a new credential file is 0600"
    );

    let sandbox = Sandbox::with_env(&format!("STRIPE_SECRET_KEY={KEY}\n"));
    let dir = sandbox.home.join(".zs-credentials/proj");
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .unwrap();
    fs::write(dir.join("stripe"), KEY).unwrap();
    fs::set_permissions(dir.join("stripe"), fs::Permissions::from_mode(0o644)).unwrap();

    let output = sandbox.init();
    let printed = printed(&output);
    assert!(output.status.success(), "{printed}");
    assert!(
        printed.lines().any(|line| line == LINE),
        "control: zs init reports the file as written with mode 0600: {printed}"
    );
    assert_eq!(
        mode(&sandbox),
        0o600,
        "zs init printed `{LINE}`, but the file has mode {:o}",
        mode(&sandbox)
    );
}

#[test]
fn a_short_brokered_password_reports_only_its_exact_copy() {
    let sandbox = Sandbox::with_env(
        "MYSQL_HOST=db.example.internal\n\
MYSQL_USER=app\n\
MYSQL_PASSWORD=app\n\
MYSQL_PWD=app\n\
APP_NAME=my-app-service\n",
    );

    let output = sandbox.init();
    let printed = printed(&output);
    assert!(output.status.success(), "{printed}");
    assert_eq!(
        fs::read_to_string(sandbox.credential("mysql")).unwrap(),
        "app",
        "positive control: zs init brokered the password: {printed}"
    );
    assert!(
        sandbox
            .env()
            .contains(&format!("MYSQL_PASSWORD={PLACEHOLDER}\n")),
        "positive control: the brokered key holds the placeholder"
    );
    assert!(
        listed_as_not_brokered(&printed, "MYSQL_PWD"),
        "the exact copy of a short brokered password is listed: {printed}"
    );
    for key in ["APP_NAME", "MYSQL_USER"] {
        assert!(
            !listed_as_not_brokered(&printed, key),
            "{key} only contains the short brokered password and must not be listed: {printed}"
        );
    }
}

#[test]
fn an_exact_copy_of_a_short_password_under_a_plain_key_is_listed() {
    let sandbox = Sandbox::with_env(
        "MYSQL_HOST=db.example.internal\n\
MYSQL_USER=app\n\
MYSQL_PASSWORD=app\n\
LEGACY_DB=app\n\
APP_LABEL=app-service\n",
    );

    let output = sandbox.init();
    let printed = printed(&output);
    assert!(output.status.success(), "{printed}");
    assert_eq!(
        fs::read_to_string(sandbox.credential("mysql")).unwrap(),
        "app",
        "positive control: zs init brokered the password: {printed}"
    );
    assert!(
        !listed_as_not_brokered(&printed, "APP_LABEL"),
        "negative control: a value that only contains the short password is not listed: {printed}"
    );
    assert!(
        listed_as_not_brokered(&printed, "LEGACY_DB"),
        "LEGACY_DB keeps the brokered password and its name does not mark a secret, and zs init \
         did not list it: {printed}"
    );
}
