use std::io::{Read, Write};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use tokio_postgres::{Config as PgConfig, NoTls};

use super::{CLIENT_TIMEOUT, output_within};
use crate::config::Protocol;
use crate::runner::{Case, Context, Upstream};

const COPY_ROWS: usize = 10_000;

pub fn cases() -> Vec<Case> {
    vec![
        Case {
            id: "PG-01",
            protocol: Protocol::Postgres,
            upstream: Upstream::Primary,
            serial_group: None,
            credential: None,
            run: simple_query,
        },
        Case {
            id: "PG-02",
            protocol: Protocol::Postgres,
            upstream: Upstream::Primary,
            serial_group: None,
            credential: None,
            run: startup_settings,
        },
        Case {
            id: "PG-03",
            protocol: Protocol::Postgres,
            upstream: Upstream::Tls,
            serial_group: None,
            credential: None,
            run: upstream_tls,
        },
        Case {
            id: "PG-04",
            protocol: Protocol::Postgres,
            upstream: Upstream::Primary,
            serial_group: None,
            credential: None,
            run: extended_protocol,
        },
        Case {
            id: "PG-05",
            protocol: Protocol::Postgres,
            upstream: Upstream::Primary,
            serial_group: None,
            credential: None,
            run: copy_in,
        },
        Case {
            id: "PG-06",
            protocol: Protocol::Postgres,
            upstream: Upstream::Primary,
            serial_group: None,
            credential: None,
            run: copy_out,
        },
        Case {
            id: "PG-07",
            protocol: Protocol::Postgres,
            upstream: Upstream::Primary,
            serial_group: None,
            credential: None,
            run: sqlstate_passthrough,
        },
        Case {
            id: "PG-08",
            protocol: Protocol::Postgres,
            upstream: Upstream::Primary,
            serial_group: None,
            credential: None,
            run: cancel_request,
        },
    ]
}

fn simple_query(ctx: &Context) -> Result<String, String> {
    let output = run_psql(ctx, &["-tAc", "select 'ZS_CONFORMANCE_OK'"])?;
    ensure_success(&output, "the simple query failed")?;
    let value = stdout_text(&output);
    if value.trim() != "ZS_CONFORMANCE_OK" {
        return Err(format!("the simple query returned {:?}", one_line(&value)));
    }
    Ok("the simple query returned ZS_CONFORMANCE_OK".to_string())
}

fn startup_settings(ctx: &Context) -> Result<String, String> {
    let mut command = psql(
        ctx,
        &[
            "-tAq",
            "-F",
            "|",
            "-c",
            "select current_setting('application_name'), current_setting('client_encoding'), current_setting('statement_timeout')",
        ],
    );
    command
        .env("PGAPPNAME", "zs-conf")
        .env("PGCLIENTENCODING", "LATIN1")
        .env("PGOPTIONS", "-c statement_timeout=4321");
    let output = output_within(&mut command, None, CLIENT_TIMEOUT)?;
    ensure_success(&output, "the startup settings query failed")?;
    let value = stdout_text(&output);
    if value.trim() != "zs-conf|LATIN1|4321ms" {
        return Err(format!(
            "the startup settings returned {:?}",
            one_line(&value)
        ));
    }
    Ok(
        "application_name, client_encoding and the -c option in the startup packet reached the server"
            .to_string(),
    )
}

fn upstream_tls(ctx: &Context) -> Result<String, String> {
    let output = run_psql(
        ctx,
        &[
            "-tA",
            "-c",
            "select ssl::text from pg_stat_ssl where pid = pg_backend_pid()",
        ],
    )?;
    ensure_success(&output, "the TLS status query failed")?;
    let value = stdout_text(&output);
    if value.trim() != "t" && value.trim() != "true" {
        return Err(format!(
            "the upstream session reported ssl = {:?}",
            one_line(&value)
        ));
    }
    Ok("the upstream session reported ssl = t".to_string())
}

fn extended_protocol(ctx: &Context) -> Result<String, String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("cannot start the async runtime: {error}"))?;
    runtime.block_on(async {
        tokio::time::timeout(CLIENT_TIMEOUT, extended_protocol_session(ctx))
            .await
            .map_err(|_| {
                format!(
                    "the extended protocol session did not finish within {} s",
                    CLIENT_TIMEOUT.as_secs()
                )
            })?
    })
}

async fn extended_protocol_session(ctx: &Context) -> Result<String, String> {
    let mut config = PgConfig::new();
    config
        .host(ctx.endpoint.ip().to_string())
        .port(ctx.endpoint.port())
        .user(ctx.roles.user.clone())
        .dbname(ctx.roles.database.clone())
        .application_name("conformance")
        .connect_timeout(Duration::from_secs(10));
    let (client, connection) = config.connect(NoTls).await.map_err(|error| {
        format!(
            "the extended protocol connection failed: {}",
            pg_error(&error)
        )
    })?;
    let connection = tokio::spawn(async move {
        let _ = connection.await;
    });
    let statement = client
        .prepare("select $1::int4")
        .await
        .map_err(|error| format!("the parse failed: {}", pg_error(&error)))?;
    let mut returned = Vec::new();
    for value in [7i32, 9i32] {
        let rows = client
            .query(&statement, &[&value])
            .await
            .map_err(|error| format!("the bind of {value} failed: {}", pg_error(&error)))?;
        let row = rows
            .first()
            .ok_or_else(|| format!("the bind of {value} returned no row"))?;
        let read: i32 = row
            .try_get(0)
            .map_err(|error| format!("cannot read the row: {error}"))?;
        if read != value {
            return Err(format!("the bind of {value} returned {read}"));
        }
        returned.push(read);
    }
    connection.abort();
    Ok(format!("one prepare and two binds returned {returned:?}"))
}

fn pg_error(error: &tokio_postgres::Error) -> String {
    match error.as_db_error() {
        Some(db) => format!("{} {}", db.code().code(), db.message()),
        None => error.to_string(),
    }
}

fn copy_in(ctx: &Context) -> Result<String, String> {
    let script = copy_script("select count(*) from conformance_copy;\n");
    let output = psql_with_input(
        ctx,
        &["-tA", "-q", "-v", "ON_ERROR_STOP=1", "-f", "-"],
        script.as_bytes(),
    )?;
    ensure_success(&output, "the COPY FROM failed")?;
    let value = stdout_text(&output);
    match value.trim().parse::<usize>() {
        Ok(rows) if rows == COPY_ROWS => Ok(format!("COPY FROM loaded {COPY_ROWS} rows")),
        _ => Err(format!("COPY FROM left {:?} rows", one_line(value.trim()))),
    }
}

fn copy_out(ctx: &Context) -> Result<String, String> {
    let expected = copy_data();
    let script = copy_script(
        "\\copy (select * from conformance_copy order by id) to stdout with (format csv)\n",
    );
    let output = psql_with_input(
        ctx,
        &["-tA", "-q", "-v", "ON_ERROR_STOP=1", "-f", "-"],
        script.as_bytes(),
    )?;
    ensure_success(&output, "the COPY TO failed")?;
    if output.stdout != expected.as_bytes() {
        let rows = output.stdout.iter().filter(|byte| **byte == b'\n').count();
        return Err(format!(
            "COPY TO returned {rows} rows that differ from the {COPY_ROWS} loaded"
        ));
    }
    Ok(format!(
        "COPY TO returned {COPY_ROWS} rows byte-identical to COPY FROM"
    ))
}

fn sqlstate_passthrough(ctx: &Context) -> Result<String, String> {
    let duplicate = "\\set VERBOSITY verbose\n\
                     create table if not exists conformance_keys (id int primary key);\n\
                     insert into conformance_keys values (1) on conflict (id) do nothing;\n\
                     insert into conformance_keys values (1);\n";
    let output = psql_with_input(
        ctx,
        &["-q", "-v", "ON_ERROR_STOP=1", "-f", "-"],
        duplicate.as_bytes(),
    )?;
    if output.status.success() {
        return Err("the duplicate primary key insert succeeded".to_string());
    }
    let error = stderr_text(&output);
    if !contains_sqlstate(&error, "23505") {
        return Err(format!(
            "the duplicate insert did not report 23505: {}",
            one_line(&error)
        ));
    }
    let missing = "\\set VERBOSITY verbose\nselect * from conformance_missing_relation;\n";
    let output = psql_with_input(
        ctx,
        &["-q", "-v", "ON_ERROR_STOP=1", "-f", "-"],
        missing.as_bytes(),
    )?;
    if output.status.success() {
        return Err("the missing relation query succeeded".to_string());
    }
    let error = stderr_text(&output);
    if !contains_sqlstate(&error, "42P01") {
        return Err(format!(
            "the missing relation did not report 42P01: {}",
            one_line(&error)
        ));
    }
    Ok("SQLSTATE 23505 and 42P01 reached the client unchanged".to_string())
}

fn cancel_request(ctx: &Context) -> Result<String, String> {
    let script = "\\set VERBOSITY verbose\nselect pg_sleep(30);\n";
    let mut child = psql(ctx, &["-q", "-f", "-"])
        .env("PGOPTIONS", "-c statement_timeout=0")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("cannot run psql: {error}"))?;
    if let Some(mut stdin) = child.stdin.take()
        && let Err(error) = stdin.write_all(script.as_bytes())
    {
        terminate(&mut child);
        return Err(format!("cannot write to psql: {error}"));
    }
    let stdout = read_all(child.stdout.take());
    let stderr = read_all(child.stderr.take());
    std::thread::sleep(Duration::from_secs(2));
    if !matches!(child.try_wait(), Ok(None)) {
        terminate(&mut child);
        let output = format!(
            "{}\n{}",
            text_of(stdout.join().unwrap_or_default()),
            text_of(stderr.join().unwrap_or_default())
        );
        return Err(format!(
            "psql finished before the cancel was sent: {}",
            one_line(&output)
        ));
    }
    let pid = child.id().to_string();
    let signal = match Command::new("kill").args(["-INT", pid.as_str()]).status() {
        Ok(signal) => signal,
        Err(error) => {
            terminate(&mut child);
            return Err(format!("cannot signal psql: {error}"));
        }
    };
    if !signal.success() {
        terminate(&mut child);
        return Err("the cancel signal could not be delivered".to_string());
    }
    let started = Instant::now();
    let mut timed_out = false;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if started.elapsed() >= Duration::from_secs(10) {
                    timed_out = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(error) => {
                terminate(&mut child);
                return Err(format!("cannot wait for psql: {error}"));
            }
        }
    }
    terminate(&mut child);
    let output = format!(
        "{}\n{}",
        text_of(stdout.join().unwrap_or_default()),
        text_of(stderr.join().unwrap_or_default())
    );
    if timed_out {
        return Err("the cancelled query did not return within 10 s".to_string());
    }
    if !contains_sqlstate(&output, "57014") {
        return Err(format!(
            "the cancelled query did not report 57014: {}",
            one_line(&output)
        ));
    }
    Ok(format!(
        "the cancel request reported 57014 in {} ms",
        started.elapsed().as_millis()
    ))
}

fn psql(ctx: &Context, args: &[&str]) -> Command {
    let mut command = Command::new("psql");
    command
        .arg("-h")
        .arg(ctx.endpoint.ip().to_string())
        .arg("-p")
        .arg(ctx.endpoint.port().to_string())
        .arg("-U")
        .arg(&ctx.roles.user)
        .arg("-d")
        .arg(&ctx.roles.database)
        .arg("-X")
        .arg("-w")
        .args(args)
        .env("PGPASSFILE", "/dev/null")
        .env("PGCONNECT_TIMEOUT", "10")
        .env_remove("PGPASSWORD")
        .env_remove("PGSERVICEFILE")
        .env_remove("PGSERVICE")
        .env_remove("PGAPPNAME")
        .env_remove("PGOPTIONS")
        .env_remove("PGCLIENTENCODING")
        .env_remove("PGSSLMODE");
    command
}

fn run_psql(ctx: &Context, args: &[&str]) -> Result<Output, String> {
    output_within(&mut psql(ctx, args), None, CLIENT_TIMEOUT)
}

fn psql_with_input(ctx: &Context, args: &[&str], input: &[u8]) -> Result<Output, String> {
    output_within(&mut psql(ctx, args), Some(input), CLIENT_TIMEOUT)
}

fn copy_script(trailer: &str) -> String {
    let mut script = String::from(
        "create table if not exists conformance_copy (id int, name text);\n\
         truncate conformance_copy;\n\
         \\copy conformance_copy from stdin with (format csv)\n",
    );
    script.push_str(&copy_data());
    script.push_str("\\.\n");
    script.push_str(trailer);
    script
}

fn copy_data() -> String {
    let mut data = String::new();
    for id in 0..COPY_ROWS {
        data.push_str(&format!("{id},row-{id:05}\n"));
    }
    data
}

fn ensure_success(output: &Output, action: &str) -> Result<(), String> {
    if output.status.success() {
        return Ok(());
    }
    let error = stderr_text(output);
    if error.trim().is_empty() {
        Err(format!("{action} with status {}", output.status))
    } else {
        Err(format!("{action}: {}", one_line(&error)))
    }
}

fn stdout_text(output: &Output) -> String {
    text_of(output.stdout.clone())
}

fn stderr_text(output: &Output) -> String {
    text_of(output.stderr.clone())
}

fn text_of(bytes: Vec<u8>) -> String {
    String::from_utf8_lossy(&bytes).into_owned()
}

fn contains_sqlstate(text: &str, code: &str) -> bool {
    text.split(|character: char| !character.is_ascii_alphanumeric())
        .any(|token| token == code)
}

fn one_line(text: &str) -> String {
    let line = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if line.chars().count() > 320 {
        line.chars().take(320).collect::<String>() + "..."
    } else {
        line
    }
}

fn read_all(stream: Option<impl Read + Send + 'static>) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut buffer = Vec::new();
        if let Some(mut stream) = stream {
            let _ = stream.read_to_end(&mut buffer);
        }
        buffer
    })
}

fn terminate(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use std::collections::BTreeMap;

    use super::*;
    use crate::config::Fixtures;
    use crate::provision::Roles;
    use crate::runner::Variant;

    fn context() -> Context {
        Context {
            endpoint: "127.0.0.1:5434".parse().expect("address"),
            env: BTreeMap::new(),
            roles: Roles {
                user: "conformance_user".to_string(),
                password: "hunter2-conformance".to_string(),
                database: "conformance".to_string(),
            },
            variant: Variant::Positive,
            fixtures: Fixtures::default(),
            http: None,
            adapter: std::path::PathBuf::new(),
            handle: crate::adapter::Handle {
                handle: String::new(),
                endpoint: "127.0.0.1:5434".parse().expect("address"),
                env: BTreeMap::new(),
            },
        }
    }

    #[test]
    fn the_copy_fixture_has_ten_thousand_csv_rows() {
        let data = copy_data();
        assert_eq!(data.lines().count(), COPY_ROWS);
        assert!(data.starts_with("0,row-00000\n"));
        assert!(data.ends_with("9999,row-09999\n"));
    }

    #[test]
    fn a_verbose_sqlstate_is_parsed() {
        assert!(contains_sqlstate(
            "ERROR:  23505: duplicate key value violates unique constraint",
            "23505"
        ));
        assert!(contains_sqlstate(
            "ERROR:  42P01: relation does not exist",
            "42P01"
        ));
        assert!(!contains_sqlstate("ERROR:  235050: other", "23505"));
    }

    #[test]
    fn every_password_source_is_removed_from_the_psql_environment() {
        let ctx = context();
        let command = psql(&ctx, &[]);
        let removed: Vec<String> = command
            .get_envs()
            .filter(|(_, value)| value.is_none())
            .map(|(key, _)| key.to_string_lossy().into_owned())
            .collect();
        for key in ["PGPASSWORD", "PGSERVICEFILE", "PGSERVICE"] {
            assert!(removed.iter().any(|removed| removed == key), "{key}");
        }
        assert!(
            command.get_envs().any(|(key, value)| key == "PGPASSFILE"
                && value.is_some_and(|value| value == "/dev/null"))
        );
        let args: Vec<String> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert!(!args.iter().any(|arg| arg.contains(&ctx.roles.password)));
        assert!(args.iter().any(|arg| arg == "127.0.0.1"));
        assert!(args.iter().any(|arg| arg == "5434"));
        assert!(args.iter().any(|arg| arg == &ctx.roles.user));
        assert!(args.iter().any(|arg| arg == &ctx.roles.database));
    }

    #[test]
    fn evidence_and_errors_stay_on_one_line() {
        assert_eq!(one_line("first\nsecond\tthird"), "first second third");
        assert_eq!(one_line(&"a".repeat(400)).len(), 323);
    }
}
