use std::path::Path;
use std::process::{Command, Output};

use super::{CLIENT_TIMEOUT, output_within};
use crate::config::Protocol;
use crate::runner::{self, Case, Context, Upstream, Variant};
use crate::wrongca;

const ACL_USER: &str = "zs_app";
const ACL_PASSWORD: &str = "zs-test-redis-acl";
const DUMMY_PASSWORD: &str = "conformance-client-dummy";
const PIPELINE_LENGTH: usize = 1000;
const LARGE_VALUE: usize = 8 * 1024 * 1024;
const WRONGTYPE: &str = "(error) WRONGTYPE Operation against a key holding the wrong kind of value";

pub fn cases() -> Vec<Case> {
    vec![
        Case {
            id: "RD-01",
            protocol: Protocol::Redis,
            upstream: Upstream::Primary,
            serial_group: None,
            credential: None,
            run: default_user,
        },
        Case {
            id: "RD-02",
            protocol: Protocol::Redis,
            upstream: Upstream::Primary,
            serial_group: None,
            credential: Some(ACL_PASSWORD),
            run: acl_user,
        },
        Case {
            id: "RD-03",
            protocol: Protocol::Redis,
            upstream: Upstream::Tls,
            serial_group: None,
            credential: None,
            run: upstream_tls,
        },
        Case {
            id: "RD-04",
            protocol: Protocol::Redis,
            upstream: Upstream::Primary,
            serial_group: None,
            credential: None,
            run: pipeline,
        },
        Case {
            id: "RD-05",
            protocol: Protocol::Redis,
            upstream: Upstream::Primary,
            serial_group: None,
            credential: None,
            run: transaction_and_script,
        },
        Case {
            id: "RD-06",
            protocol: Protocol::Redis,
            upstream: Upstream::Primary,
            serial_group: None,
            credential: None,
            run: large_value,
        },
        Case {
            id: "RD-07",
            protocol: Protocol::Redis,
            upstream: Upstream::Primary,
            serial_group: None,
            credential: None,
            run: error_reply,
        },
    ]
}

fn default_user(ctx: &Context) -> Result<String, String> {
    let key = "conformance:rd01";
    expect_lines(
        &session(
            ctx,
            &[
                "PING",
                "ACL WHOAMI",
                &format!("SET {key} rd01-value"),
                &format!("GET {key}"),
                &format!("DEL {key}"),
                &format!("EXISTS {key}"),
            ],
        )?,
        &[
            "PONG",
            "\"default\"",
            "OK",
            "\"rd01-value\"",
            "(integer) 1",
            "(integer) 0",
        ],
        "the credential-free client did not complete PING, SET, GET and DEL",
    )?;
    Ok("a client that sent no password got PONG, ACL WHOAMI answered default, and SET, GET and DEL round-tripped".to_string())
}

fn acl_user(ctx: &Context) -> Result<String, String> {
    let key = "conformance:rd02";
    let mut command = redis_cli(ctx);
    command
        .args(["--no-raw", "--user", ACL_USER])
        .env("REDISCLI_AUTH", DUMMY_PASSWORD);
    let commands = [
        "ACL WHOAMI".to_string(),
        format!("SET {key} rd02-value"),
        format!("GET {key}"),
        format!("DEL {key}"),
    ];
    expect_lines(
        &run(&mut command, &commands)?,
        &["\"zs_app\"", "OK", "\"rd02-value\"", "(integer) 1"],
        "the client that sent AUTH zs_app with a dummy secret did not act as zs_app",
    )?;
    let hello = session(
        ctx,
        &[
            &format!("HELLO 3 AUTH {ACL_USER} {DUMMY_PASSWORD}"),
            "ACL WHOAMI",
            "CONFIG GET maxmemory",
        ],
    )?;
    let lines = reply_lines(&hello);
    let proto = lines
        .iter()
        .any(|line| line.contains("\"proto\" => (integer) 3"));
    let tail = &lines[lines.len().saturating_sub(2)..];
    if !proto
        || tail.first().map(String::as_str) != Some("\"zs_app\"")
        || !tail
            .get(1)
            .is_some_and(|line| line.starts_with("(error) NOPERM"))
    {
        return Err(format!(
            "the client that sent HELLO 3 with zs_app and a dummy secret did not get RESP3 as zs_app without admin rights; the client printed: {}",
            printed(&hello)
        ));
    }
    Ok("AUTH zs_app and HELLO 3 AUTH zs_app, each with a dummy password, ran as zs_app: ACL WHOAMI answered zs_app, HELLO answered proto 3 and CONFIG GET answered NOPERM".to_string())
}

fn upstream_tls(ctx: &Context) -> Result<String, String> {
    let result = encrypted_round_trip(ctx);
    match (ctx.variant, result) {
        (Variant::WrongCa, Err(refusal)) => Err(attribute_refusal(ctx, &refusal)),
        (_, result) => result,
    }
}

fn encrypted_round_trip(ctx: &Context) -> Result<String, String> {
    let key = "conformance:rd03";
    let output = session(
        ctx,
        &[
            "PING",
            &format!("SET {key} rd03-value"),
            &format!("GET {key}"),
            &format!("DEL {key}"),
            "CONFIG GET port",
            "CONFIG GET tls-port",
        ],
    )?;
    let lines = reply_lines(&output);
    let expected = [
        "PONG",
        "OK",
        "\"rd03-value\"",
        "(integer) 1",
        "1) \"port\"",
        "2) \"0\"",
    ];
    let encrypted_port = lines
        .get(7)
        .and_then(|line| line.strip_prefix("2) \""))
        .and_then(|line| line.strip_suffix('"'))
        .filter(|port| !port.is_empty() && *port != "0");
    if lines.len() != 8 || lines[..6] != expected || encrypted_port.is_none() {
        return Err(format!(
            "the client did not complete the round trip on the fixture that serves only encrypted connections; the client printed: {}",
            printed(&output)
        ));
    }
    Ok(format!(
        "PING, SET, GET and DEL round-tripped through an upstream that has its plaintext port off and listens encrypted on {}, with the upstream CA pinned by ca-sha256",
        encrypted_port.unwrap_or_default()
    ))
}

fn attribute_refusal(ctx: &Context, refusal: &str) -> String {
    let unproven = |why: &str| {
        format!(
            "the client was refused, but {why}, so the refusal is not attributable to the substituted CA: {refusal}"
        )
    };
    if !refusal.contains("(error)") && !refusal.contains("Error") {
        return unproven("the client printed no error reply");
    }
    let Some(fixture) = ctx.fixtures.redis_tls else {
        return unproven("no encrypted fixture is configured");
    };
    let wrong = match wrongca::wrong_ca() {
        Ok(path) => path,
        Err(error) => return unproven(&format!("the substituted CA cannot be read ({error})")),
    };
    let own = match probe(fixture, &runner::fixture_ca()) {
        Ok(output) => printed(&output),
        Err(error) => return unproven(&error),
    };
    if !own.contains("NOAUTH") {
        return unproven("the fixture did not answer a direct client that trusts its own CA");
    }
    let substituted = match probe(fixture, &wrong) {
        Ok(output) => printed(&output),
        Err(error) => return unproven(&error),
    };
    if substituted.is_empty() || substituted.contains("NOAUTH") || substituted.contains("PONG") {
        return unproven("a direct client that trusts the substituted CA was not refused");
    }
    format!(
        "a direct TLS client to {fixture} with the substituted CA failed ({substituted}) and with the fixture CA got NOAUTH; the client through the endpoint was refused: {refusal}"
    )
}

fn probe(fixture: std::net::SocketAddr, ca: &Path) -> Result<Output, String> {
    let mut command = Command::new("redis-cli");
    command
        .args(["--no-auth-warning", "--tls", "--cacert"])
        .arg(ca)
        .arg("-h")
        .arg(fixture.ip().to_string())
        .arg("-p")
        .arg(fixture.port().to_string())
        .arg("PING")
        .env_remove("REDISCLI_AUTH");
    output_within(&mut command, None, CLIENT_TIMEOUT)
}

fn pipeline(ctx: &Context) -> Result<String, String> {
    let key = "conformance:rd04";
    let mut batch = resp(&["DEL", key]);
    for index in 1..=PIPELINE_LENGTH {
        batch.extend(resp(&["RPUSH", key, &index.to_string()]));
    }
    let mut command = redis_cli(ctx);
    command.arg("--pipe");
    let output = output_within(&mut command, Some(&batch), CLIENT_TIMEOUT)?;
    let summary = format!("errors: 0, replies: {}", PIPELINE_LENGTH + 1);
    let text = printed(&output);
    if !output.status.success()
        || !text.contains(&summary)
        || !text.contains("Last reply received from server")
    {
        return Err(format!(
            "the pipelined batch of {} commands was not answered in full; the client printed: {}",
            PIPELINE_LENGTH + 1,
            text
        ));
    }
    let mut command = redis_cli(ctx);
    command.arg("--raw");
    let listed = run(
        &mut command,
        &[format!("LRANGE {key} 0 -1"), format!("DEL {key}")],
    )?;
    let expected: Vec<String> = (1..=PIPELINE_LENGTH)
        .map(|index| index.to_string())
        .chain(std::iter::once("1".to_string()))
        .collect();
    if reply_lines(&listed) != expected {
        return Err(format!(
            "the pipelined RPUSH commands did not land in order; the client printed: {}",
            printed(&listed)
        ));
    }
    Ok(format!(
        "redis-cli --pipe wrote {} commands without waiting and counted {summary} with its trailing ECHO answered last; LRANGE returned 1 to {PIPELINE_LENGTH} in order",
        PIPELINE_LENGTH + 1
    ))
}

fn transaction_and_script(ctx: &Context) -> Result<String, String> {
    let key = "conformance:rd05";
    expect_lines(
        &session(
            ctx,
            &[
                "MULTI",
                &format!("SET {key} 1"),
                &format!("INCR {key}"),
                "EXEC",
                &format!("EVAL \"return redis.call('INCRBY', KEYS[1], ARGV[1])\" 1 {key} 5"),
                &format!("DEL {key}"),
            ],
        )?,
        &[
            "OK",
            "QUEUED",
            "QUEUED",
            "1) OK",
            "2) (integer) 2",
            "(integer) 7",
            "(integer) 1",
        ],
        "MULTI, EXEC and EVAL did not answer as the server does",
    )?;
    Ok("MULTI queued SET and INCR, EXEC answered [OK, 2], and EVAL ran INCRBY to 7 on the same connection".to_string())
}

fn large_value(ctx: &Context) -> Result<String, String> {
    let key = "conformance:rd06";
    let value = large_payload();
    let mut command = redis_cli(ctx);
    command.args(["--no-raw", "-x", "SET", key]);
    let stored = output_within(&mut command, Some(&value), CLIENT_TIMEOUT)?;
    if reply_lines(&stored) != ["OK"] {
        return Err(format!(
            "SET of the {LARGE_VALUE}-byte value was not answered OK; the client exited with {} and printed: {}",
            stored.status,
            printed(&stored)
        ));
    }
    let mut command = redis_cli(ctx);
    command.args(["--raw", "GET", key]);
    let read = output_within(&mut command, None, CLIENT_TIMEOUT)?;
    let mut expected = value;
    expected.push(b'\n');
    if read.stdout != expected {
        let offset = read
            .stdout
            .iter()
            .zip(expected.iter())
            .position(|(left, right)| left != right)
            .unwrap_or(read.stdout.len().min(expected.len()));
        return Err(format!(
            "GET returned {} bytes, expected {}, first difference at byte {offset}; the client printed to stderr: {}",
            read.stdout.len(),
            expected.len(),
            one_line(&String::from_utf8_lossy(&read.stderr))
        ));
    }
    let mut command = redis_cli(ctx);
    command.args(["--no-raw", "DEL", key]);
    let deleted = output_within(&mut command, None, CLIENT_TIMEOUT)?;
    if reply_lines(&deleted) != ["(integer) 1"] {
        return Err(format!(
            "DEL of the large value failed; the client printed: {}",
            printed(&deleted)
        ));
    }
    Ok(format!(
        "an {LARGE_VALUE}-byte value with CR, LF and NUL bytes went in with SET and came back byte-identical from GET"
    ))
}

fn large_payload() -> Vec<u8> {
    (0..LARGE_VALUE)
        .map(|index| ((index.wrapping_mul(31)) ^ (index >> 9)) as u8)
        .collect()
}

fn error_reply(ctx: &Context) -> Result<String, String> {
    let key = "conformance:rd07";
    expect_lines(
        &session(
            ctx,
            &[
                &format!("SET {key} rd07-value"),
                &format!("LPUSH {key} item"),
                &format!("GET {key}"),
                &format!("DEL {key}"),
            ],
        )?,
        &["OK", WRONGTYPE, "\"rd07-value\"", "(integer) 1"],
        "the WRONGTYPE error did not reach the client unchanged",
    )?;
    Ok("LPUSH on a string key answered WRONGTYPE with the server's text, and GET on the same connection still answered".to_string())
}

fn redis_cli(ctx: &Context) -> Command {
    let mut command = Command::new("redis-cli");
    command
        .arg("--no-auth-warning")
        .arg("-h")
        .arg(ctx.endpoint.ip().to_string())
        .arg("-p")
        .arg(ctx.endpoint.port().to_string())
        .env_remove("REDISCLI_AUTH")
        .env_remove("REDISCLI_CLUSTER_YES");
    command
}

fn session(ctx: &Context, commands: &[&str]) -> Result<Output, String> {
    let mut command = redis_cli(ctx);
    command.arg("--no-raw");
    let commands: Vec<String> = commands.iter().map(|line| line.to_string()).collect();
    run(&mut command, &commands)
}

fn run(command: &mut Command, commands: &[String]) -> Result<Output, String> {
    let mut input = commands.join("\n");
    input.push('\n');
    output_within(command, Some(input.as_bytes()), CLIENT_TIMEOUT)
}

fn resp(args: &[&str]) -> Vec<u8> {
    let mut frame = format!("*{}\r\n", args.len()).into_bytes();
    for arg in args {
        frame.extend(format!("${}\r\n{arg}\r\n", arg.len()).into_bytes());
    }
    frame
}

fn expect_lines(output: &Output, expected: &[&str], what: &str) -> Result<(), String> {
    if reply_lines(output) == expected {
        return Ok(());
    }
    Err(format!("{what}; the client printed: {}", printed(output)))
}

fn reply_lines(output: &Output) -> Vec<String> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim_end)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect()
}

fn printed(output: &Output) -> String {
    let text = format!(
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    one_line(&text)
}

fn one_line(text: &str) -> String {
    let line = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if line.chars().count() > 320 {
        line.chars().take(320).collect::<String>() + "..."
    } else {
        line
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use std::collections::BTreeMap;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    use super::*;
    use crate::config::Fixtures;
    use crate::provision::Roles;

    fn context() -> Context {
        Context {
            endpoint: "127.0.0.1:6380".parse().expect("address"),
            env: BTreeMap::new(),
            roles: Roles {
                user: "default".to_string(),
                password: "hunter2-conformance".to_string(),
                database: String::new(),
            },
            variant: Variant::Positive,
            fixtures: Fixtures::default(),
            http: None,
            adapter: std::path::PathBuf::new(),
            handle: crate::adapter::Handle {
                handle: String::new(),
                endpoint: "127.0.0.1:6380".parse().expect("address"),
                env: BTreeMap::new(),
            },
        }
    }

    fn output(stdout: &str, stderr: &str) -> Output {
        Output {
            status: ExitStatus::from_raw(0),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    #[test]
    fn the_registry_lists_rd_01_to_rd_07() {
        let cases = cases();
        let ids: Vec<&str> = cases.iter().map(|case| case.id).collect();
        assert_eq!(
            ids,
            [
                "RD-01", "RD-02", "RD-03", "RD-04", "RD-05", "RD-06", "RD-07"
            ]
        );
        assert!(cases.iter().all(|case| case.protocol == Protocol::Redis));
        assert!(cases.iter().all(|case| case.serial_group.is_none()));
        assert_eq!(cases[1].credential, Some(ACL_PASSWORD));
        assert!(
            cases
                .iter()
                .enumerate()
                .all(|(index, case)| index == 1 || case.credential.is_none())
        );
        let tls: Vec<&str> = cases
            .iter()
            .filter(|case| case.upstream == Upstream::Tls)
            .map(|case| case.id)
            .collect();
        assert_eq!(tls, ["RD-03"]);
    }

    #[test]
    fn no_password_reaches_the_arguments_or_the_environment() {
        let ctx = context();
        let command = redis_cli(&ctx);
        let removed: Vec<String> = command
            .get_envs()
            .filter(|(_, value)| value.is_none())
            .map(|(key, _)| key.to_string_lossy().into_owned())
            .collect();
        assert!(removed.iter().any(|key| key == "REDISCLI_AUTH"));
        let args: Vec<String> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert!(!args.iter().any(|arg| arg.contains(&ctx.roles.password)));
        assert!(!args.iter().any(|arg| arg.contains(ACL_PASSWORD)));
        assert!(args.iter().any(|arg| arg == "6380"));
        assert_ne!(DUMMY_PASSWORD, ACL_PASSWORD);
        assert_ne!(DUMMY_PASSWORD, "conformance-wrong-password");
    }

    #[test]
    fn a_pipelined_command_is_framed_as_resp() {
        assert_eq!(
            resp(&["RPUSH", "k", "10"]),
            b"*3\r\n$5\r\nRPUSH\r\n$1\r\nk\r\n$2\r\n10\r\n"
        );
    }

    #[test]
    fn the_large_value_has_the_bytes_that_break_line_framing() {
        let value = large_payload();
        assert_eq!(value.len(), LARGE_VALUE);
        for byte in [b'\r', b'\n', 0] {
            assert!(value.contains(&byte), "{byte}");
        }
    }

    #[test]
    fn a_refusal_without_a_probe_is_not_attributed_to_the_ca() {
        let mut ctx = context();
        ctx.variant = Variant::WrongCa;
        let refusal = "the client printed: (error) ERR upstream unavailable";
        let reason = attribute_refusal(&ctx, refusal);
        assert!(reason.contains("not attributable"), "{reason}");
        for marker in [
            "certificate",
            "tls",
            "ssl",
            "verify",
            "ca-sha256",
            "self-signed",
        ] {
            assert!(
                !reason.to_lowercase().contains(marker),
                "{marker}: {reason}"
            );
        }
        let quiet = attribute_refusal(&ctx, "the client printed nothing");
        assert!(quiet.contains("no error reply"), "{quiet}");
    }

    #[test]
    fn reply_lines_drop_blank_lines_and_trailing_space() {
        let lines = reply_lines(&output("PONG\n\n\"v\"  \n", "ignored"));
        assert_eq!(lines, ["PONG", "\"v\""]);
        assert_eq!(printed(&output("a\nb", "c")), "a b c");
    }
}
