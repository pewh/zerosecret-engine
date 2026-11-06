use crate::cli::{self, VerifyArgs};
use crate::report::{self, DecisionEvidence, VectorEvidence, VerificationReport};
use crate::scan;
use crate::tokenize::tokenize;
use crate::upstream::{self, FakeUpstreamState};
use crate::workspace::PreparedWorkspace;
use std::collections::BTreeMap;
use std::io::{BufRead, Read};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use zeroize::Zeroizing;

const ERR_SPAWN: &str = "cannot spawn the agent; refusing to report on a scan that never ran";
const ERR_SERIALIZE: &str = "cannot serialize the report";

fn refuse(message: &str) -> i32 {
    eprintln!("zs-verify: {message}");
    2
}

pub(crate) fn run(args: VerifyArgs) -> i32 {
    // The credential stays in a zeroizing buffer, never in `args` or any command line.
    let credential = match cli::read_credential(&args.credential_file) {
        Ok(credential) => credential,
        Err(message) => return refuse(message),
    };
    let started = Instant::now();
    let (listener, upstream_addr) = match upstream::bind(args.upstream_port) {
        Ok(bound) => bound,
        Err(message) => return refuse(message),
    };

    let prepared = match PreparedWorkspace::prepare(&args, upstream_addr.port()) {
        Ok(prepared) => prepared,
        Err(message) => return refuse(message),
    };

    let policy = prepared.policy_path().display().to_string();
    let state = Arc::new(FakeUpstreamState::default());
    upstream::serve(
        listener,
        upstream::credential_expectation(&policy, &credential),
        state.clone(),
    );
    let negative_control_rejected = upstream::run_negative_control(upstream_addr, &policy, &state);

    let agent_cmd = prepared.expand(&args.agent_cmd, &args, upstream_addr.port());
    let mut agent_parts = tokenize(&agent_cmd);
    if agent_parts.is_empty() {
        return refuse(cli::ERR_AGENT_CMD);
    }
    let program = agent_parts.remove(0);
    let agent = match Command::new(&program)
        .args(&agent_parts)
        .env("ZS_VERIFY_ENV_REPORT", prepared.env_report_path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(agent) => agent,
        Err(_) => return refuse(ERR_SPAWN),
    };
    let captured = capture(
        agent,
        &credential,
        args.proxy_addr.as_deref(),
        prepared.env_report_path(),
    );
    let vectors = BTreeMap::from([
        (
            report::CHILD_ENVIRONMENT,
            scan::environment(
                prepared.env_report_path(),
                &credential,
                captured.observed_live,
            ),
        ),
        (
            report::CHILD_FILES,
            scan::files(
                &scan::file_roots(&args.exclude),
                &credential,
                &args.exclude,
                prepared.env_report_path(),
                prepared.policy_path(),
            ),
        ),
        (report::CHILD_MEMORY, scan::memory()),
        (report::AGENT_LISTENER, captured.listener),
        (
            report::AGENT_OUTPUT,
            scan::output(
                &captured.stdout,
                &captured.stderr,
                captured.complete,
                &args.audit_file,
                &credential,
            ),
        ),
    ]);
    let cleanup = prepared.close();

    let report = VerificationReport {
        leaked: vectors.values().any(|vector| vector.found == Some(true)),
        vectors,
        decisions: DecisionEvidence {
            upstream_requests: state.requests.load(Ordering::SeqCst),
            upstream_auth_ok: state.auth_ok.load(Ordering::SeqCst),
            upstream_auth_mismatch: state.auth_mismatch.load(Ordering::SeqCst),
            negative_control_rejected,
        },
        elapsed_ms: started.elapsed().as_millis() as u64,
    };
    let json = match serde_json::to_string_pretty(&report.to_json()) {
        Ok(json) => json,
        Err(_) => return refuse(ERR_SERIALIZE),
    };
    println!("{json}");
    match cleanup {
        Ok(()) => report.exit_code(),
        Err(message) => refuse(message),
    }
}

fn combine_listener(tokenless: VectorEvidence, authenticated: VectorEvidence) -> VectorEvidence {
    if tokenless.found == Some(true) || authenticated.found == Some(true) {
        return VectorEvidence::complete(true);
    }
    if tokenless.found.is_some() && authenticated.found.is_some() {
        return VectorEvidence::complete(false);
    }
    VectorEvidence::incomplete(
        tokenless
            .reason
            .or(authenticated.reason)
            .unwrap_or(scan::REASON_LISTENER),
    )
}

fn without_run_token(tokenless: VectorEvidence) -> VectorEvidence {
    if tokenless.found == Some(true) {
        return tokenless;
    }
    VectorEvidence::incomplete(tokenless.reason.unwrap_or(scan::REASON_NO_RUN_TOKEN))
}

struct Captured {
    stdout: Zeroizing<Vec<u8>>,
    stderr: Zeroizing<Vec<u8>>,
    complete: bool,
    observed_live: bool,
    listener: VectorEvidence,
}

fn capture(
    mut agent: Child,
    credential: &Zeroizing<String>,
    proxy_addr: Option<&str>,
    env_report: &std::path::Path,
) -> Captured {
    let stderr_drain = agent.stderr.take().map(|mut stderr| {
        std::thread::spawn(move || {
            let mut buf = Zeroizing::new(Vec::new());
            let complete = stderr.read_to_end(&mut buf).is_ok();
            (buf, complete)
        })
    });
    let mut stdout_buf = Zeroizing::new(Vec::new());
    let mut complete = true;
    let stop = Arc::new(AtomicBool::new(false));
    let mut environ_polls = Vec::new();
    let mut listener_probe = None;
    let mut token_probe = None;
    let announced: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));
    match agent.stdout.take() {
        Some(stdout) => {
            let mut reader = std::io::BufReader::new(stdout);
            let mut line = Zeroizing::new(Vec::new());
            loop {
                line.clear();
                match reader.read_until(b'\n', &mut line) {
                    Ok(0) => break,
                    Err(_) => {
                        complete = false;
                        break;
                    }
                    Ok(_) => {
                        let text = String::from_utf8_lossy(&line);
                        if let Some(pid) = text
                            .strip_prefix("zs: child-pid ")
                            .and_then(|pid| pid.trim().parse::<u32>().ok())
                        {
                            let stop = stop.clone();
                            let needle = credential.clone();
                            environ_polls.push(std::thread::spawn(move || {
                                scan::poll_child_environ(pid, &needle, stop)
                            }));
                            if token_probe.is_none() {
                                let announced = announced.clone();
                                let needle = credential.clone();
                                let env_report = env_report.to_path_buf();
                                token_probe = Some(std::thread::spawn(move || {
                                    scan::authenticated_listener(
                                        pid,
                                        &env_report,
                                        announced,
                                        &needle,
                                    )
                                }));
                            }
                        }
                        if let Some(printed) = text.strip_prefix("zs: proxy ")
                            && listener_probe.is_none()
                        {
                            let addr = proxy_addr
                                .map(str::to_string)
                                .unwrap_or_else(|| printed.trim().to_string());
                            if let Ok(mut slot) = announced.lock() {
                                *slot = Some(addr.clone());
                            }
                            let needle = credential.clone();
                            listener_probe = Some(std::thread::spawn(move || {
                                scan::listener(Some(&addr), &needle, None)
                            }));
                        }
                        stdout_buf.extend_from_slice(&line);
                    }
                }
            }
        }
        _ => {
            complete = false;
        }
    }
    stop.store(true, Ordering::SeqCst);
    let stderr = match stderr_drain.map(|drain| drain.join()) {
        Some(Ok((buf, drained))) => {
            complete &= drained;
            buf
        }
        _ => {
            complete = false;
            Zeroizing::new(Vec::new())
        }
    };
    let _ = agent.wait();

    let observed_live = environ_polls
        .into_iter()
        .map(|poll| poll.join().unwrap_or(false))
        .collect::<Vec<_>>()
        .contains(&true);
    let tokenless = match listener_probe {
        Some(probe) => probe
            .join()
            .unwrap_or_else(|_| VectorEvidence::incomplete(scan::REASON_LISTENER)),
        None => scan::listener(proxy_addr, credential, None),
    };
    let authenticated = token_probe.and_then(|probe| probe.join().ok().flatten());
    let listener = match authenticated {
        Some(authenticated) => combine_listener(tokenless, authenticated),
        None => without_run_token(tokenless),
    };
    Captured {
        stdout: stdout_buf,
        stderr,
        complete,
        observed_live,
        listener,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_listener_probed_only_without_the_token_is_incomplete() {
        let gated = without_run_token(VectorEvidence::complete(false));
        assert_eq!(gated.status, "incomplete");
        assert_eq!(gated.found, None);
        assert_eq!(gated.reason, Some(scan::REASON_NO_RUN_TOKEN));

        let leaked = without_run_token(VectorEvidence::complete(true));
        assert_eq!(leaked.status, "complete");
        assert_eq!(leaked.found, Some(true));

        let both = combine_listener(
            VectorEvidence::complete(false),
            VectorEvidence::complete(false),
        );
        assert_eq!(both.status, "complete");
        assert_eq!(both.found, Some(false));
    }
}
