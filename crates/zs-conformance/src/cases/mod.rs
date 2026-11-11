pub mod mongodb;
pub mod mysql;
pub mod postgres;
pub mod redis;
pub mod sigv4;

use std::io::{Read, Write};
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

pub(crate) const CLIENT_TIMEOUT: Duration = Duration::from_secs(60);

pub(crate) fn output_within(
    command: &mut Command,
    input: Option<&[u8]>,
    timeout: Duration,
) -> Result<Output, String> {
    let program = command.get_program().to_string_lossy().into_owned();
    let mut child = command
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("cannot run {program}: {error}"))?;
    let stdout = drain(child.stdout.take());
    let stderr = drain(child.stderr.take());
    if let (Some(mut stdin), Some(input)) = (child.stdin.take(), input) {
        let input = input.to_vec();
        thread::spawn(move || {
            let _ = stdin.write_all(&input);
        });
    }
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "{program} did not finish within {} s",
                    timeout.as_secs()
                ));
            }
            Ok(None) => thread::sleep(Duration::from_millis(20)),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("cannot wait for {program}: {error}"));
            }
        }
    };
    Ok(Output {
        status,
        stdout: collect(stdout),
        stderr: collect(stderr),
    })
}

fn drain(stream: Option<impl Read + Send + 'static>) -> mpsc::Receiver<Vec<u8>> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut buffer = Vec::new();
        if let Some(mut stream) = stream {
            let _ = stream.read_to_end(&mut buffer);
        }
        let _ = sender.send(buffer);
    });
    receiver
}

fn collect(receiver: mpsc::Receiver<Vec<u8>>) -> Vec<u8> {
    receiver
        .recv_timeout(Duration::from_secs(5))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn a_client_that_never_finishes_is_killed_at_the_deadline() {
        let started = Instant::now();
        let error = output_within(
            Command::new("sleep").arg("30"),
            None,
            Duration::from_secs(1),
        )
        .expect_err("the client must time out");
        assert!(error.contains("did not finish"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn input_reaches_the_client_and_output_comes_back() {
        let output = output_within(
            &mut Command::new("cat"),
            Some(b"conformance"),
            CLIENT_TIMEOUT,
        )
        .expect("cat runs");
        assert_eq!(output.stdout, b"conformance");
    }
}
