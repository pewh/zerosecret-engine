#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::TcpListener;
use std::process::Command;

mod stub;
#[path = "../tokenize.rs"]
mod tokenize;

use stub::{call_upstream, refuse};
use tokenize::tokenize;

fn main() {
    let mut child_cmd = "sleep 2".to_string();
    let mut creds_file = String::new();
    let mut upstream_port = String::new();
    let raw_args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < raw_args.len() {
        match raw_args[i].as_str() {
            "--child-cmd" => {
                let mut parts: Vec<String> = Vec::new();
                i += 1;
                while i < raw_args.len() && !raw_args[i].starts_with("--") {
                    parts.push(raw_args[i].clone());
                    i += 1;
                }
                child_cmd = parts.join(" ");
                continue;
            }
            "--creds-file" => {
                creds_file = raw_args.get(i + 1).cloned().unwrap_or_default();
                i += 2;
                continue;
            }
            "--upstream-port" => {
                upstream_port = raw_args.get(i + 1).cloned().unwrap_or_default();
                i += 2;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    // Fail rather than write a shared report file another run could consume.
    let report = std::env::var("ZS_VERIFY_ENV_REPORT").unwrap_or_default();
    if report.is_empty() {
        eprintln!("zs-stub-clean: ZS_VERIFY_ENV_REPORT is required");
        std::process::exit(2);
    }
    let proxy = TcpListener::bind("127.0.0.1:0").expect("bind proxy");
    let proxy_addr = proxy.local_addr().expect("proxy address");
    std::thread::spawn(move || {
        for stream in proxy.incoming().flatten() {
            refuse(stream);
        }
    });
    if !upstream_port.is_empty() {
        let credential = std::fs::read_to_string(&creds_file).unwrap_or_default();
        call_upstream(&upstream_port, credential.trim());
    }
    let wrapped = format!("sh -c 'env > {report}; exec {child_cmd}'");
    let mut parts = tokenize(&wrapped);
    let program = parts.first().expect("child command").clone();
    parts.remove(0);
    let mut child = Command::new(program)
        .args(parts)
        .spawn()
        .expect("spawn child");
    println!("zs: proxy {proxy_addr}");
    println!("zs: child-pid {}", child.id());
    let status = child.wait().expect("wait child");
    std::process::exit(status.code().unwrap_or(1));
}
