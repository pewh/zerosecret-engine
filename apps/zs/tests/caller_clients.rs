#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::atomic::Ordering;

use common::{TestHome, bin_path, spawn_agent_capturing, spawn_fake_upstream, write_test_setup};

const STRIP_USERINFO: &str = r#"export HTTPS_PROXY=$(printf %s "$HTTPS_PROXY" | sed 's|zs:[^@]*@||'); export https_proxy=$HTTPS_PROXY; exec "$@""#;

struct Client {
    name: &'static str,
    program: &'static str,
    check: &'static [&'static str],
    args: Vec<String>,
    answer: Option<&'static str>,
}

fn required() -> bool {
    std::env::var("ZS_REQUIRE_CLIENTS").as_deref() == Ok("1")
}

fn python() -> String {
    r#"import requests
try:
    print(requests.get("https://api.stripe.com/v1/customers", timeout=20).status_code)
except Exception:
    print("error")"#
        .to_string()
}

fn node() -> String {
    r#"fetch("https://api.stripe.com/v1/customers").then((r) => console.log(r.status)).catch(() => console.log("error"));"#.to_string()
}

fn bun() -> String {
    r#"try { const r = await fetch("https://api.stripe.com/v1/customers"); console.log(r.status); } catch { console.log("error"); }"#.to_string()
}

fn bun_websocket() -> String {
    r#"const done = (state) => { console.log(state); process.exit(0); };
const socket = new WebSocket("wss://api.stripe.com/v1/socket");
socket.onopen = () => done("open");
socket.onerror = () => done("error");
socket.onclose = () => done("closed");
setTimeout(() => done("timeout"), 15000);"#
        .to_string()
}

fn go_source(directory: &std::path::Path) -> String {
    let path = directory.join("caller_client.go");
    std::fs::write(
        &path,
        r#"package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
)

func main() {
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if bundle := os.Getenv("SSL_CERT_FILE"); bundle != "" {
		if pem, err := os.ReadFile(bundle); err == nil {
			pool.AppendCertsFromPEM(pem)
		}
	}
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{RootCAs: pool},
	}}
	response, err := client.Get("https://api.stripe.com/v1/customers")
	if err != nil {
		fmt.Print("error: ", err)
		return
	}
	defer response.Body.Close()
	io.Copy(io.Discard, response.Body)
	fmt.Print(response.StatusCode)
}
"#,
    )
    .unwrap();
    path.display().to_string()
}

fn clients(directory: &std::path::Path) -> Vec<Client> {
    vec![
        Client {
            name: "curl",
            program: "curl",
            check: &["--version"],
            args: vec![
                "-sS".into(),
                "-o".into(),
                "/dev/null".into(),
                "-w".into(),
                "%{http_code}".into(),
                "https://api.stripe.com/v1/customers".into(),
            ],
            answer: Some("200"),
        },
        Client {
            name: "go net/http",
            program: "go",
            check: &["version"],
            args: vec!["run".into(), go_source(directory)],
            answer: Some("200"),
        },
        Client {
            name: "python requests",
            program: "python3",
            check: &["-c", "import requests"],
            args: vec!["-c".into(), python()],
            answer: Some("200"),
        },
        Client {
            name: "node fetch",
            program: "node",
            check: &["--version"],
            args: vec!["-e".into(), node()],
            answer: Some("200"),
        },
        Client {
            name: "bun fetch",
            program: "bun",
            check: &["--version"],
            args: vec!["-e".into(), bun()],
            answer: Some("200"),
        },
        Client {
            name: "bun websocket",
            program: "bun",
            check: &["--version"],
            args: vec!["-e".into(), bun_websocket()],
            answer: None,
        },
    ]
}

fn installed(client: &Client) -> bool {
    std::process::Command::new(client.program)
        .args(client.check)
        .output()
        .is_ok_and(|output| output.status.success())
}

fn proxy_refusals(home: &std::path::Path) -> usize {
    let mut count = 0;
    let mut pending = vec![home.join(".zs-log")];
    while let Some(next) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&next) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else {
                count += std::fs::read_to_string(&path)
                    .unwrap_or_default()
                    .lines()
                    .filter(|line| {
                        line.contains("\"caller_refused\"") && line.contains("\"proxy\"")
                    })
                    .count();
            }
        }
    }
    count
}

fn run(client: &Client, strip_userinfo: bool) -> (String, usize, usize) {
    let home = TestHome::new(".zs-ca");
    let upstream = spawn_fake_upstream();
    let (policy, creds, audit, ca_dir, _) =
        write_test_setup(home.path(), upstream.addr.port(), true, true);
    let mut arguments: Vec<String> = Vec::new();
    if strip_userinfo {
        arguments.extend(["sh", "-c", STRIP_USERINFO, "sh", client.program].map(str::to_string));
        arguments.extend(client.args.iter().cloned());
    } else {
        arguments.push(client.program.to_string());
        arguments.extend(client.args.iter().cloned());
    }
    let borrowed: Vec<&str> = arguments.iter().map(String::as_str).collect();
    let captured = spawn_agent_capturing(
        bin_path().as_path(),
        &policy,
        &creds,
        &audit,
        &ca_dir,
        &borrowed,
    )
    .expect("agent spawn");
    (
        captured
            .child_output
            .lines()
            .filter(|line| !line.starts_with("zs: "))
            .collect::<Vec<_>>()
            .join("\n"),
        upstream.requests.load(Ordering::SeqCst),
        proxy_refusals(home.path()),
    )
}

#[test]
fn each_measured_client_sends_the_run_token() {
    let home = TestHome::new(".zs-ca");
    let mut measured = 0;
    let mut missing = Vec::new();
    for client in clients(home.path()) {
        if !installed(&client) {
            if required() {
                panic!(
                    "{} is required by ZS_REQUIRE_CLIENTS=1 but not installed",
                    client.name
                );
            }
            eprintln!("skipped {}: not installed", client.name);
            missing.push(client.name);
            continue;
        }

        let (positive, reached, admitted_refusals) = run(&client, false);
        assert!(
            client.answer.is_none_or(|answer| positive.contains(answer))
                && reached == 1
                && admitted_refusals == 0,
            "{}: expected a 200 through the proxy, got {positive:?} with {reached} upstream request(s) and {admitted_refusals} refusal(s)",
            client.name
        );

        let (control, refused, refusals) = run(&client, true);
        assert!(
            !control.contains("200") && refused == 0 && refusals >= 1,
            "{}: without the userinfo the client must be refused, got {control:?} with {refused} upstream request(s) and {refusals} caller_refused event(s)",
            client.name
        );
        measured += 1;
    }
    assert!(
        measured > 0 || !missing.is_empty(),
        "no measured client was available; missing: {missing:?}"
    );
    eprintln!("measured {measured} client(s); skipped: {missing:?}");
}

const BUN_S3: &str = r#"import { S3Client } from "bun";
const endpoint = process.env.ZS_STRIPE_PRODUCTION_URL;
const s3 = new S3Client({ accessKeyId: "AKIDTEST", secretAccessKey: "placeholder-secret", region: "eu-central-003", endpoint, bucket: "bucket" });
let read;
try { read = "read " + (await s3.file("k.txt").text()).length; } catch (error) { read = "error " + (error?.code ?? error); }
const presigned = s3.presign("k.txt", { expiresIn: 600, method: "GET" });
const answer = await fetch(endpoint + "/.zs/presign", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ url: presigned, method: "GET" }) });
console.log(JSON.stringify({ endpoint, read, presigned, status: answer.status, signed: await answer.text() }));"#;

#[test]
fn bun_s3client_reaches_the_endpoint_with_the_path_token_and_presigns_without_it() {
    let bun = Client {
        name: "bun s3client",
        program: "bun",
        check: &["--version"],
        args: Vec::new(),
        answer: None,
    };
    if !installed(&bun) {
        assert!(
            !required(),
            "bun is required by ZS_REQUIRE_CLIENTS=1 but not installed"
        );
        eprintln!("skipped bun s3client: not installed");
        return;
    }
    let home = TestHome::new(".zs-ca");
    let upstream = spawn_fake_upstream();
    let mut connection = common::loopback_connection(upstream.addr.port(), true);
    connection.local_endpoint = true;
    let (policy, creds, audit, ca_dir, _) =
        common::write_test_setup_signing(home.path(), upstream.addr.port(), &["GET"], connection);
    let text = std::fs::read_to_string(&policy).unwrap().replace(
        r#""operations": "#,
        r#""auth": {"scheme": "aws-sigv4", "access_key_id": "AKIDTEST", "region": "eu-central-003", "service": "s3"}, "local_endpoint": true, "operations": "#,
    );
    std::fs::write(&policy, text).unwrap();
    let script = home.path().join("s3.mjs");
    std::fs::write(&script, BUN_S3).unwrap();

    let captured = spawn_agent_capturing(
        bin_path().as_path(),
        &policy,
        &creds,
        &audit,
        &ca_dir,
        &["bun", "run", script.to_str().unwrap()],
    )
    .expect("agent spawn");
    let line = captured
        .child_output
        .lines()
        .find(|line| line.starts_with('{'))
        .unwrap_or_else(|| panic!("bun printed no result: {}", captured.child_output));
    let result: serde_json::Value = serde_json::from_str(line).unwrap();
    let endpoint = result["endpoint"].as_str().unwrap();
    let hex = endpoint.rsplit('/').next().unwrap();
    assert_eq!(
        hex.len(),
        64,
        "control: the endpoint url carries the token: {endpoint}"
    );

    assert!(
        result["read"].as_str().unwrap().starts_with("read "),
        "{result}"
    );
    assert_eq!(upstream.requests.load(Ordering::SeqCst), 1, "{result}");
    let head = upstream.last_head.lock().unwrap().clone();
    assert!(head.starts_with("GET /bucket/k.txt"), "{head}");
    assert!(
        !head.contains(hex),
        "the token reached the upstream: {head}"
    );
    let auth = upstream.last_auth.lock().unwrap().clone();
    assert!(auth.contains("/eu-central-003/s3/aws4_request"), "{auth}");

    let presigned = result["presigned"].as_str().unwrap();
    assert!(
        presigned.contains(&format!("/{hex}/bucket/k.txt")),
        "control: the client presigns on the endpoint url: {presigned}"
    );
    assert_eq!(result["status"], 200, "{result}");
    let signed = result["signed"].as_str().unwrap();
    assert!(
        signed.starts_with("https://api.stripe.com/bucket/k.txt?"),
        "{signed}"
    );
    assert!(
        !signed.contains(hex),
        "the presigned url carries the token: {signed}"
    );
    assert_eq!(
        upstream.requests.load(Ordering::SeqCst),
        1,
        "presigning never calls upstream"
    );
}
