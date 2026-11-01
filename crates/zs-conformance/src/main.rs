use std::path::PathBuf;
use std::process::ExitCode;

use zs_conformance::config;
use zs_conformance::runner;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("run") => run(&args[1..]),
        _ => {
            eprintln!("usage: zs-conformance run --config <path> [--allow-skips]");
            ExitCode::from(2)
        }
    }
}

fn run(args: &[String]) -> ExitCode {
    let mut config_path: Option<PathBuf> = None;
    let mut allow_skips = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--config" => {
                index += 1;
                match args.get(index) {
                    Some(path) => config_path = Some(PathBuf::from(path)),
                    None => {
                        eprintln!("--config needs a path");
                        return ExitCode::from(2);
                    }
                }
            }
            "--allow-skips" => allow_skips = true,
            other => {
                eprintln!("unknown argument: {other}");
                return ExitCode::from(2);
            }
        }
        index += 1;
    }
    let Some(path) = config_path else {
        eprintln!("--config is required");
        return ExitCode::from(2);
    };
    let config = match config::load(&path) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(2);
        }
    };
    let report = runner::run_all(&config, allow_skips);
    print!("{}", report.to_markdown());
    if let Err(error) = report.write_json(&runner::report_path()) {
        eprintln!("cannot write the report: {error}");
        return ExitCode::from(2);
    }
    ExitCode::from(report.exit_code(allow_skips) as u8)
}
