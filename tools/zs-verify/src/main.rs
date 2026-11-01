mod cli;
mod report;
mod runner;
mod scan;
mod tokenize;
mod upstream;
mod workspace;

fn main() {
    let code = match cli::parse(std::env::args().skip(1)) {
        Ok(args) => runner::run(args),
        Err(message) => {
            eprintln!("zs-verify: {message}");
            2
        }
    };
    std::process::exit(code);
}
