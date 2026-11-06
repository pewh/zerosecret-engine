use std::io::Write;

const AGENT_INSTRUCTIONS: &str = r#"
You are integrating ZeroSecret into this application repository.
Rule 1: The application must hold ZERO credentials in .env, configuration files, or memory.
Rule 2: Never print, log, or copy credential values. Refer to secrets by key name only.

Procedure:
1. Verify environment:
   Run `zs status --json`. If `signed_in` or `enrolled` is false, ask the developer to run `zs login`.
2. Inspect schema:
   Run `zs schema` to get the JSON Schema for `zs-policy.json` that this zs version accepts.
3. Preview:
   Run `zs init --dry-run`. Review the generated bindings and every key listed as not brokered.
4. Scaffold:
   Run `zs init` to write `zs-policy.json`, back up `.env` to `~/.zs-backups/<project>/` with 0600 permissions, and replace brokered secrets with placeholders.
   For each key listed as not brokered, ask the developer how to handle it. Do not copy its value anywhere.
5. Wrap startup commands:
   Prefix application run scripts (package.json, Makefile, Dockerfile) with `zs run -- <command>`.
6. Validate:
   Run `zs doctor --json` and confirm that `status` is "ok". Then run the application tests."#;

pub fn print_instructions() -> i32 {
    stdout_line!(
        "# ZeroSecret Integration Protocol (zs {}){AGENT_INSTRUCTIONS}",
        env!("CARGO_PKG_VERSION")
    );
    0
}
