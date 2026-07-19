//! # ec-secrets — binary entry point
//!
//! Wires the pure logic in [`ec_secrets`] to a live EdgeCommons credentials vault. It parses the
//! CLI, opens the local vault the same way a component's runtime does
//! ([`ec_secrets::open_service`] → [`edgecommons::credentials::open_namespaced_with_default`]),
//! and dispatches the subcommand ([`ec_secrets::run`]). stdout carries the command output (values,
//! listings, JSON); logs and diagnostics go to stderr.
//!
//! Everything the tool writes is byte-compatible with what a component decrypts — the vault
//! crypto, KeyProvider/KEK, on-disk format, and key namespacing are all the library's.

use std::process::ExitCode as ProcExitCode;

use clap::Parser;

use ec_secrets::{Cli, ExitCode, open_service, run};

fn main() -> ProcExitCode {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    // Open the vault exactly as a component would (build the CredentialsConfig from the flags /
    // reused `credentials` block, then the library's open_namespaced_with_default).
    let svc = match open_service(&cli) {
        Ok(svc) => svc,
        Err(e) => {
            eprintln!("ec-secrets: {e:#}");
            return ProcExitCode::from(ExitCode::VaultError.code() as u8);
        }
    };

    let exit = match run(&cli, &svc) {
        Ok(code) => code,
        Err(e) => {
            // Usage/parse/IO failures surfaced from the subcommand (broker-independent).
            eprintln!("ec-secrets: {e:#}");
            ExitCode::VaultError
        }
    };
    ProcExitCode::from(exit.code() as u8)
}

/// Initialize stderr logging (default WARN; --verbose lifts to DEBUG). stdout is reserved for
/// command output so the tool is pipe-friendly.
fn init_tracing(verbose: bool) {
    let default = if verbose { "debug" } else { "warn" };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}
