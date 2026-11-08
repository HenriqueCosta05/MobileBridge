//! mobile-bridge command-line interface.

mod cli;
mod commands;
mod config;
mod context;
mod error;
mod output;

use std::process::ExitCode;

use clap::{CommandFactory, Parser};

use crate::cli::{AppsCommand, Cli, Command, DevicesCommand, SessionsCommand};
use crate::commands::sessions::EventOrder;
use crate::commands::{apps, devices, doctor, record, sessions};
use crate::context::Context;
use crate::error::{CliError, ExitStatus};

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let verbose = cli.global.verbose;
    match run(cli).await {
        Ok(()) => ExitStatus::Success.into(),
        Err(error) => {
            report_error(&error, verbose);
            error.status.into()
        }
    }
}

async fn run(cli: Cli) -> Result<(), CliError> {
    if let Command::Completions { shell } = cli.command {
        clap_complete::generate(
            shell,
            &mut Cli::command(),
            "mobile-bridge",
            &mut std::io::stdout(),
        );
        return Ok(());
    }
    let context = Context::new(cli.global)?;
    match cli.command {
        Command::Doctor => doctor::run(&context).await,
        Command::Devices(DevicesCommand::List { watch }) => devices::list(&context, watch).await,
        Command::Devices(DevicesCommand::Show { app }) => devices::show(&context, app).await,
        Command::Apps(AppsCommand::List {
            third_party,
            running,
            filter,
        }) => apps::list(&context, third_party, running, filter).await,
        Command::Apps(AppsCommand::Processes { app }) => apps::processes(&context, app).await,
        Command::Record(args) => record::run(&context, args).await,
        Command::Sessions(command) => run_sessions(&context, command),
        Command::Completions { .. } => Ok(()),
    }
}

fn run_sessions(context: &Context, command: SessionsCommand) -> Result<(), CliError> {
    match command {
        SessionsCommand::List => sessions::list(context),
        SessionsCommand::Show { session } => sessions::show(context, &session),
        SessionsCommand::Events { session, filter } => {
            sessions::events(context, &session, filter, EventOrder::Collection)
        }
        SessionsCommand::Timeline { session, filter } => {
            sessions::events(context, &session, filter, EventOrder::Chronological)
        }
        SessionsCommand::Analyze { session } => sessions::analyze_session(context, &session),
        SessionsCommand::Export {
            session,
            export_format,
            output,
            force,
        } => sessions::export(context, &session, export_format, &output, force),
        SessionsCommand::Delete { session, yes } => sessions::delete(context, &session, yes),
    }
}

fn report_error(error: &CliError, verbose: bool) {
    if error.status == ExitStatus::Partial {
        eprintln!("warning: {}", error.message);
        if let Some(remediation) = &error.remediation {
            eprintln!("  hint: {remediation}");
        }
    } else {
        eprintln!("{error}");
    }
    if verbose {
        eprintln!("  exit code: {}", error.status as u8);
    }
}
