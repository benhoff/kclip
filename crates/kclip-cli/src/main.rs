use clap::Parser;
use kclip_cli::{Cli, execute};
use std::io;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    if let Err(error) = execute(&cli, &mut input, &mut output).await {
        if error.already_reported() {
            // The command already emitted its complete human or JSON result.
        } else if cli.json {
            let value = serde_json::json!({
                "error": error.to_string(),
                "exit_code": error.exit_code(),
            });
            eprintln!("{value}");
        } else {
            eprintln!("kclip: {error}");
        }
        std::process::exit(error.exit_code().into());
    }
}
