use broker_server::{
    ServerError, bootstrap_local_administrator, default_config_path, load_config, serve,
};
use clap::Parser;
use std::{
    io::{IsTerminal, Read},
    path::PathBuf,
    process::ExitCode,
    time::Duration,
};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "graphit-broker", version, about = "Graphit Broker server")]
struct Cli {
    #[arg(long, env = "GRAPHIT_BROKER_CONFIG")]
    config: Option<PathBuf>,
    #[arg(long, conflicts_with = "healthcheck")]
    check_config: bool,
    /// Create the first LOCAL administrator from protected, non-terminal stdin.
    #[arg(long, conflicts_with_all = ["check_config", "healthcheck"])]
    bootstrap_admin_stdin: bool,
    #[arg(long, value_name = "URL", conflicts_with = "config")]
    healthcheck: Option<String>,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
async fn run() -> Result<(), ServerError> {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) =>
        {
            error.print().map_err(|_| ServerError::Configuration)?;
            return Ok(());
        }
        Err(_) => return Err(ServerError::Configuration),
    };
    if let Some(url) = cli.healthcheck {
        let url = reqwest::Url::parse(&url).map_err(|_| ServerError::Configuration)?;
        if !matches!(url.scheme(), "http" | "https")
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(ServerError::Configuration);
        }
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| ServerError::Listener)?;
        let result = client
            .get(url)
            .send()
            .await
            .map_err(|_| ServerError::Listener)?;
        return if result.status().is_success() {
            Ok(())
        } else {
            Err(ServerError::Listener)
        };
    }
    let path = match cli.config {
        Some(path) => path,
        None => default_config_path()?,
    };
    let config = load_config(&path).await?;
    if cli.check_config {
        config.shutdown_models().await?;
        println!("configuration valid");
        return Ok(());
    }
    if cli.bootstrap_admin_stdin {
        let password = initial_administrator_password()?;
        bootstrap_local_administrator(config, &password).await?;
        println!("local administrator created");
        return Ok(());
    }
    // Install signal handlers before opening the database or admitting HTTP.
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(|_| ServerError::Signal)?;
        let mut interrupt =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                .map_err(|_| ServerError::Signal)?;
        serve(config, async move {
            tokio::select! {_ = terminate.recv()=>{},_ = interrupt.recv()=>{}};
            Ok(())
        })
        .await
    }
    #[cfg(not(unix))]
    {
        serve(config, async {
            tokio::signal::ctrl_c()
                .await
                .map_err(|_| ServerError::Signal)
        })
        .await
    }
}

fn initial_administrator_password() -> Result<Zeroizing<String>, ServerError> {
    let input = std::io::stdin();
    if input.is_terminal() {
        return Err(ServerError::AdministratorInput);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    input
        .lock()
        .take((broker_security::LOCAL_PASSWORD_MAX_BYTES + 3) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ServerError::AdministratorInput)?;
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    let password = std::str::from_utf8(&bytes).map_err(|_| ServerError::AdministratorInput)?;
    broker_control::validate_initial_administrator_password(password)
        .map_err(|_| ServerError::AdministratorInput)?;
    Ok(Zeroizing::new(password.to_owned()))
}
