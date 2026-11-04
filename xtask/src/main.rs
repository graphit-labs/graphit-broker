use std::{env, process::ExitCode};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.as_slice() {
        [command, rest @ ..] if command == "build" => {
            let mut debug = false;
            let mut output = std::path::PathBuf::from(if cfg!(windows) {
                "graphit-broker.exe"
            } else {
                "graphit-broker"
            });
            let mut options = rest.iter();
            while let Some(option) = options.next() {
                match option.as_str() {
                    "--debug" if !debug => debug = true,
                    "--output" => {
                        let Some(path) = options.next().filter(|p| !p.is_empty()) else {
                            eprintln!("build --output requires a path");
                            return ExitCode::FAILURE;
                        };
                        output = path.into();
                    }
                    _ => {
                        eprintln!("usage: xtask build [--debug] [--output PATH]");
                        return ExitCode::FAILURE;
                    }
                }
            }
            match xtask::build::build(debug, &output) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("{error}");
                    ExitCode::FAILURE
                }
            }
        }
        [command, rest @ ..] if command == "package" => {
            let mut debug = false;
            let mut output = None;
            let mut binary = None;
            let mut artifacts = None;
            let mut options = rest.iter();
            while let Some(option) = options.next() {
                match option.as_str() {
                    "--debug" if !debug => debug = true,
                    "--binary" if binary.is_none() => {
                        binary = options
                            .next()
                            .filter(|p| !p.is_empty())
                            .map(std::path::PathBuf::from);
                        if binary.is_none() {
                            eprintln!("package --binary requires a path");
                            return ExitCode::FAILURE;
                        }
                    }
                    "--cargo-artifacts" if artifacts.is_none() => {
                        artifacts = options
                            .next()
                            .filter(|p| !p.is_empty())
                            .map(std::path::PathBuf::from);
                        if artifacts.is_none() {
                            eprintln!("package --cargo-artifacts requires a path");
                            return ExitCode::FAILURE;
                        }
                    }
                    "--output" if output.is_none() => {
                        output = options
                            .next()
                            .filter(|p| !p.is_empty())
                            .map(std::path::PathBuf::from);
                        if output.is_none() {
                            eprintln!("package --output requires a directory");
                            return ExitCode::FAILURE;
                        }
                    }
                    _ => {
                        eprintln!(
                            "usage: xtask package [--debug | --binary PATH [--cargo-artifacts PATH]] --output DIR"
                        );
                        return ExitCode::FAILURE;
                    }
                }
            }
            let Some(output) = output else {
                eprintln!("package requires an explicit new --output DIR");
                return ExitCode::FAILURE;
            };
            if artifacts.is_some() && binary.is_none() {
                eprintln!("package --cargo-artifacts requires --binary");
                return ExitCode::FAILURE;
            }
            if debug && binary.is_some() {
                eprintln!("package --binary cannot be combined with --debug");
                return ExitCode::FAILURE;
            }
            match xtask::package::package(debug, &output, binary.as_deref(), artifacts.as_deref()) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("{error}");
                    ExitCode::FAILURE
                }
            }
        }
        [command, event] if command == "hook" => {
            let Some(event) = xtask::parse_event(event) else {
                eprintln!("unknown hook event");
                return ExitCode::FAILURE;
            };
            let paths = if event == xtask::Event::PreCommit {
                match xtask::staged_paths() {
                    Ok(paths) => paths,
                    Err(_) => {
                        eprintln!("cannot inspect staged paths");
                        return ExitCode::FAILURE;
                    }
                }
            } else {
                Vec::new()
            };
            run_checks(xtask::checks(event, &paths))
        }
        [command] if command == "qualify" => run_checks(xtask::qualification_checks()),
        _ => {
            eprintln!(
                "usage: xtask build [--debug] [--output PATH] | package [--debug | --binary PATH [--cargo-artifacts PATH]] --output DIR | hook pre-commit|pre-push | qualify"
            );
            ExitCode::FAILURE
        }
    }
}

fn run_checks(checks: Vec<xtask::Check>) -> ExitCode {
    for check in checks {
        match xtask::execute(check) {
            Ok(status) if status.success() => {}
            Ok(status) => {
                eprintln!("broker check failed: {} ({status})", check.program);
                return ExitCode::FAILURE;
            }
            Err(error) => {
                eprintln!("cannot launch broker check: {}: {error}", check.program);
                return ExitCode::FAILURE;
            }
        }
    }
    ExitCode::SUCCESS
}
