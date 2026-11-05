#[path = "../../broker-control/tests/support/command.rs"]
mod command;

use std::{
    io::{Read, Write},
    process::Command,
    time::{Duration, Instant},
};

fn child(mode: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "process_child", "--ignored", "--nocapture"])
        .env("BROKER_PROCESS_FIXTURE_CHILD", mode);
    command
}

#[test]
fn bounded_fixture_drains_large_input_and_both_outputs() {
    let input = vec![b'x'; 256 * 1024];
    let result = command::output(
        &mut child("echo"),
        &input,
        Instant::now() + Duration::from_secs(10),
    )
    .unwrap();
    assert!(result.status.success());
    // The harness adds its own output; the entire request must remain contiguous.
    assert!(
        result
            .stdout
            .windows(input.len())
            .any(|window| window == input)
    );
    assert!(result.stderr.ends_with(b"fixture-stderr"));
}

#[test]
fn bounded_fixture_terminates_and_reaps_a_stalled_child() {
    let result = command::output(
        &mut child("stall"),
        &[],
        Instant::now() + Duration::from_millis(100),
    );
    assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    let next = command::output(
        &mut child("echo"),
        b"after timeout",
        Instant::now() + Duration::from_secs(10),
    )
    .unwrap();
    assert!(next.status.success());
    assert!(
        next.stdout
            .windows(13)
            .any(|window| window == b"after timeout")
    );
}

#[test]
#[ignore = "launched only by the bounded-process tests with private child input"]
fn process_child() {
    match std::env::var("BROKER_PROCESS_FIXTURE_CHILD").as_deref() {
        Ok("echo") => {
            let mut input = Vec::new();
            std::io::stdin().read_to_end(&mut input).unwrap();
            std::io::stdout().write_all(&input).unwrap();
            std::io::stderr().write_all(b"fixture-stderr").unwrap();
        }
        Ok("stall") => loop {
            std::thread::park();
        },
        _ => panic!("parent-owned process fixture required"),
    }
}
