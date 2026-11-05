//! Bounded process IO for explicit infrastructure qualifications.
use std::{
    io::{self, Read, Seek, SeekFrom, Write},
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        // Covers IO failures and assertion unwinding as well as normal timeout.
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

pub fn output(command: &mut Command, input: &[u8], end: Instant) -> io::Result<Output> {
    let mut stdin = tempfile::tempfile()?;
    stdin.write_all(input)?;
    stdin.seek(SeekFrom::Start(0))?;
    let mut stdout = tempfile::tempfile()?;
    let mut stderr = tempfile::tempfile()?;
    command
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::from(stdout.try_clone()?))
        .stderr(Stdio::from(stderr.try_clone()?));
    let mut child = OwnedChild(command.spawn()?);
    let status = loop {
        if let Some(status) = child.0.try_wait()? {
            break status;
        }
        let remaining = end.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            child.0.kill()?;
            child.0.wait()?;
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "fixture process deadline",
            ));
        }
        std::thread::sleep(remaining.min(Duration::from_millis(5)));
    };
    stdout.seek(SeekFrom::Start(0))?;
    stderr.seek(SeekFrom::Start(0))?;
    let mut out = Vec::new();
    let mut err = Vec::new();
    stdout.read_to_end(&mut out)?;
    stderr.read_to_end(&mut err)?;
    Ok(Output {
        status,
        stdout: out,
        stderr: err,
    })
}
