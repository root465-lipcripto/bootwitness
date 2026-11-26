use std::{
    io::{self, Read, Write},
    process::{Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

#[derive(Debug)]
pub struct ProcessOutput {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub timed_out: bool,
    pub output_truncated: bool,
}

const POLL_INTERVAL: Duration = Duration::from_millis(20);

pub fn run_bounded(
    command: &mut Command,
    timeout: Duration,
    max_output_bytes: usize,
) -> io::Result<ProcessOutput> {
    run_bounded_with_input(command, None, timeout, max_output_bytes)
}

pub fn run_bounded_with_input(
    command: &mut Command,
    input: Option<Vec<u8>>,
    timeout: Duration,
    max_output_bytes: usize,
) -> io::Result<ProcessOutput> {
    command
        .stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn()?;
    let stdout = child.stdout.take().expect("stdout was configured as piped");
    let stderr = child.stderr.take().expect("stderr was configured as piped");
    let stdout_reader = thread::spawn(move || read_limited(stdout, max_output_bytes));
    let stderr_reader = thread::spawn(move || read_limited(stderr, max_output_bytes));
    let input_writer = input.map(|bytes| {
        let mut stdin = child.stdin.take().expect("stdin was configured as piped");
        thread::spawn(move || stdin.write_all(&bytes))
    });

    let deadline = Instant::now() + timeout;
    let (status, timed_out) = loop {
        match child.try_wait() {
            Ok(Some(status)) => break (status, false),
            Ok(None) if Instant::now() < deadline => thread::sleep(POLL_INTERVAL),
            Ok(None) => {
                // Ignore a kill error if the child exited between try_wait and kill.
                let _ = child.kill();
                break (child.wait()?, true);
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        }
    };

    let (stdout, stdout_truncated) = stdout_reader
        .join()
        .map_err(|_| io::Error::other("stdout reader thread panicked"))??;
    let (stderr, stderr_truncated) = stderr_reader
        .join()
        .map_err(|_| io::Error::other("stderr reader thread panicked"))??;
    if let Some(writer) = input_writer {
        match writer.join() {
            Ok(Ok(())) => {}
            // A killed process may close stdin before all input was written.
            Ok(Err(error)) if timed_out && error.kind() == io::ErrorKind::BrokenPipe => {}
            Ok(Err(error)) => return Err(error),
            Err(_) => return Err(io::Error::other("stdin writer thread panicked")),
        }
    }

    Ok(ProcessOutput {
        status,
        stdout,
        stderr,
        timed_out,
        output_truncated: stdout_truncated || stderr_truncated,
    })
}

fn read_limited<R: Read>(mut reader: R, limit: usize) -> io::Result<(Vec<u8>, bool)> {
    let mut bytes = Vec::with_capacity(limit.min(64 * 1024));
    let mut buffer = [0_u8; 8192];
    let mut truncated = false;

    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        let remaining = limit.saturating_sub(bytes.len());
        let kept = count.min(remaining);
        bytes.extend_from_slice(&buffer[..kept]);
        truncated |= kept < count;
        // Continue draining after the cap so the child doesn't fail with a broken pipe.
    }

    Ok((bytes, truncated))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captures_output_and_reports_nonzero_exit() {
        let mut command = Command::new("sh");
        command.args(["-c", "printf out; printf err >&2; exit 7"]);
        let result = run_bounded(&mut command, Duration::from_secs(2), 1024).unwrap();
        assert_eq!(result.stdout, b"out");
        assert_eq!(result.stderr, b"err");
        assert_eq!(result.status.code(), Some(7));
        assert!(!result.timed_out);
    }

    #[test]
    fn kills_a_process_after_its_deadline() {
        let mut command = Command::new("sleep");
        command.arg("2");
        let result = run_bounded(&mut command, Duration::from_millis(50), 1024).unwrap();
        assert!(result.timed_out);
    }

    #[test]
    fn bounds_child_output() {
        let mut command = Command::new("printf");
        command.arg("0123456789");
        let result = run_bounded(&mut command, Duration::from_secs(2), 5).unwrap();
        assert_eq!(result.stdout, b"01234");
        assert!(result.output_truncated);
    }
}
