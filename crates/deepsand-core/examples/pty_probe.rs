//! Run one command inside the app's exact PTY path and stream its output with timestamps.
//!
//! `cargo run --example pty_probe -- <program> [args...]`
//!
//! The point is to reproduce a launch hang *outside* the app: the same `Session::spawn` the app
//! uses, the same ConPTY, the same reader loop -- just with the program of your choice. Watching
//! which step the timestamps stop after tells you whether the hang is the terminal creation, the
//! child itself, or the output plumbing.

use std::io::Write;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::{Duration, Instant};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: pty_probe <program> [args...]");
        std::process::exit(2);
    }
    let program = PathBuf::from(&args[0]);
    let started = Instant::now();
    let (tx, rx) = mpsc::channel::<Vec<u8>>();

    let session = deepsand_core::session::Session::spawn(
        deepsand_core::session::SessionOptions {
            program: program.clone(),
            args: args[1..].to_vec(),
            cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            env: vec![],
            rows: 40,
            cols: 120,
        },
        move |chunk| {
            let _ = tx.send(chunk.to_vec());
        },
        move |code| {
            eprintln!("[probe] exit code {code} at {:?}", started.elapsed());
        },
    )
    .expect("session spawn");

    eprintln!("[probe] spawned at {:?}", started.elapsed());

    let mut stdout = std::io::stdout();
    let deadline = Instant::now() + Duration::from_secs(25);
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(50)) {
            Ok(chunk) => {
                eprintln!("[probe] +{} bytes at {:?}", chunk.len(), started.elapsed());
                let _ = stdout.write_all(&chunk);
                let _ = stdout.flush();
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                eprintln!("[probe] PTY closed at {:?}", started.elapsed());
                break;
            }
        }
    }
    eprintln!("[probe] done at {:?}", started.elapsed());
    drop(session);
}
