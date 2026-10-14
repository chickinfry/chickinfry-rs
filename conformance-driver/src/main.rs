use std::io::{self, BufReader};
use std::os::fd::FromRawFd;
use std::os::unix::fs::FileTypeExt;

unsafe extern "C" {
    fn fcntl(fd: std::ffi::c_int, command: std::ffi::c_int, ...) -> std::ffi::c_int;
}

fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if !valid_sdk_args(&args) {
        eprintln!("invalid driver arguments");
        std::process::exit(2);
    }
    // F_GETFD validates the inherited descriptor before Rust assumes ownership.
    if unsafe { fcntl(3, 1) } < 0 {
        eprintln!("credential pipe unavailable");
        std::process::exit(2);
    }
    // SAFETY: fd 3 is open and exclusively transferred by the coordinator.
    let credentials = unsafe { std::fs::File::from_raw_fd(3) };
    std::panic::set_hook(Box::new(|_| eprintln!("driver execution failed")));
    if !credentials
        .metadata()
        .is_ok_and(|m| m.file_type().is_fifo())
    {
        eprintln!("credential pipe unavailable");
        std::process::exit(2);
    }
    let result = std::panic::catch_unwind(|| {
        chickinfry_conformance_driver::run(
            io::stdin().lock(),
            io::stdout(),
            &mut BufReader::new(credentials),
        )
    });
    if !matches!(result, Ok(Ok(()))) {
        eprintln!("driver failed");
        std::process::exit(2);
    }
}

fn valid_sdk_args(args: &[std::ffi::OsString]) -> bool {
    match args {
        [] => true,
        [plain, plain_path, auth, auth_path] => {
            plain == "--plain-sdk"
                && auth == "--auth-sdk"
                && !plain_path.is_empty()
                && !auth_path.is_empty()
        }
        _ => false,
    }
}

#[test]
fn accepts_only_coordinator_sdk_paths_or_standalone_launch() {
    assert!(valid_sdk_args(&[]));
    for (args, expected) in [
        (vec!["--plain-sdk", "/plain", "--auth-sdk", "/auth"], true),
        (vec!["--plain-sdk", "/plain"], false),
        (vec!["--plain-sdk", "", "--auth-sdk", "/auth"], false),
        (vec!["--fixture", "plain"], false),
    ] {
        let args: Vec<_> = args.into_iter().map(Into::into).collect();
        assert_eq!(valid_sdk_args(&args), expected);
    }
}
