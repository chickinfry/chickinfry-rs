use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

fn test_root() -> PathBuf {
    std::env::current_dir()
        .unwrap()
        .join(std::env::var_os("CARGO_TARGET_DIR").unwrap_or_else(|| "target".into()))
}

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = test_root().join("test-home").join(format!(
            "device-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        Self(root)
    }
    fn scope(&self) -> Scope {
        Scope {
            app: "test-app".into(),
            origin: "https://example.com".into(),
            project: "test-project".into(),
        }
    }
    fn open(&self) -> Device {
        Device::open(&self.0, self.scope()).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if self.0.exists() {
            let manifest = test_root().join(format!(
                "cleanup-{}-{}.txt",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::write(manifest, self.0.as_os_str().as_encoded_bytes()).unwrap();
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
}
fn key(owner: &str, kind: &str) -> Key {
    Key {
        owner: owner.into(),
        kind: kind.into(),
    }
}

#[test]
fn tombstone_rejects_late_recreation_after_restart() {
    let f = Fixture::new();
    let d = f.open();
    let mut state = d.read().unwrap();
    state
        .records
        .insert(key("user-a", "session"), b"synthetic-session".to_vec());
    assert!(d.replace(0, state).unwrap());
    let old = d.read().unwrap();
    assert!(d.clear(old.generation).unwrap());
    drop(d);
    let reopened = f.open();
    assert!(reopened.read().unwrap().records.is_empty());
    assert!(!reopened.replace(old.generation, old).unwrap());
}

#[test]
fn generation_compare_prevents_lost_updates_and_separates_owners() {
    let f = Fixture::new();
    let d = f.open();
    let other = f.open();
    let mut state = d.read().unwrap();
    state
        .records
        .insert(key("screen-a", "attempt"), b"first".to_vec());
    state
        .records
        .insert(key("screen-b", "attempt"), b"second".to_vec());
    state
        .records
        .insert(key("user-a", "session"), b"third".to_vec());
    assert!(d.replace(0, state.clone()).unwrap());
    assert!(!other.replace(0, Snapshot::default()).unwrap());
    let mut state = other.read().unwrap();
    state.records.remove(&key("screen-a", "attempt"));
    let generation = state.generation;
    assert!(other.replace(generation, state).unwrap());
    let state = d.read().unwrap();
    assert!(!state.records.contains_key(&key("screen-a", "attempt")));
    assert!(state.records.contains_key(&key("screen-b", "attempt")));
    assert!(state.records.contains_key(&key("user-a", "session")));
    let mut scope = f.scope();
    scope.project = "other-project".into();
    assert!(
        Device::open(&f.0, scope)
            .unwrap()
            .read()
            .unwrap()
            .records
            .is_empty()
    );
}

#[test]
fn killed_refresh_sender_cannot_reuse_its_claim() {
    let f = Fixture::new();
    assert!(child(&f, "write").wait().unwrap().success());
    let mut process = child(&f, "claimed-and-waiting");
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !f.0.join("claimed").exists() && std::time::Instant::now() < deadline {
        if process.try_wait().unwrap().is_some() {
            panic!("sender ended before claim checkpoint");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let claimed = f.0.join("claimed").exists();
    process.kill().unwrap();
    process.wait().unwrap();
    assert!(claimed);
    let reopened = f.open();
    let state = reopened.read().unwrap();
    let session = key("user-a", "session");
    assert!(state.refreshing.contains(&session));
    assert!(
        reopened
            .claim_refresh(state.generation, &session)
            .unwrap()
            .is_none()
    );
}

#[cfg(unix)]
#[test]
fn rejects_unsafe_permissions_and_symlink_sidecars_without_repair() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let f = Fixture::new();
    let d = f.open();
    assert!(d.replace(0, Snapshot::default()).unwrap());
    let path = d.path("json");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(d.read().is_err());
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o644
    );
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&path, d.path("tmp")).unwrap();
    assert!(d.read().is_err());
    std::fs::remove_file(d.path("tmp")).unwrap();
    assert!(d.read().is_ok());
}

#[test]
fn corrupt_and_newer_files_are_preserved_and_blocked() {
    let f = Fixture::new();
    let d = f.open();
    assert!(d.replace(0, Snapshot::default()).unwrap());
    let path = d.path("json");
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    value["version"] = serde_json::json!(99);
    value["future_field"] = serde_json::json!(true);
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    let before = std::fs::read(&path).unwrap();
    assert!(
        matches!(Device::open(&f.0, f.scope()), Err(ClientError::Protocol(code)) if code == "device_storage_version_unsupported")
    );
    assert!(std::fs::read(&path).unwrap() == before);
    std::fs::write(&path, b"corrupt data").unwrap();
    assert!(
        matches!(Device::open(&f.0, f.scope()), Err(ClientError::Protocol(code)) if code == "device_storage_corrupt")
    );
    assert!(std::fs::read(&path).unwrap() == b"corrupt data");
}

fn command(program: &std::ffi::OsStr) -> std::process::Command {
    let mut command = std::process::Command::new(program);
    command.env_clear();
    for name in [
        "PATH",
        "CARGO_TARGET_DIR",
        "SystemRoot",
        "WINDIR",
        "TEMP",
        "TMP",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command.env("LANG", "C").env("LC_ALL", "C");
    command
}

fn child(f: &Fixture, mode: &str) -> std::process::Child {
    command(std::env::current_exe().unwrap().as_os_str())
        .args([
            "--exact",
            "client::device::tests::subprocess",
            "--nocapture",
        ])
        .env("HOME", &f.0)
        .env(
            "XDG_STATE_HOME",
            if mode.starts_with("relative-") {
                PathBuf::from("relative")
            } else {
                f.0.join("state")
            },
        )
        .env("LOCALAPPDATA", f.0.join("state"))
        .env("DEVICE_CHILD_ROOT", &f.0)
        .env("DEVICE_CHILD_MODE", mode)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap()
}

#[test]
fn subprocess() {
    let Some(root) = std::env::var_os("DEVICE_CHILD_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let scope = Scope {
        app: "test-app".into(),
        origin: "https://example.com".into(),
        project: "test-project".into(),
    };
    let mode = std::env::var("DEVICE_CHILD_MODE").unwrap();
    let opened = Device::open(&root, scope.clone());
    let d = match opened {
        Ok(device) => device,
        Err(ClientError::Protocol(code))
            if matches!(mode.as_str(), "competing-write" | "claim")
                && code == "device_storage_unavailable" =>
        {
            std::process::exit(8)
        }
        Err(_) => panic!("test device open failed"),
    };
    match mode.as_str() {
        "pinned-dir-write" | "pinned-dir-read" => {
            use crate::client::Client;
            std::env::set_current_dir(&root).unwrap();
            let client = Client::new("https://example.com").unwrap();
            assert!(
                matches!(client.with_persist(Persist::Dir(PathBuf::new())), Err(ClientError::Protocol(code)) if code == "device_storage_unavailable")
            );
            let client = client.with_persist(Persist::Dir("nested".into())).unwrap();
            std::env::set_current_dir(root.parent().unwrap()).unwrap();
            let store = client.device_store(scope).unwrap().unwrap();
            assert!(store.root == root.join("nested"));
            if mode == "pinned-dir-write" {
                let mut state = store.read().unwrap();
                let mut value = vec![0u8; 32];
                getrandom::getrandom(&mut value).unwrap();
                state.records.insert(key("user-a", "session"), value);
                assert!(store.replace(0, state).unwrap());
            } else {
                let state = store.read().unwrap();
                assert_eq!(state.generation, 1);
                assert!(state.records.contains_key(&key("user-a", "session")));
            }
        }
        "default-write" | "default-read" | "relative-write" | "relative-read" => {
            let client = crate::client::Client::new("https://example.com").unwrap();
            let store = client.device_store(scope).unwrap().unwrap();
            if matches!(mode.as_str(), "default-write" | "relative-write") {
                let mut state = store.read().unwrap();
                state
                    .records
                    .insert(key("user-a", "session"), b"default-session".to_vec());
                assert!(store.replace(state.generation, state).unwrap());
            } else {
                assert!(
                    store
                        .read()
                        .unwrap()
                        .records
                        .get(&key("user-a", "session"))
                        .is_some_and(|value| value == b"default-session")
                );
            }
        }
        "write" | "host-write" => {
            let mut state = d.read().unwrap();
            state
                .records
                .insert(key("user-a", "session"), b"subprocess-session".to_vec());
            assert!(d.replace(state.generation, state).unwrap());
        }
        "read" | "host-read" => assert!(
            d.read()
                .unwrap()
                .records
                .get(&key("user-a", "session"))
                .is_some_and(|value| value == b"subprocess-session")
        ),
        "empty" | "host-empty" => assert!(d.read().unwrap().records.is_empty()),
        "claimed-and-waiting" => {
            let state = d.read().unwrap();
            assert!(
                d.claim_refresh(state.generation, &key("user-a", "session"))
                    .unwrap()
                    .is_some()
            );
            std::fs::write(root.join("claimed"), b"claimed").unwrap();
            loop {
                std::thread::park();
            }
        }
        "claim" => {
            let outcome = d
                .read()
                .and_then(|state| d.claim_refresh(state.generation, &key("user-a", "session")));
            match outcome {
                Ok(Some(_)) => (),
                Ok(None) => std::process::exit(7),
                Err(ClientError::Protocol(code)) if code == "device_storage_unavailable" => {
                    std::process::exit(8)
                }
                Err(_) => panic!("refresh claim failed"),
            }
        }
        "paused-write" | "competing-write" => {
            let mut state = d.read().unwrap();
            state
                .records
                .insert(key("user-a", "session"), b"competing-session".to_vec());
            match d.replace(state.generation, state) {
                Ok(true) => (),
                Ok(false) => std::process::exit(7),
                Err(_) => std::process::exit(8),
            }
        }
        "uncommitted" => {
            let mut state = d.read().unwrap();
            state.records.clear();
            d.replace(state.generation, state).unwrap();
        }
        _ => panic!("invalid test mode"),
    }
}

#[test]
fn process_restart_restores_and_logout_stays_deleted() {
    let f = Fixture::new();
    assert!(child(&f, "write").wait().unwrap().success());
    assert!(child(&f, "read").wait().unwrap().success());
    let d = f.open();
    assert!(d.clear(d.read().unwrap().generation).unwrap());
    assert!(child(&f, "empty").wait().unwrap().success());
}

#[test]
fn process_refresh_race_allows_only_one_claim() {
    let f = Fixture::new();
    assert!(child(&f, "write").wait().unwrap().success());
    let mut first = child(&f, "claim");
    let mut second = child(&f, "claim");
    let codes = [
        first.wait().unwrap().code().unwrap(),
        second.wait().unwrap().code().unwrap(),
    ];
    assert!(codes.iter().all(|code| [0, 7, 8].contains(code)));
    assert_eq!(codes.iter().filter(|code| **code == 0).count(), 1);
    assert!(
        f.open()
            .read()
            .unwrap()
            .refreshing
            .contains(&key("user-a", "session"))
    );
}

#[test]
fn failed_refresh_commit_preserves_marker_and_blocks_reuse_after_restart() {
    let f = Fixture::new();
    assert!(child(&f, "write").wait().unwrap().success());
    let d = f.open();
    let session = key("user-a", "session");
    let before = d.read().unwrap();
    let claimed = d
        .claim_refresh(before.generation, &session)
        .unwrap()
        .unwrap();
    let mut next = claimed.clone();
    let mut replacement = vec![0u8; 32];
    getrandom::getrandom(&mut replacement).unwrap();
    next.records.insert(session.clone(), replacement);
    next.refreshing.clear();

    let staging = d.path("tmp");
    drop(files::create(&staging).unwrap());
    #[cfg(unix)]
    let restore = {
        use std::os::unix::fs::PermissionsExt;
        let restore = std::fs::metadata(&staging).unwrap().permissions();
        std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o400)).unwrap();
        restore
    };
    #[cfg(windows)]
    let blocker = {
        use std::os::windows::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&staging)
            .unwrap()
    };
    let result = d.replace(claimed.generation, next);
    #[cfg(unix)]
    std::fs::set_permissions(&staging, restore).unwrap();
    #[cfg(windows)]
    drop(blocker);
    assert!(
        matches!(result, Err(ClientError::Protocol(code)) if code == "device_storage_unavailable")
    );
    let persisted = d.read().unwrap();
    assert_eq!(persisted.generation, claimed.generation);
    assert!(persisted.records == claimed.records);
    assert!(persisted.refreshing.contains(&session));
    assert_eq!(child(&f, "claim").wait().unwrap().code(), Some(7));
}

#[test]
fn killed_staging_preserves_the_committed_bundle() {
    let f = Fixture::new();
    assert!(child(&f, "write").wait().unwrap().success());
    let mut process = child(&f, "uncommitted");
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !f.0.join("ready").exists() && std::time::Instant::now() < deadline {
        if process.try_wait().unwrap().is_some() {
            panic!("child ended before staging checkpoint");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let ready = f.0.join("ready").exists();
    process.kill().unwrap();
    process.wait().unwrap();
    assert!(ready);
    assert!(child(&f, "read").wait().unwrap().success());
}

#[test]
fn capacity_rejection_preserves_previous_state() {
    let f = Fixture::new();
    let d = f.open();
    let mut state = d.read().unwrap();
    for screen in ["screen-a", "screen-b", "screen-c", "screen-d"] {
        state
            .records
            .insert(key(screen, "attempt"), b"synthetic-attempt".to_vec());
    }
    assert!(
        matches!(d.replace(0, state), Err(ClientError::Protocol(code)) if code == "device_storage_full")
    );
    let mut state = d.read().unwrap();
    state
        .records
        .insert(key("user-a", "session"), vec![b'x'; 8193]);
    assert!(
        matches!(d.replace(0, state), Err(ClientError::Protocol(code)) if code == "device_storage_full")
    );
    assert!(d.read().unwrap().records.is_empty());
}

#[test]
fn locked_file_does_not_become_an_empty_session() {
    let f = Fixture::new();
    let d = f.open();
    let blocker = d.lock().unwrap();
    assert!(
        matches!(d.read(), Err(ClientError::Protocol(code)) if code == "device_storage_unavailable")
    );
    drop(blocker);
    assert!(d.read().is_ok());
}

#[test]
fn swapped_scope_is_never_reset_or_returned() {
    let f = Fixture::new();
    let d = f.open();
    let mut state = d.read().unwrap();
    state
        .records
        .insert(key("user-a", "session"), b"synthetic-session".to_vec());
    assert!(d.replace(0, state).unwrap());
    let path = d.path("json");
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    value["scope"]["origin"] = serde_json::json!("https://other.example.com");
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    let before = std::fs::read(&path).unwrap();
    assert!(
        matches!(d.read(), Err(ClientError::Protocol(code)) if code == "device_storage_corrupt")
    );
    assert!(std::fs::read(&path).unwrap() == before);
}

pub(super) fn before_replace(root: &Path) {
    if std::env::var("DEVICE_CHILD_MODE").as_deref() == Ok("uncommitted") {
        std::fs::write(root.join("ready"), b"ready").unwrap();
        loop {
            std::thread::park();
        }
    }
}

pub(super) fn pause_replace(root: &Path) {
    if std::env::var("DEVICE_CHILD_MODE").as_deref() == Ok("paused-write") {
        std::fs::write(root.join("compared"), b"ready").unwrap();
        while !root.join("release").exists() {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

#[test]
fn an_interrupted_compare_cannot_overwrite_a_competing_commit() {
    let f = Fixture::new();
    assert!(child(&f, "write").wait().unwrap().success());
    let mut first = child(&f, "paused-write");
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !f.0.join("compared").exists() && std::time::Instant::now() < deadline {
        if first.try_wait().unwrap().is_some() {
            panic!("writer ended before compare checkpoint");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if !f.0.join("compared").exists() {
        first.kill().unwrap();
        first.wait().unwrap();
        panic!("compare checkpoint timed out");
    }
    let mut second = child(&f, "competing-write");
    let second_code = second.wait().unwrap().code().unwrap();
    std::fs::write(f.0.join("release"), b"release").unwrap();
    let first_code = first.wait().unwrap().code().unwrap();
    assert!([0, 7, 8].contains(&first_code) && [0, 7, 8].contains(&second_code));
    assert!(
        first_code != 0 || second_code != 0,
        "both stale writers were accepted"
    );
    assert!(
        first_code == 0 || second_code == 0,
        "neither writer committed"
    );
}

#[test]
fn owner_only_file_mode_restores_without_a_key_file() {
    let f = Fixture::new();
    let d = f.open();
    let mut state = d.read().unwrap();
    state
        .records
        .insert(key("screen-a", "attempt"), b"synthetic-attempt".to_vec());
    assert!(d.replace(0, state).unwrap());
    drop(d);
    let reopened = f.open();
    assert!(
        reopened
            .read()
            .unwrap()
            .records
            .contains_key(&key("screen-a", "attempt"))
    );
    let files: Vec<_> = std::fs::read_dir(&f.0)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(files.len(), 2);
    assert!(files.iter().all(|name| {
        name.to_str()
            .is_some_and(|name| name.ends_with(".json") || name.ends_with(".lock"))
    }));
}

#[cfg(any(target_os = "macos", windows))]
#[test]
#[ignore = "Requires a disposable hosted runner and CHICKINFRY_HOST_DEVICE_TESTS=1."]
fn hosted_file_permissions_survive_process_restart_and_logout() {
    assert!(
        std::env::var("CI").as_deref() == Ok("true")
            && std::env::var("CHICKINFRY_HOST_DEVICE_TESTS").as_deref() == Ok("1")
    );
    process_restart_restores_and_logout_stays_deleted();
    #[cfg(target_os = "macos")]
    {
        macos_acl_rejects_other_principals_on_existing_files_and_sidecars();
        macos_acl_rejects_inherited_access_before_new_file_writes();
        macos_acl_deny_entries_preserve_owner_storage();
        macos_default_application_support_acl_is_compatible();
    }
    #[cfg(windows)]
    {
        windows_acl_rejects_missing_inheritance_protection();
        windows_acl_rejects_inherited_allow_entries();
        windows_acl_rejects_another_principal();
        let f = Fixture::new();
        let d = f.open();
        assert!(d.replace(0, Snapshot::default()).unwrap());
        let status = command(std::ffi::OsStr::new("icacls.exe"))
            .arg(d.path("json"))
            .args(["/grant", "*S-1-1-0:(R)"])
            .output()
            .unwrap()
            .status;
        assert!(status.success());
        assert!(
            matches!(d.read(), Err(ClientError::Protocol(code)) if code == "device_storage_unavailable")
        );
        let f = Fixture::new();
        let d = f.open();
        assert!(d.replace(0, Snapshot::default()).unwrap());
        let script = r#"$ErrorActionPreference = 'Stop'
$root = $env:DEVICE_TEST_DIRECTORY
$path = $env:DEVICE_TEST_FILE
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$parent = Get-Acl -LiteralPath $root
$rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
    $user,
    [System.Security.AccessControl.FileSystemRights]::FullControl,
    [System.Security.AccessControl.InheritanceFlags]::None,
    [System.Security.AccessControl.PropagationFlags]::None,
    [System.Security.AccessControl.AccessControlType]::Allow)
$parent.SetAccessRule($rule)
Set-Acl -LiteralPath $root -AclObject $parent
$file = Get-Acl -LiteralPath $path
$file.SetAccessRuleProtection($false, $true)
Set-Acl -LiteralPath $path -AclObject $file
$actual = Get-Acl -LiteralPath $path
$rules = $actual.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
if ($actual.AreAccessRulesProtected -or $rules.Count -ne 1 -or
    $rules[0].IsInherited -or $rules[0].IdentityReference.Value -ne $user.Value) {
    throw 'Expected one explicit current-user entry without inheritance protection.'
}
"#;
        let status = command(std::ffi::OsStr::new("powershell.exe"))
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .env("DEVICE_TEST_DIRECTORY", &f.0)
            .env("DEVICE_TEST_FILE", d.path("json"))
            .output()
            .unwrap()
            .status;
        assert!(status.success());
        assert!(
            matches!(d.read(), Err(ClientError::Protocol(code)) if code == "device_storage_unavailable")
        );
    }
}

#[test]
fn process_default_location_restores_without_configuration() {
    let f = Fixture::new();
    assert!(child(&f, "default-write").wait().unwrap().success());
    assert!(child(&f, "default-read").wait().unwrap().success());
}

#[cfg(target_os = "linux")]
#[test]
fn relative_xdg_uses_the_home_default() {
    let f = Fixture::new();
    assert!(child(&f, "relative-write").wait().unwrap().success());
    assert!(child(&f, "relative-read").wait().unwrap().success());
}

#[cfg(unix)]
#[test]
fn existing_owned_directory_can_be_traversable_but_not_writable_by_others() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    let d = f.open();
    std::fs::set_permissions(&f.0, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(d.replace(0, Snapshot::default()).unwrap());
    std::fs::set_permissions(&f.0, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(
        matches!(d.read(), Err(ClientError::Protocol(code)) if code == "device_storage_unavailable")
    );
}

#[test]
fn relative_directory_is_pinned_before_chdir_and_empty_is_rejected() {
    let f = Fixture::new();
    assert!(child(&f, "pinned-dir-write").wait().unwrap().success());
    assert!(child(&f, "pinned-dir-read").wait().unwrap().success());
}

#[test]
fn windows_acl_rejects_missing_inheritance_protection() {
    assert!(
        matches!(files::private_windows_acl(0, 0, u32::MAX, "current-user", "current-user"),
        Err(ClientError::Protocol(code)) if code == "device_storage_unavailable")
    );
}

#[test]
fn windows_acl_rejects_inherited_allow_entries() {
    assert!(
        matches!(files::private_windows_acl(0x1000, 0x10, u32::MAX, "current-user", "current-user"),
        Err(ClientError::Protocol(code)) if code == "device_storage_unavailable")
    );
}

#[test]
fn windows_acl_rejects_another_principal() {
    assert!(
        files::private_windows_acl(0x1000, 0, u32::MAX, "current-user", "current-user").is_ok()
    );
    assert!(
        matches!(files::private_windows_acl(0x1000, 0, u32::MAX, "another-user", "current-user"),
        Err(ClientError::Protocol(code)) if code == "device_storage_unavailable")
    );
}

#[cfg(target_os = "macos")]
fn chmod_acl(path: &Path, rule: Option<&str>) {
    let mut chmod = command(std::ffi::OsStr::new("/bin/chmod"));
    if let Some(rule) = rule {
        chmod.args(["+a", rule]);
    } else {
        chmod.arg("-N");
    }
    assert!(chmod.arg(path).output().unwrap().status.success());
}

#[cfg(target_os = "macos")]
#[test]
fn macos_acl_rejects_other_principals_on_existing_files_and_sidecars() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    let d = f.open();
    assert!(d.replace(0, Snapshot::default()).unwrap());
    drop(files::create(&d.path("tmp")).unwrap());
    for suffix in ["json", "lock", "tmp"] {
        let path = d.path(suffix);
        chmod_acl(&path, Some("everyone allow read"));
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        let result = d.read();
        chmod_acl(&path, None);
        assert_eq!(mode, 0o600);
        assert!(
            matches!(result, Err(ClientError::Protocol(code)) if code == "device_storage_unavailable")
        );
    }
}

#[cfg(target_os = "macos")]
#[test]
fn macos_acl_rejects_inherited_access_before_new_file_writes() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    let d = f.open();
    chmod_acl(
        &f.0,
        Some("everyone allow read,file_inherit,directory_inherit"),
    );
    let mode = std::fs::metadata(&f.0).unwrap().permissions().mode() & 0o777;
    let read = d.read();
    let probe = f.0.join("acl-probe");
    let created = files::create(&probe);
    let length = std::fs::metadata(&probe).unwrap().len();
    chmod_acl(&f.0, None);
    assert_eq!(mode, 0o700);
    assert_eq!(length, 0);
    assert!(
        matches!(read, Err(ClientError::Protocol(code)) if code == "device_storage_unavailable")
    );
    assert!(
        matches!(created, Err(ClientError::Protocol(code)) if code == "device_storage_unavailable")
    );
}

#[cfg(target_os = "macos")]
#[test]
fn macos_acl_deny_entries_preserve_owner_storage() {
    let f = Fixture::new();
    let d = f.open();
    chmod_acl(&f.0, Some("everyone deny delete"));
    let result = d.replace(0, Snapshot::default());
    chmod_acl(&f.0, None);
    assert!(result.unwrap());
    let owner = command(std::ffi::OsStr::new("/usr/bin/id"))
        .arg("-un")
        .output()
        .unwrap();
    assert!(owner.status.success());
    let owner = String::from_utf8(owner.stdout).unwrap();
    chmod_acl(&f.0, Some(&format!("{} allow read", owner.trim())));
    let result = d.read();
    chmod_acl(&f.0, None);
    assert!(result.is_ok());
}

#[cfg(target_os = "macos")]
#[test]
fn macos_default_application_support_acl_is_compatible() {
    let base = files::state_home().unwrap();
    assert!(base.is_dir());
    files::check_directory(&base).unwrap();
}

#[cfg(unix)]
#[test]
fn released_transaction_does_not_leave_refresh_blocked_by_a_duplicated_descriptor() {
    let f = Fixture::new();
    let d = f.open();
    let session = key("user-a", "session");
    let mut state = d.read().unwrap();
    let mut value = vec![0u8; 32];
    getrandom::getrandom(&mut value).unwrap();
    state.records.insert(session.clone(), value);
    assert!(d.replace(0, state).unwrap());
    let held = d.lock().unwrap();
    let duplicate = held.0.try_clone().unwrap();
    drop(held);
    let claim = d.claim_refresh(1, &session);
    drop(duplicate);
    assert!(claim.unwrap().is_some());
}
