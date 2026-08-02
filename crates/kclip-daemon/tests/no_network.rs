use std::{
    collections::HashSet,
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Stdio},
    thread,
    time::Duration,
};
use tempfile::TempDir;

#[test]
fn phase_one_daemon_opens_only_a_unix_listener() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let socket = temp.path().join("runtime/kclipd.sock");
    let data = temp.path().join("data");
    let mut child = Command::new(env!("CARGO_BIN_EXE_kclipd"))
        .args([
            "--socket",
            socket.to_str().unwrap(),
            "--data-dir",
            data.to_str().unwrap(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(socket.exists(), "daemon did not become ready");

    let socket_inodes = process_socket_inodes(child.id());
    assert!(
        !socket_inodes.is_empty(),
        "daemon did not open its Unix socket"
    );
    for table in ["tcp", "tcp6", "udp", "udp6"] {
        let entries =
            fs::read_to_string(format!("/proc/{}/net/{table}", child.id())).unwrap_or_default();
        for inode in &socket_inodes {
            assert!(
                !entries.split_whitespace().any(|field| field == inode),
                "daemon opened an unexpected network socket listed in {table}"
            );
        }
    }

    unsafe {
        libc::kill(child.id() as i32, libc::SIGINT);
    }
    let status = child.wait().unwrap();
    assert!(status.success());
}

fn process_socket_inodes(pid: u32) -> HashSet<String> {
    let mut inodes = HashSet::new();
    for entry in fs::read_dir(Path::new(&format!("/proc/{pid}/fd"))).unwrap() {
        let target = fs::read_link(entry.unwrap().path()).unwrap_or_default();
        let target = target.to_string_lossy();
        if let Some(inode) = target
            .strip_prefix("socket:[")
            .and_then(|value| value.strip_suffix(']'))
        {
            inodes.insert(inode.to_owned());
        }
    }
    inodes
}
