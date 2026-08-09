use kclip_cli::{Cli, CliError, Command, execute, send_request};
use kclip_daemon::{ServerConfig, run_until};
use kclip_protocol::{
    ErrorCode, Operation, Request, Response, ResponsePayload, read_frame, write_frame,
};
use std::{
    fs,
    io::{Cursor, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command as ProcessCommand, Stdio},
    time::Duration,
};
use tempfile::TempDir;
use tokio::{io::AsyncWriteExt, net::UnixStream, sync::oneshot, task::JoinHandle};

struct TestDaemon {
    _temp: TempDir,
    socket: PathBuf,
    data: PathBuf,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl TestDaemon {
    async fn start(max_content_size: u64) -> Self {
        let temp = TempDir::new().unwrap();
        let socket = temp.path().join("runtime/kclipd.sock");
        let data = temp.path().join("data");
        Self::start_with_temp(temp, socket, data, max_content_size).await
    }

    async fn start_with_temp(
        temp: TempDir,
        socket: PathBuf,
        data: PathBuf,
        max_content_size: u64,
    ) -> Self {
        let config = server_config(&socket, &data, max_content_size);
        Self::start_with_server_config(temp, socket, data, config).await
    }

    async fn start_with_server_config(
        temp: TempDir,
        socket: PathBuf,
        data: PathBuf,
        config: ServerConfig,
    ) -> Self {
        let (shutdown, receiver) = oneshot::channel();
        let task = tokio::spawn(async move {
            run_until(config, async {
                let _ = receiver.await;
            })
            .await
            .unwrap();
        });
        wait_for_socket(&socket).await;
        Self {
            _temp: temp,
            socket,
            data,
            shutdown: Some(shutdown),
            task,
        }
    }

    async fn stop(mut self) -> (TempDir, PathBuf, PathBuf) {
        self.shutdown.take().unwrap().send(()).unwrap();
        self.task.await.unwrap();
        (self._temp, self.socket, self.data)
    }

    fn cli(&self, command: Command) -> Cli {
        Cli {
            socket: Some(self.socket.clone()),
            json: false,
            command,
        }
    }
}

fn server_config(socket: &Path, data: &Path, max_content_size: u64) -> ServerConfig {
    ServerConfig {
        socket_path: socket.to_path_buf(),
        database_path: data.join("kclip.db"),
        blob_directory: data.join("blobs"),
        max_content_size,
        sync: kclip_config::SyncResolution::Disabled,
        slots: Default::default(),
    }
}

async fn wait_for_socket(socket: &Path) {
    for _ in 0..100 {
        if socket.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("daemon socket did not appear");
}

async fn execute_with_input(
    daemon: &TestDaemon,
    command: Command,
    input: &[u8],
) -> Result<Vec<u8>, CliError> {
    let cli = daemon.cli(command);
    let mut input = Cursor::new(input.to_vec());
    let mut output = Vec::new();
    execute(&cli, &mut input, &mut output).await?;
    Ok(output)
}

async fn copy(daemon: &TestDaemon, slot: &str, content: &[u8]) -> Result<(), CliError> {
    execute_with_input(
        daemon,
        Command::Copy {
            slot: slot.into(),
            file: None,
            content_type: None,
            local: false,
        },
        content,
    )
    .await
    .map(|_| ())
}

async fn paste(daemon: &TestDaemon, slot: &str) -> Result<Vec<u8>, CliError> {
    execute_with_input(
        daemon,
        Command::Paste {
            slot: slot.into(),
            file: None,
        },
        &[],
    )
    .await
}

#[tokio::test]
async fn text_stdin_round_trip_preserves_exact_bytes() {
    let daemon = TestDaemon::start(1024).await;
    copy(&daemon, "default", b"text with no final newline")
        .await
        .unwrap();
    assert_eq!(
        paste(&daemon, "default").await.unwrap(),
        b"text with no final newline"
    );
    daemon.stop().await;
}

#[tokio::test]
async fn binary_and_empty_values_round_trip() {
    let daemon = TestDaemon::start(1024).await;
    let binary = [0, 255, 1, 128, b'\n', 0];
    copy(&daemon, "binary", &binary).await.unwrap();
    copy(&daemon, "empty", b"").await.unwrap();
    assert_eq!(paste(&daemon, "binary").await.unwrap(), binary);
    assert_eq!(paste(&daemon, "empty").await.unwrap(), b"");
    daemon.stop().await;
}

#[tokio::test]
async fn named_slots_are_independent_and_clear_is_scoped() {
    let daemon = TestDaemon::start(1024).await;
    copy(&daemon, "one", b"first").await.unwrap();
    copy(&daemon, "two", b"second").await.unwrap();
    execute_with_input(
        &daemon,
        Command::Clear {
            slot: "one".into(),
            local: false,
        },
        &[],
    )
    .await
    .unwrap();

    assert!(
        matches!(paste(&daemon, "one").await, Err(CliError::Remote(error)) if error.code == ErrorCode::SlotNotFound)
    );
    assert_eq!(paste(&daemon, "two").await.unwrap(), b"second");
    daemon.stop().await;
}

#[tokio::test]
async fn content_survives_a_daemon_restart() {
    let daemon = TestDaemon::start(1024).await;
    copy(&daemon, "default", b"survives restart").await.unwrap();
    let (temp, socket, data) = daemon.stop().await;

    let daemon = TestDaemon::start_with_temp(temp, socket, data, 1024).await;
    assert_eq!(
        paste(&daemon, "default").await.unwrap(),
        b"survives restart"
    );
    daemon.stop().await;
}

#[tokio::test]
async fn concurrent_copies_receive_distinct_revision_ids() {
    let daemon = TestDaemon::start(1024).await;
    let first = send_request(
        &daemon.socket,
        Operation::Copy {
            slot: "one".into(),
            content: b"1".to_vec(),
            content_type: None,
            local: false,
        },
    );
    let second = send_request(
        &daemon.socket,
        Operation::Copy {
            slot: "two".into(),
            content: b"2".to_vec(),
            content_type: None,
            local: false,
        },
    );
    let (first, second) = tokio::join!(first, second);
    let ResponsePayload::Stored(first) = first.unwrap() else {
        panic!("unexpected response")
    };
    let ResponsePayload::Stored(second) = second.unwrap() else {
        panic!("unexpected response")
    };
    assert_ne!(first.revision_id, second.revision_id);
    assert_ne!(first.origin_sequence, second.origin_sequence);
    daemon.stop().await;
}

#[tokio::test]
async fn oversized_content_and_missing_slot_use_stable_exit_codes() {
    let daemon = TestDaemon::start(32).await;
    let error = copy(&daemon, "default", &[0; 33]).await.unwrap_err();
    assert_eq!(error.exit_code(), 6);

    let error = paste(&daemon, "missing").await.unwrap_err();
    assert_eq!(error.exit_code(), 4);
    daemon.stop().await;
}

#[tokio::test]
async fn malformed_frames_do_not_crash_the_daemon() {
    let daemon = TestDaemon::start(1024).await;
    let mut stream = UnixStream::connect(&daemon.socket).await.unwrap();
    stream.write_u32(3).await.unwrap();
    stream.write_all(&[0xff, 0xff, 0xff]).await.unwrap();
    stream.flush().await.unwrap();
    let _: Response = read_frame(&mut stream).await.unwrap();

    copy(&daemon, "default", b"daemon remains alive")
        .await
        .unwrap();
    assert_eq!(
        paste(&daemon, "default").await.unwrap(),
        b"daemon remains alive"
    );
    daemon.stop().await;
}

#[tokio::test]
async fn file_copy_and_atomic_file_paste_work() {
    let daemon = TestDaemon::start(1024).await;
    let input_path = daemon.data.parent().unwrap().join("input.bin");
    let output_path = daemon.data.parent().unwrap().join("output.bin");
    fs::write(&input_path, [9, 0, 8, 7]).unwrap();

    execute_with_input(
        &daemon,
        Command::Copy {
            slot: "file".into(),
            file: Some(input_path),
            content_type: None,
            local: false,
        },
        b"ignored stdin",
    )
    .await
    .unwrap();
    execute_with_input(
        &daemon,
        Command::Paste {
            slot: "file".into(),
            file: Some(output_path.clone()),
        },
        &[],
    )
    .await
    .unwrap();
    assert_eq!(fs::read(output_path).unwrap(), [9, 0, 8, 7]);
    daemon.stop().await;
}

#[tokio::test]
async fn list_reports_only_current_live_slots() {
    let daemon = TestDaemon::start(1024).await;
    copy(&daemon, "z", b"last").await.unwrap();
    copy(&daemon, "a", b"first").await.unwrap();
    execute_with_input(
        &daemon,
        Command::Clear {
            slot: "z".into(),
            local: false,
        },
        &[],
    )
    .await
    .unwrap();
    let output = execute_with_input(&daemon, Command::List, &[])
        .await
        .unwrap();
    let text = String::from_utf8(output).unwrap();
    assert!(text.starts_with("a\t"));
    assert!(!text.contains("z\t"));
    daemon.stop().await;
}

#[tokio::test]
async fn socket_permissions_are_restrictive() {
    let daemon = TestDaemon::start(1024).await;
    let mode = fs::metadata(&daemon.socket).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let directory_mode = fs::metadata(daemon.socket.parent().unwrap())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(directory_mode, 0o700);
    daemon.stop().await;
}

#[tokio::test]
async fn protocol_version_mismatch_returns_a_structured_error() {
    let daemon = TestDaemon::start(1024).await;
    let mut stream = UnixStream::connect(&daemon.socket).await.unwrap();
    let mut request = Request::new(42, Operation::List);
    request.protocol_version += 1;
    write_frame(&mut stream, &request).await.unwrap();
    let response: Response = read_frame(&mut stream).await.unwrap();
    let kclip_protocol::ResponseResult::Error { error } = response.result else {
        panic!("expected error")
    };
    assert_eq!(error.code, ErrorCode::ProtocolMismatch);
    daemon.stop().await;
}

#[tokio::test]
async fn compiled_cli_supports_shell_pipes_and_process_exit_codes() {
    let daemon = TestDaemon::start(1024).await;
    let socket = daemon.socket.clone();
    let result = tokio::task::spawn_blocking(move || {
        let executable = env!("CARGO_BIN_EXE_kclip");
        let mut copy = ProcessCommand::new(executable)
            .args(["--socket", socket.to_str().unwrap(), "copy"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        copy.stdin
            .take()
            .unwrap()
            .write_all(b"actual shell-pipe bytes")
            .unwrap();
        let copy = copy.wait_with_output().unwrap();
        assert!(
            copy.status.success(),
            "{}",
            String::from_utf8_lossy(&copy.stderr)
        );
        assert!(copy.stdout.is_empty());

        let paste = ProcessCommand::new(executable)
            .args(["--socket", socket.to_str().unwrap(), "paste"])
            .output()
            .unwrap();
        assert!(paste.status.success());
        assert_eq!(paste.stdout, b"actual shell-pipe bytes");

        let missing = ProcessCommand::new(executable)
            .args([
                "--socket",
                socket.to_str().unwrap(),
                "paste",
                "--slot",
                "missing",
            ])
            .output()
            .unwrap();
        assert_eq!(missing.status.code(), Some(4));
    })
    .await;
    result.unwrap();
    daemon.stop().await;
}

#[tokio::test]
async fn offline_relay_never_blocks_local_clipboard_operations() {
    let temp = TempDir::new().unwrap();
    let socket = temp.path().join("runtime/kclipd.sock");
    let data = temp.path().join("data");
    let token_path = temp.path().join("secrets/token.json");
    let key_path = temp.path().join("secrets/sync.key");
    kclip_sync::write_token(&token_path, "offline-token").unwrap();
    kclip_crypto::write_sync_key(&key_path, &[3_u8; 32]).unwrap();
    let mut slots = std::collections::BTreeMap::new();
    slots.insert(
        "secret".into(),
        kclip_config::SlotConfig {
            sync: Some(false),
            ..Default::default()
        },
    );
    let config = ServerConfig {
        socket_path: socket.clone(),
        database_path: data.join("kclip.db"),
        blob_directory: data.join("blobs"),
        max_content_size: 1024,
        sync: kclip_config::SyncResolution::Ready(kclip_config::ResolvedSyncConfig {
            relay_url: "ws://127.0.0.1:1/sync/v1".into(),
            reconnect_min_delay: Duration::from_millis(10),
            reconnect_max_delay: Duration::from_millis(50),
            device_name: "offline-test".into(),
            token_path,
            pairing_path: temp.path().join("config/pairing.json"),
            sync_key_path: key_path,
            allow_insecure_transport: true,
        }),
        slots,
    };
    let daemon = TestDaemon::start_with_server_config(temp, socket, data, config).await;
    copy(&daemon, "default", b"local still works")
        .await
        .unwrap();
    assert_eq!(
        paste(&daemon, "default").await.unwrap(),
        b"local still works"
    );
    copy(&daemon, "secret", b"slot policy").await.unwrap();
    execute_with_input(
        &daemon,
        Command::Copy {
            slot: "one-off-private".into(),
            file: None,
            content_type: None,
            local: true,
        },
        b"local flag",
    )
    .await
    .unwrap();
    let ResponsePayload::Status(status) = send_request(&daemon.socket, Operation::Status)
        .await
        .unwrap()
    else {
        panic!("unexpected status response")
    };
    assert!(status.synchronization_enabled);
    assert_eq!(status.pending_outbox_count, 1);
    daemon.stop().await;
}
