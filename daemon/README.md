# Userspace daemon

The daemon implementation now lives in [`../crates/kclip-daemon`](../crates/kclip-daemon)
as part of the Rust workspace. This directory is retained as a pointer from the
earlier repository layout; new daemon code, tests, and packaging belong in the
workspace crate and `packaging/systemd`.
