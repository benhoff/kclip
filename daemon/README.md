# Userspace daemon

The daemon implementation now lives in [`../crates/kclip-daemon`](../crates/kclip-daemon)
as part of the Rust workspace. This directory is retained as a pointer from the
earlier repository layout; new daemon code, tests, and packaging belong in the
workspace crate and `packaging/systemd`.

The daemon owns synchronization lifecycle, while encrypted relay transport is
implemented in [`../crates/kclip-sync`](../crates/kclip-sync) and envelope/key
handling is implemented in
[`../crates/kclip-crypto`](../crates/kclip-crypto). Neither subsystem is used
when `[sync] enabled = false`.
