# kclip kernel module

This directory contains the existing experimental Linux kernel implementation.
It is isolated here so development of the userspace daemon does not mix service
code, packaging, and tests with kernel build inputs.

The module registers `/dev/kclip` and implements an ioctl-based, multipart
message queue backed by memfd objects. The ABI is declared in
`include/uapi/kclip_uapi.h`; it is not a byte-stream device, so `cat` and `echo`
are not valid clients.

> **Warning:** the module is a prototype and has known correctness and safety
> issues. Do not load it on production systems or systems containing important
> data.

## Build and test

From the repository root:

```bash
make kernel
make kernel-test
```

Or work directly in this directory:

```bash
make
python3 -m pytest -q tests
```

The tests require a built and loaded module plus a `/dev/kclip` device. They are
skipped when that device is unavailable. Loading or installing a kernel module
requires root privileges and matching kernel headers.

## DKMS

`VERSION`, `dkms.conf`, `bootstrap.sh`, and `check_versions.sh` deliberately live
beside the module because they package only this component. Before publishing a
new kernel version, update both `VERSION` and `PACKAGE_VERSION` in `dkms.conf`,
then run:

```bash
./check_versions.sh
```

The bootstrap installer currently tracks the `shmem-clipboard` branch. Override
that with `KCLIP_GIT_REF` when testing another branch or tag.
