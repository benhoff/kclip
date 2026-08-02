PREFIX ?= $(HOME)/.local
SYSTEMD_USER_DIR ?= $(HOME)/.config/systemd/user

.PHONY: all userspace daemon release test check install kernel kmod kernel-test \
	kernel-clean kernel-install print-vars clean

# The supported userspace implementation is the default project build.
all: userspace

userspace daemon:
	cargo build --workspace

release:
	cargo build --workspace --release

test:
	cargo test --workspace --all-targets

check:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets -- -D warnings

install:
	./install.sh --prefix "$(PREFIX)"

# The experimental kernel prototype remains available only through explicit targets.
kernel kmod:
	$(MAKE) -C kernel kmod

kernel-test:
	python3 -m pytest -q kernel/tests

kernel-clean:
	$(MAKE) -C kernel clean

kernel-install:
	$(MAKE) -C kernel install

print-vars:
	@echo "PREFIX           = $(PREFIX)"
	@echo "SYSTEMD_USER_DIR = $(SYSTEMD_USER_DIR)"
	$(MAKE) -C kernel print-vars

clean:
	cargo clean
