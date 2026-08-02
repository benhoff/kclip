#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

PROJECT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
PREFIX=${KCLIP_PREFIX:-/usr/local}
PREFIX_EXPLICIT=0
START_SERVICE=1
MINIMUM_RUST_VERSION=1.88.0
SUDO_READY=0
ADMIN=()
TEMP_SERVICE=""

info() {
    printf '==> %s\n' "$*"
}

warn() {
    printf 'Warning: %s\n' "$*" >&2
}

fail() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
Usage: ./install.sh [OPTIONS]

Build, install, configure, and start kclip for the current user.

Options:
  --prefix PATH  Install binaries below PATH (default: /usr/local)
  --user         Install binaries below $HOME/.local without sudo
  --no-start     Install and configure without starting the user service
  -h, --help     Show this help

Environment:
  KCLIP_PREFIX   Alternative default installation prefix
EOF
}

cleanup() {
    if [[ -n "$TEMP_SERVICE" && -f "$TEMP_SERVICE" ]]; then
        rm -f -- "$TEMP_SERVICE"
    fi
}
trap cleanup EXIT

while (($# > 0)); do
    case "$1" in
        --prefix)
            (($# >= 2)) || fail "--prefix requires a path"
            PREFIX=$2
            PREFIX_EXPLICIT=1
            shift 2
            ;;
        --user)
            [[ -n "${HOME:-}" ]] || fail "HOME is unavailable; use --prefix PATH"
            PREFIX="$HOME/.local"
            PREFIX_EXPLICIT=1
            shift
            ;;
        --no-start)
            START_SERVICE=0
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            fail "unknown option: $1"
            ;;
    esac
done

[[ $(uname -s) == Linux ]] || fail "kclip currently supports Linux only"
[[ "$PREFIX" == /* ]] || fail "installation prefix must be an absolute path"
[[ "$PREFIX" != *[[:space:]]* ]] || fail "installation prefix must not contain whitespace"
[[ -n "${HOME:-}" ]] || fail "HOME is unavailable"
if ((EUID == 0)) && [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != root ]]; then
    fail "run this installer as your normal user, without sudo; it will request sudo only when needed"
fi

command -v cargo >/dev/null 2>&1 || fail \
    "Cargo was not found. Install Rust ${MINIMUM_RUST_VERSION} or newer from https://rustup.rs and rerun."
command -v rustc >/dev/null 2>&1 || fail "rustc was not found next to Cargo"

version_greater_equal() {
    [[ $(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1) == "$2" ]]
}

RUST_VERSION=$(rustc --version | awk '{print $2}')
version_greater_equal "$RUST_VERSION" "$MINIMUM_RUST_VERSION" || fail \
    "Rust ${RUST_VERSION} is too old; kclip requires ${MINIMUM_RUST_VERSION} or newer"

nearest_existing_directory() {
    local candidate=$1
    while [[ ! -e "$candidate" ]]; do
        local parent
        parent=$(dirname -- "$candidate")
        [[ "$parent" != "$candidate" ]] || break
        candidate=$parent
    done
    printf '%s\n' "$candidate"
}

prefix_is_writable() {
    local existing
    existing=$(nearest_existing_directory "$PREFIX/bin")
    [[ -d "$existing" && -w "$existing" ]]
}

if ((EUID != 0)) && ! prefix_is_writable && ! command -v sudo >/dev/null 2>&1; then
    if ((PREFIX_EXPLICIT)); then
        fail "${PREFIX} is not writable and sudo is unavailable"
    fi
    PREFIX="$HOME/.local"
    info "sudo is unavailable; using the user installation prefix ${PREFIX}"
fi

ensure_admin() {
    if prefix_is_writable; then
        ADMIN=()
        return
    fi
    ensure_root
}

ensure_root() {
    if ((EUID == 0)); then
        ADMIN=()
        return
    fi
    command -v sudo >/dev/null 2>&1 || fail "administrator access is required to write below ${PREFIX}"
    if ((SUDO_READY == 0)); then
        info "Administrator access is needed to update ${PREFIX}/bin"
        sudo -v || fail "administrator authentication failed"
        SUDO_READY=1
    fi
    ADMIN=(sudo)
}

install_build_tools() {
    info "A C build toolchain is missing; installing the native SQLite build prerequisites"
    ensure_root
    if command -v apt-get >/dev/null 2>&1; then
        "${ADMIN[@]}" apt-get update
        "${ADMIN[@]}" apt-get install -y build-essential
    elif command -v dnf >/dev/null 2>&1; then
        "${ADMIN[@]}" dnf install -y gcc make
    elif command -v pacman >/dev/null 2>&1; then
        "${ADMIN[@]}" pacman -S --needed --noconfirm base-devel
    elif command -v zypper >/dev/null 2>&1; then
        "${ADMIN[@]}" zypper --non-interactive install gcc make
    else
        fail "install a C compiler, make, and archiver, then rerun the installer"
    fi
}

for required_tool in cc make ar; do
    if ! command -v "$required_tool" >/dev/null 2>&1; then
        install_build_tools
        break
    fi
done

cd "$PROJECT_DIR"
info "Building kclip ${RUST_VERSION:+with Rust ${RUST_VERSION}}"
cargo build --workspace --release --locked

BUILD_TARGET_DIR=${CARGO_TARGET_DIR:-$PROJECT_DIR/target}
if [[ "$BUILD_TARGET_DIR" != /* ]]; then
    BUILD_TARGET_DIR="$PROJECT_DIR/$BUILD_TARGET_DIR"
fi
BINDIR="$PREFIX/bin"
CLI_SOURCE="$BUILD_TARGET_DIR/release/kclip"
DAEMON_SOURCE="$BUILD_TARGET_DIR/release/kclipd"
CLI_DESTINATION="$BINDIR/kclip"
DAEMON_DESTINATION="$BINDIR/kclipd"

[[ -x "$CLI_SOURCE" && -x "$DAEMON_SOURCE" ]] || fail "release build did not produce both binaries"

if [[ ! -f "$CLI_DESTINATION" ]] || ! cmp -s -- "$CLI_SOURCE" "$CLI_DESTINATION" \
    || [[ ! -f "$DAEMON_DESTINATION" ]] || ! cmp -s -- "$DAEMON_SOURCE" "$DAEMON_DESTINATION"; then
    ensure_admin
fi

CONFIG_ROOT=${XDG_CONFIG_HOME:-$HOME/.config}
[[ "$CONFIG_ROOT" == /* ]] || fail "XDG_CONFIG_HOME must be an absolute path"
CONFIG_FILE="$CONFIG_ROOT/kclip/config.toml"
SYSTEMD_USER_DIR="$CONFIG_ROOT/systemd/user"
SERVICE_FILE="$SYSTEMD_USER_DIR/kclipd.service"

info "Creating or updating ${CONFIG_FILE}"
"$DAEMON_SOURCE" --config "$CONFIG_FILE" --update-config

install_binary() {
    local source=$1
    local destination=$2
    if [[ -f "$destination" ]] && cmp -s -- "$source" "$destination"; then
        info "Already current: ${destination}"
        return
    fi
    ensure_admin
    "${ADMIN[@]}" install -Dm755 -- "$source" "$destination"
    info "Installed: ${destination}"
}

install_binary "$CLI_SOURCE" "$CLI_DESTINATION"
install_binary "$DAEMON_SOURCE" "$DAEMON_DESTINATION"

TEMP_SERVICE=$(mktemp)
awk -v executable="$DAEMON_DESTINATION" '
    /^ExecStart=/ { print "ExecStart=" executable; next }
    { print }
' "$PROJECT_DIR/packaging/systemd/kclipd.service" >"$TEMP_SERVICE"

if [[ ! -f "$SERVICE_FILE" ]] || ! cmp -s -- "$TEMP_SERVICE" "$SERVICE_FILE"; then
    mkdir -p -- "$SYSTEMD_USER_DIR"
    chmod 700 -- "$SYSTEMD_USER_DIR"
    if [[ -f "$SERVICE_FILE" ]]; then
        SERVICE_BACKUP="${SERVICE_FILE}.bak.$(date +%s)"
        cp -p -- "$SERVICE_FILE" "$SERVICE_BACKUP"
        info "Previous service unit: ${SERVICE_BACKUP}"
    fi
    install -m644 -- "$TEMP_SERVICE" "$SERVICE_FILE"
    info "Installed user service: ${SERVICE_FILE}"
else
    info "Already current: ${SERVICE_FILE}"
fi

"$CLI_DESTINATION" --version
"$DAEMON_DESTINATION" --version

case ":${PATH}:" in
    *":${BINDIR}:"*) ;;
    *) warn "${BINDIR} is not on PATH; add it before invoking kclip by name" ;;
esac

if ((START_SERVICE == 0)); then
    info "Installation complete; service startup was skipped"
    exit 0
fi

if ! command -v systemctl >/dev/null 2>&1; then
    warn "systemd is unavailable; start kclipd manually with: ${DAEMON_DESTINATION}"
    exit 0
fi

if ! systemctl --user daemon-reload; then
    warn "the systemd user manager is unavailable in this session"
    warn "later, run: systemctl --user enable --now kclipd.service"
    exit 0
fi

if ! systemctl --user enable kclipd.service >/dev/null; then
    warn "could not enable kclipd.service; retry with: systemctl --user enable --now kclipd.service"
    exit 1
fi
if systemctl --user is-active --quiet kclipd.service; then
    info "Restarting kclipd with the installed binary and configuration"
    SERVICE_ACTION=restart
else
    info "Starting kclipd"
    SERVICE_ACTION=start
fi
if ! systemctl --user "$SERVICE_ACTION" kclipd.service; then
    warn "kclipd could not ${SERVICE_ACTION}; inspect it with: journalctl --user -u kclipd.service"
    exit 1
fi

if systemctl --user is-active --quiet kclipd.service; then
    info "kclip is installed and kclipd is running"
else
    warn "kclipd did not become active; inspect it with: journalctl --user -u kclipd.service"
    exit 1
fi
