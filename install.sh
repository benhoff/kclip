#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

PROJECT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
PREFIX=${KCLIP_PREFIX:-/usr/local}
PREFIX_EXPLICIT=0
START_SERVICE=1
DATABASE_ACTION=prompt
MINIMUM_RUST_VERSION=1.88.0
SUDO_READY=0
ADMIN=()
TEMP_SERVICE=""
SERVICE_STOPPED_FOR_DATABASE=0

info() {
    printf '==> %s\n' "$*"
}

warn() {
    printf 'Warning: %s\n' "$*" >&2
}

shell_quote() {
    local value=$1
    printf "'%s'" "${value//\'/\'\\\'\'}"
}

ensure_bin_on_path() {
    local shell_name profile marker quoted_bindir
    shell_name=$(basename -- "${SHELL:-sh}")
    marker="# Added by the kclip installer: ${BINDIR}"

    case "$shell_name" in
        bash)
            profile="$HOME/.bashrc"
            ;;
        zsh)
            profile="${ZDOTDIR:-$HOME}/.zshrc"
            ;;
        fish)
            profile="${XDG_CONFIG_HOME:-$HOME/.config}/fish/conf.d/kclip-path.fish"
            ;;
        *)
            profile="$HOME/.profile"
            ;;
    esac

    if [[ -f "$profile" ]] && grep -Fqx -- "$marker" "$profile"; then
        info "PATH setup is already present in ${profile}; start a new shell to use kclip by name"
        return
    fi

    mkdir -p -- "$(dirname -- "$profile")"
    quoted_bindir=$(shell_quote "$BINDIR")
    {
        [[ ! -s "$profile" ]] || printf '\n'
        printf '%s\n' "$marker"
        if [[ "$shell_name" == fish ]]; then
            printf 'fish_add_path --global %s\n' "$quoted_bindir"
        else
            printf 'export PATH=%s:"$PATH"\n' "$quoted_bindir"
        fi
    } >>"$profile"
    info "Added ${BINDIR} to PATH in ${profile}"
    info "Start a new shell to invoke kclip by name"
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
  --database-action ACTION
                 On a schema change: prompt, migrate, delete, or abort
                 (default: prompt)
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
        --database-action)
            (($# >= 2)) || fail "--database-action requires an action"
            DATABASE_ACTION=$2
            case "$DATABASE_ACTION" in
                prompt|migrate|delete|abort) ;;
                *) fail "--database-action must be prompt, migrate, delete, or abort" ;;
            esac
            shift 2
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

stop_service_for_database_change() {
    if command -v systemctl >/dev/null 2>&1 \
        && systemctl --user is-active --quiet kclipd.service; then
        info "Stopping kclipd before changing its database"
        systemctl --user stop kclipd.service \
            || fail "could not stop kclipd.service; the database was not changed"
        SERVICE_STOPPED_FOR_DATABASE=1
    fi
    if command -v pgrep >/dev/null 2>&1 && pgrep -u "$EUID" -x kclipd >/dev/null; then
        fail "another kclipd process is still running; stop it before changing the database"
    fi
}

delete_existing_database() {
    local database_path=$1
    [[ "$database_path" == /* ]] || fail "refusing to delete a non-absolute database path: ${database_path}"
    [[ "$database_path" != / ]] || fail "refusing to delete the filesystem root"

    stop_service_for_database_change

    rm -f -- "$database_path" "${database_path}-wal" "${database_path}-shm"
    info "Deleted database and SQLite sidecars: ${database_path}"
    info "This deletion has no installer-created backup; unreferenced blobs are cleaned on the next daemon start"
}

handle_database_upgrade() {
    local output database_state existing_schema target_schema database_path selected answer
    local -a storage_lines
    output=$("$DAEMON_SOURCE" --config "$CONFIG_FILE" --installer-storage-info) \
        || fail "could not inspect the existing kclip database"
    mapfile -t storage_lines <<<"$output"
    ((${#storage_lines[@]} >= 2)) || fail "kclipd returned incomplete storage information"
    read -r database_state existing_schema target_schema <<<"${storage_lines[0]}"
    database_path=${storage_lines[1]}

    case "$database_state" in
        absent|current)
            return
            ;;
        migratable|unsupported) ;;
        *) fail "kclipd returned an unknown database state: ${database_state}" ;;
    esac

    selected=$DATABASE_ACTION
    if [[ "$selected" == prompt ]]; then
        [[ -t 0 ]] || fail \
            "database schema ${existing_schema} requires a decision; rerun with --database-action migrate, delete, or abort"
        printf '\nExisting kclip database: %s\n' "$database_path"
        printf 'Database schema: %s; this release uses schema %s.\n' "$existing_schema" "$target_schema"
        if [[ "$database_state" == migratable ]]; then
            printf 'Migration preserves local history and pending synchronization state.\n'
            printf 'Deletion permanently discards the local database; credentials and the account key are retained.\n'
            while true; do
                read -r -p 'Choose [m]igrate, [d]elete, or [a]bort: ' answer
                case "$answer" in
                    m|M|migrate) selected=migrate; break ;;
                    d|D|delete) selected=delete; break ;;
                    a|A|abort) selected=abort; break ;;
                    *) warn "enter m, d, or a" ;;
                esac
            done
        else
            printf 'No automatic migration is available for this schema.\n'
            printf 'Deletion permanently discards the local database; credentials and the account key are retained.\n'
            while true; do
                read -r -p 'Choose [d]elete or [a]bort: ' answer
                case "$answer" in
                    d|D|delete) selected=delete; break ;;
                    a|A|abort) selected=abort; break ;;
                    *) warn "enter d or a" ;;
                esac
            done
        fi
    fi

    case "$selected" in
        migrate)
            [[ "$database_state" == migratable ]] || fail \
                "database schema ${existing_schema} cannot be migrated by this release; use --database-action delete or abort"
            stop_service_for_database_change
            info "Migrating ${database_path} from schema ${existing_schema} to ${target_schema}"
            "$DAEMON_SOURCE" --config "$CONFIG_FILE" --installer-migrate-storage \
                || fail "database migration failed; installed binaries were not changed"
            ;;
        delete)
            delete_existing_database "$database_path"
            ;;
        abort)
            fail "installation stopped without changing the existing database"
            ;;
        *) fail "unexpected database action: ${selected}" ;;
    esac
}

handle_database_upgrade

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
    *) ensure_bin_on_path ;;
esac

if ((START_SERVICE == 0)); then
    if ((SERVICE_STOPPED_FOR_DATABASE)); then
        info "kclipd remains stopped because --no-start was selected"
    fi
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
    info "To configure encrypted synchronization, run: kclip sync setup"
else
    warn "kclipd did not become active; inspect it with: journalctl --user -u kclipd.service"
    exit 1
fi
