#!/usr/bin/env bash
#
# pipassword installer.
#
#   curl -fsSL https://raw.githubusercontent.com/laonan/pipassword/main/install.sh | bash
#
# Prefer reading it first; it costs nothing:
#
#   curl -fsSL https://raw.githubusercontent.com/laonan/pipassword/main/install.sh -o install.sh
#   less install.sh && bash install.sh
#
# Everything is wrapped in a function that is only invoked on the final line. That
# matters for the piped form: if the connection drops mid-transfer, bash executes
# whatever bytes arrived. Without the wrapper a truncated download could run half an
# installer. With it, an incomplete file simply never calls main.
#
# Installs, with no root required:
#
#   ~/.local/lib/pipassword/app     the source tree
#   ~/.local/lib/pipassword/venv    a private virtualenv with pinned dependencies
#   ~/.local/bin/pipw               launcher
#
# The vault lives separately at ~/.local/share/pipassword/vault and is never touched
# by this script. That separation is deliberate: you point Syncthing at the vault
# directory, and the application must not be inside it.
#
# Environment:
#   PIPASSWORD_REF=v0.1.0       git ref to install (default: main)
#   PIPASSWORD_SOURCE=/path     install from a local directory instead of downloading
#   PIPASSWORD_PREFIX=~/.local  install prefix
#   PIPASSWORD_ALLOW_UNSUPPORTED=1   skip the aarch64 check (development only)

set -euo pipefail

pipassword_install() {
    local repo_url="${PIPASSWORD_REPO:-https://github.com/laonan/pipassword}"
    local ref="${PIPASSWORD_REF:-main}"
    local prefix="${PIPASSWORD_PREFIX:-$HOME/.local}"
    local source_dir="${PIPASSWORD_SOURCE:-}"
    local action="${1:-install}"

    local lib_dir="$prefix/lib/pipassword"
    local app_dir="$lib_dir/app"
    local venv_dir="$lib_dir/venv"
    local bin_dir="$prefix/bin"
    local launcher="$bin_dir/pipw"

    local red="" green="" yellow="" bold="" reset=""
    if [ -t 2 ] && [ "${TERM:-dumb}" != "dumb" ]; then
        red=$'\033[31m'; green=$'\033[32m'; yellow=$'\033[33m'
        bold=$'\033[1m'; reset=$'\033[0m'
    fi

    say()  { printf '%s\n' "$*" >&2; }
    step() { printf '%s==>%s %s\n' "$bold" "$reset" "$*" >&2; }
    warn() { printf '%swarning:%s %s\n' "$yellow" "$reset" "$*" >&2; }
    die()  { printf '%serror:%s %s\n' "$red" "$reset" "$*" >&2; exit 1; }

    # ---------------------------------------------------------------- uninstall

    if [ "$action" = "uninstall" ]; then
        step "Removing pipassword"
        # Copy the script out of the tree it is about to delete, so removing the
        # app directory cannot pull the rug from under a running bash.
        local self_copy
        self_copy="$(mktemp)"
        cp "${BASH_SOURCE[0]}" "$self_copy" 2>/dev/null || true
        rm -f "$launcher" "$bin_dir/pipw-uninstall"
        rm -rf "$lib_dir"
        rm -f "$self_copy"
        say ""
        say "${green}Removed.${reset}"
        say "Your vault was NOT touched. It is still at:"
        say "  ${XDG_DATA_HOME:-$HOME/.local/share}/pipassword/vault"
        say "Delete it yourself if that is what you want."
        return 0
    fi

    # ------------------------------------------------------------ requirements

    step "Checking requirements"

    local uname_s uname_m
    uname_s="$(uname -s)"
    uname_m="$(uname -m)"

    if [ "${PIPASSWORD_ALLOW_UNSUPPORTED:-}" = "1" ]; then
        warn "skipping platform check because PIPASSWORD_ALLOW_UNSUPPORTED=1"
    else
        [ "$uname_s" = "Linux" ] || die "Linux is required (found $uname_s).
  pipassword targets 64-bit Raspberry Pi OS. Set
  PIPASSWORD_ALLOW_UNSUPPORTED=1 to install anyway for development."
        case "$uname_m" in
            aarch64|arm64) ;;
            armv6l|armv7l)
                die "32-bit ARM is not supported (found $uname_m).
  The cryptography and argon2 wheels are aarch64 only, so they would have to
  compile from source on the device. Reinstall with 64-bit Raspberry Pi OS." ;;
            *)
                die "an aarch64 CPU is required (found $uname_m).
  Set PIPASSWORD_ALLOW_UNSUPPORTED=1 to install anyway for development." ;;
        esac
    fi

    local python=""
    local candidate
    for candidate in python3.13 python3.12 python3.11 python3; do
        if command -v "$candidate" >/dev/null 2>&1; then
            if "$candidate" -c 'import sys; sys.exit(0 if sys.version_info[:2] >= (3, 11) else 1)' 2>/dev/null; then
                python="$candidate"
                break
            fi
        fi
    done
    [ -n "$python" ] || die "Python 3.11 or later is required.
  On Raspberry Pi OS Bookworm: sudo apt install python3 python3-venv"

    "$python" -c 'import venv' 2>/dev/null \
        || die "the venv module is missing. sudo apt install python3-venv"

    say "  platform   $uname_s $uname_m"
    say "  python     $("$python" -V 2>&1) at $(command -v "$python")"

    # ------------------------------------------------------------------ source

    local staging="" cleanup_staging=0
    if [ -n "$source_dir" ]; then
        step "Using local source $source_dir"
        [ -f "$source_dir/pyproject.toml" ] \
            || die "$source_dir does not look like a pipassword checkout"
        staging="$source_dir"
    else
        step "Downloading $repo_url at $ref"
        command -v curl >/dev/null 2>&1 || die "curl is required. sudo apt install curl"
        command -v tar  >/dev/null 2>&1 || die "tar is required"

        staging="$(mktemp -d)"
        cleanup_staging=1
        # shellcheck disable=SC2064
        trap "rm -rf '$staging'" EXIT

        local tarball="$repo_url/archive/refs/heads/$ref.tar.gz"
        case "$ref" in
            v[0-9]*) tarball="$repo_url/archive/refs/tags/$ref.tar.gz" ;;
        esac

        if ! curl -fsSL "$tarball" | tar -xz -C "$staging" --strip-components=1; then
            die "could not download $tarball
  Check the ref name, or set PIPASSWORD_SOURCE to a local checkout."
        fi
        [ -f "$staging/pyproject.toml" ] || die "downloaded archive looks wrong"
    fi

    # --------------------------------------------------------------- install

    step "Installing to $lib_dir"
    mkdir -p "$lib_dir" "$bin_dir"

    # Replace the app tree wholesale rather than merging, so a removed module from
    # a previous version cannot linger and shadow anything.
    #
    # An explicit include list, not tar --exclude: exclusion pattern matching differs
    # between BSD tar and GNU tar, and an earlier version of this script silently
    # shipped build/ and .pytest_cache/ on macOS while excluding them on Linux.
    rm -rf "$app_dir.new"
    mkdir -p "$app_dir.new"
    local item
    for item in src tests pyproject.toml LICENSE README.md FORMAT.md \
                install.sh recover.py .kiro; do
        [ -e "$staging/$item" ] || continue
        cp -R "$staging/$item" "$app_dir.new/"
    done
    # Caches can still ride along inside src/ or tests/ from a working checkout.
    find "$app_dir.new" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
    find "$app_dir.new" -name '*.pyc' -delete 2>/dev/null || true
    rm -rf "$app_dir.new/.pytest_cache" "$app_dir.new/src/pipassword.egg-info"

    if [ ! -d "$venv_dir" ]; then
        step "Creating virtualenv"
        "$python" -m venv "$venv_dir"
    fi

    step "Installing dependencies"
    # pyproject.toml remains the single source of truth for the pinned dependency
    # set; pip reads it. We are changing the delivery channel, not the manifest.
    "$venv_dir/bin/python" -m pip install --quiet --upgrade pip >/dev/null
    if ! "$venv_dir/bin/python" -m pip install --quiet "$app_dir.new"; then
        rm -rf "$app_dir.new"
        die "dependency installation failed.
  If a wheel was unavailable and a build was attempted, you are probably on
  32-bit Raspberry Pi OS. pipassword needs the 64-bit image."
    fi

    # pip builds in-tree and leaves build/ and *.egg-info behind. Harmless, but the
    # app directory should contain source and nothing else.
    rm -rf "$app_dir.new/build" "$app_dir.new/src/pipassword.egg-info"

    rm -rf "$app_dir"
    mv "$app_dir.new" "$app_dir"

    # ------------------------------------------------------------- launcher

    step "Writing $launcher"
    cat > "$launcher" <<LAUNCHER
#!/usr/bin/env bash
# Generated by the pipassword installer. Edits will be overwritten on update.
exec "$venv_dir/bin/pipw" "\$@"
LAUNCHER
    chmod 755 "$launcher"

    cat > "$bin_dir/pipw-uninstall" <<UNINSTALL
#!/usr/bin/env bash
# Generated by the pipassword installer.
exec env PIPASSWORD_PREFIX="$prefix" bash "$app_dir/install.sh" uninstall
UNINSTALL
    chmod 755 "$bin_dir/pipw-uninstall"

    [ "$cleanup_staging" = "1" ] && trap - EXIT

    # -------------------------------------------------------------- verify

    step "Verifying"
    local version
    version="$(PIPASSWORD_ALLOW_UNSUPPORTED="${PIPASSWORD_ALLOW_UNSUPPORTED:-}" \
        "$launcher" --version 2>/dev/null || true)"
    [ -n "$version" ] || die "the installed launcher does not run"
    say "  $version"

    say ""
    say "${green}Installed.${reset}"

    case ":$PATH:" in
        *":$bin_dir:"*) ;;
        *)
            say ""
            warn "$bin_dir is not on your PATH. Add this to ~/.bashrc:"
            say "    export PATH=\"\$PATH:$bin_dir\"" ;;
    esac

    say ""
    say "Next:"
    say "  pipw gen -p        pick a master passphrase"
    say "  pipw calibrate     measure key derivation on THIS device before you"
    say "                     create a vault, since the setting is baked in"
    say "  pipw init          create the vault and print the recovery key"
    say "  pipw tui           the interface"
    say ""
    say "Already using minipassword?"
    say "  pipw import-legacy --dry-run    read-only; your old vault is untouched"
    say ""
    say "To update:   re-run this installer"
    say "To remove:   pipw-uninstall"
}

pipassword_install "$@"
