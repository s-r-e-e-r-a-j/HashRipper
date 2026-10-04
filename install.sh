#!/usr/bin/env bash

# Developer: Sreeraj
# GitHub: https://github.com/s-r-e-e-r-a-j

set -euo pipefail

OUT="hashripper"
IS_TERMUX=0
if [[ -n "${TERMUX_VERSION:-}" || "${PREFIX:-}" == *"/com.termux/"* || -d "/data/data/com.termux" ]]; then
    IS_TERMUX=1
fi
if [[ $IS_TERMUX -eq 1 ]]; then
    DEST="${PREFIX}/bin/${OUT}"
else
    DEST="/usr/local/bin/${OUT}"
    if [[ $EUID -ne 0 ]]; then
        echo "[!] Please run this installer as root or using sudo."
        exit 1
    fi
fi

if [[ ! -f Makefile && ! -f makefile ]]; then
    echo "[!] Makefile not found in current directory."
    exit 1
fi

PM=""
if [[ $IS_TERMUX -eq 1 ]]; then
    PM="termux"
elif command -v apt-get >/dev/null 2>&1; then
    PM="apt"
elif command -v dnf >/dev/null 2>&1; then
    PM="dnf"
elif command -v yum >/dev/null 2>&1; then
    PM="yum"
elif command -v pacman >/dev/null 2>&1; then
    PM="pacman"
else
    echo "[!] No supported package manager found."
    echo "    Install gcc, make, OpenSSL development files, zlib development files, and xxHash development files manually."
    exit 1
fi

echo "[*] Detected package manager: $PM"

need_gcc=0
need_make=0
need_openssl=0
need_zlib=0
need_xxhash=0

command -v clang >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1 || need_gcc=1
command -v make >/dev/null 2>&1 || need_make=1
if [[ $IS_TERMUX -eq 1 ]]; then
    [[ -f "$PREFIX/include/openssl/evp.h" ]] || need_openssl=1
    [[ -f "$PREFIX/include/zlib.h" ]] || need_zlib=1
    [[ -f "$PREFIX/include/xxhash.h" ]] || need_xxhash=1
else
    [[ -f /usr/include/openssl/evp.h || -f /usr/local/include/openssl/evp.h ]] || need_openssl=1
    [[ -f /usr/include/zlib.h || -f /usr/local/include/zlib.h ]] || need_zlib=1
    [[ -f /usr/include/xxhash.h || -f /usr/local/include/xxhash.h ]] || need_xxhash=1
fi

install_deps_termux() {
    local pkgs=()
    [[ $need_gcc -eq 1 ]] && pkgs+=(clang)
    [[ $need_make -eq 1 ]] && pkgs+=(make)
    [[ $need_openssl -eq 1 ]] && pkgs+=(openssl)
    [[ $need_zlib -eq 1 ]] && pkgs+=(zlib)
    [[ $need_xxhash -eq 1 ]] && pkgs+=(xxhash)
    if [[ ${#pkgs[@]} -gt 0 ]]; then
        pkg update
        pkg install -y "${pkgs[@]}"
    fi
}

install_deps_apt() {
    local pkgs=()
    if [[ $need_gcc -eq 1 || $need_make -eq 1 ]]; then
        pkgs+=(build-essential)
    fi
    [[ $need_openssl -eq 1 ]] && pkgs+=(libssl-dev)
    [[ $need_zlib -eq 1 ]] && pkgs+=(zlib1g-dev)
    [[ $need_xxhash -eq 1 ]] && pkgs+=(libxxhash-dev)
    if [[ ${#pkgs[@]} -gt 0 ]]; then
        apt-get update
        apt-get install -y "${pkgs[@]}"
    fi
}

install_deps_rhel() {
    local pkgs=()
    if [[ $need_gcc -eq 1 || $need_make -eq 1 ]]; then
        if command -v dnf >/dev/null 2>&1; then
            dnf groupinstall -y "Development Tools"
        else
            yum groupinstall -y "Development Tools"
        fi
    fi
    [[ $need_openssl -eq 1 ]] && pkgs+=(openssl-devel)
    [[ $need_zlib -eq 1 ]] && pkgs+=(zlib-devel)
    [[ $need_xxhash -eq 1 ]] && pkgs+=(xxhash-devel)
    if [[ ${#pkgs[@]} -gt 0 ]]; then
        if command -v dnf >/dev/null 2>&1; then
            dnf install -y "${pkgs[@]}"
        else
            yum install -y "${pkgs[@]}"
        fi
    fi
}

install_deps_arch() {
    local pkgs=()
    if [[ $need_gcc -eq 1 || $need_make -eq 1 ]]; then
        pkgs+=(base-devel)
    fi
    [[ $need_openssl -eq 1 ]] && pkgs+=(openssl)
    [[ $need_zlib -eq 1 ]] && pkgs+=(zlib)
    [[ $need_xxhash -eq 1 ]] && pkgs+=(xxhash)
    if [[ ${#pkgs[@]} -gt 0 ]]; then
        pacman -S --noconfirm --needed "${pkgs[@]}"
    fi
}

case "$PM" in
    termux) install_deps_termux ;;
    apt) install_deps_apt ;;
    dnf|yum) install_deps_rhel ;;
    pacman) install_deps_arch ;;
esac

if ! command -v clang >/dev/null 2>&1 && ! command -v gcc >/dev/null 2>&1; then
    echo "[!] C compiler not found after installation."
    exit 1
fi
command -v make >/dev/null 2>&1 || { echo "[!] make not found after installation."; exit 1; }
if [[ $IS_TERMUX -eq 1 ]]; then
    [[ -f "$PREFIX/include/openssl/evp.h" ]] || { echo "[!] OpenSSL headers not found."; exit 1; }
    [[ -f "$PREFIX/include/zlib.h" ]] || { echo "[!] zlib headers not found."; exit 1; }
    [[ -f "$PREFIX/include/xxhash.h" ]] || { echo "[!] xxHash headers not found."; exit 1; }
else
    [[ -f /usr/include/openssl/evp.h || -f /usr/local/include/openssl/evp.h ]] || { echo "[!] OpenSSL headers not found."; exit 1; }
    [[ -f /usr/include/zlib.h || -f /usr/local/include/zlib.h ]] || { echo "[!] zlib headers not found."; exit 1; }
    [[ -f /usr/include/xxhash.h || -f /usr/local/include/xxhash.h ]] || { echo "[!] xxHash headers not found."; exit 1; }
fi

BUILD_TARGET="hashripper"

echo "[*] Building $BUILD_TARGET..."
make clean >/dev/null 2>&1 || true
make

if [[ ! -f "$BUILD_TARGET" ]]; then
    echo "[!] Build completed but '$BUILD_TARGET' was not produced."
    exit 1
fi

install -m 755 "$BUILD_TARGET" "$DEST"

if [[ $IS_TERMUX -eq 0 ]] && command -v ldconfig >/dev/null 2>&1; then
    ldconfig >/dev/null 2>&1 || true
fi

echo "[+] Installation complete!"
echo "[+] Binary: $DEST"
echo "[+] Run with: $OUT"
