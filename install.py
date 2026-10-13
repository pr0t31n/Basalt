#!/usr/bin/env python3
"""Basalt installer — multi-platform."""
import subprocess
import sys
import shutil
from pathlib import Path

TOOL_NAME = "Basalt"
MIN_PYTHON = (3, 10)


def _run(cmd, check=True):
    print(f"  -> {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    return subprocess.run(cmd, shell=isinstance(cmd, str), check=check)


def _has(binary):
    return shutil.which(binary) is not None


def install_pip_deps():
    """Install Python packages."""
    req = Path(__file__).resolve().parent / "requirements.txt"
    if req.exists():
        _run([sys.executable, "-m", "pip", "install",
              "--break-system-packages", "-r", str(req)])
    else:
        print("  requirements.txt not found, skipping pip install")


def main():
    if sys.version_info < MIN_PYTHON:
        v = ".".join(map(str, MIN_PYTHON))
        print(f"ERROR: Python {v}+ required (have {sys.version})")
        sys.exit(1)

    print(f"\n{TOOL_NAME} — Installation\n")

    print("[1/2] Installing Python dependencies...")
    install_pip_deps()

    print("\n[2/2] Verifying cryptography import...")
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        print("  cryptography package OK")
    except ImportError:
        print("  WARNING: cryptography package not available.")
        print("  Basalt requires it for AES-256 encryption.")
        print("  Install manually: pip install cryptography")

    print(f"\n{TOOL_NAME} installed.")
    print("  Backup : python3 basalt.py backup -s /path/to/dir -d /mnt/backup")
    print("  Restore: python3 basalt.py restore -a /mnt/backup/<id>.basalt")
    print("  Verify : python3 basalt.py verify -a /mnt/backup/<id>.basalt --deep")
    print("  List   : python3 basalt.py list -d /mnt/backup")
    print("  Prune  : python3 basalt.py prune -d /mnt/backup -r 5")


if __name__ == "__main__":
    main()
