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


def _pip_installed(pkg_spec):
    import importlib.util
    name = pkg_spec.split(">=")[0].split("==")[0].split("[")[0].split("<")[0].strip()
    _IMPORT_MAP = {
        "pyyaml": "yaml", "Pillow": "PIL", "beautifulsoup4": "bs4",
        "flask-socketio": "flask_socketio", "python-nmap": "nmap",
        "python-docx": "docx", "pyOpenSSL": "OpenSSL",
        "charset-normalizer": "charset_normalizer",
        "webdriver-manager": "webdriver_manager",
    }
    mod = _IMPORT_MAP.get(name, name.replace("-", "_"))
    return importlib.util.find_spec(mod) is not None


def install_pip_deps():
    """Install Python packages."""
    req = Path(__file__).resolve().parent / "requirements.txt"
    if not req.exists():
        print("  requirements.txt not found, skipping pip install")
        return
    with open(req) as fh:
        lines = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    missing = [l for l in lines if not _pip_installed(l)]
    if not missing:
        print("  all Python packages already installed")
        return
    for pkg in missing:
        print(f"  Installing {pkg} ...")
        _run([sys.executable, "-m", "pip", "install",
              "--break-system-packages", pkg])


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
