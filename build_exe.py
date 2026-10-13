#!/usr/bin/env python3
"""Build Basalt into a standalone Windows .exe via PyInstaller.

Run this on a Windows machine with Python 3.10+ installed:
    python build_exe.py

Output: dist/basalt.exe (single file, ~15-20 MB, no dependencies needed)
"""
import subprocess
import sys
import shutil
from pathlib import Path

TOOL_DIR = Path(__file__).resolve().parent


def main():
    print("Basalt — Building standalone .exe\n")

    # 1. Install build dependencies
    print("[1/3] Installing build dependencies...")
    subprocess.run([
        sys.executable, "-m", "pip", "install",
        "--break-system-packages",
        "pyinstaller>=6.0", "cryptography>=41.0.0",
    ], check=True)
    print()

    # 2. Clean previous build
    print("[2/3] Cleaning previous build artifacts...")
    for d in ("build", "dist", "__pycache__"):
        p = TOOL_DIR / d
        if p.exists():
            shutil.rmtree(p)
            print(f"  Removed {d}/")
    spec = TOOL_DIR / "basalt.spec"
    if spec.exists():
        spec.unlink()
        print("  Removed basalt.spec")
    print()

    # 3. Build
    print("[3/3] Running PyInstaller...")
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--clean",
        "--name", "basalt",
        "--add-data", f"VERSION{';' if sys.platform == 'win32' else ':'}.",
        "--hidden-import", "cryptography",
        "--hidden-import", "cryptography.hazmat.primitives.ciphers",
        "--hidden-import", "cryptography.hazmat.primitives.ciphers.algorithms",
        "--hidden-import", "cryptography.hazmat.primitives.ciphers.modes",
        "--hidden-import", "cryptography.hazmat.backends",
        "--hidden-import", "cryptography.hazmat.backends.openssl",
        "--console",
        str(TOOL_DIR / "basalt.py"),
    ]
    subprocess.run(cmd, check=True, cwd=str(TOOL_DIR))

    exe = TOOL_DIR / "dist" / ("basalt.exe" if sys.platform == "win32" else "basalt")
    if exe.exists():
        size_mb = exe.stat().st_size / (1024 * 1024)
        print(f"\nBuild successful!")
        print(f"  Output : {exe}")
        print(f"  Size   : {size_mb:.1f} MB")
        print(f"\nCopy basalt.exe to any Windows server and run:")
        print(f"  basalt.exe backup -s C:\\data\\important -d E:\\backups")
        print(f"  basalt.exe restore -a E:\\backups\\<uuid>.basalt")
    else:
        print("\nERROR: Build failed — exe not found", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
