"""Write a SHA-256 manifest and build provenance for a packaged artifact."""
import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import subprocess
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    artifact = args.artifact.resolve(strict=True)
    output_dir = (args.output_dir or artifact.parent).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    with artifact.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    sha256 = digest.hexdigest()
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True,
            check=True, timeout=5,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        commit = "unknown"
    packages = {}
    for name in ("pywebview", "yara-python", "pyinstaller"):
        try:
            packages[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            packages[name] = "not-installed"
    (output_dir / "SHA256SUMS.txt").write_text(
        f"{sha256}  {artifact.name}\n", encoding="ascii"
    )
    provenance = {
        "artifact": artifact.name,
        "sha256": sha256,
        "commit": os.environ.get("GITHUB_SHA", commit),
        "ref": os.environ.get("GITHUB_REF", "local"),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "dependencies": packages,
        "signed": False,
    }
    (output_dir / "build-provenance.json").write_text(
        json.dumps(provenance, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"SHA-256 {sha256}  {artifact.name}")


if __name__ == "__main__":
    main()
