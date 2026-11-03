"""
scripts/build_lambda.py — Build the Lambda bundle into build/lambda/
=====================================================================

Downloads LINUX wheels (manylinux, CPython 3.12, x86_64) even when run on
Windows or macOS, so no Docker is needed. Then copies in the source files
the Lambda needs. CDK zips build/lambda/ during `cdk deploy`.

    python scripts/build_lambda.py
"""

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "build" / "lambda"
SOURCES = ["lambda_handler.py", "graph.py", "detector.py", "telemetry.py", "dynamo_store.py"]


def main():
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)

    subprocess.run([
        sys.executable, "-m", "pip", "install",
        "-r", str(ROOT / "requirements-lambda.txt"),
        "--target", str(OUT),
        "--platform", "manylinux2014_x86_64",
        "--implementation", "cp",
        "--python-version", "3.12",
        "--only-binary=:all:",
        "--upgrade", "--quiet",
    ], check=True)

    for name in SOURCES:
        shutil.copy2(ROOT / name, OUT / name)

    # Trim things Lambda never needs
    for pattern in ("**/__pycache__", "**/tests"):
        for path in OUT.glob(pattern):
            shutil.rmtree(path, ignore_errors=True)

    size_mb = sum(f.stat().st_size for f in OUT.rglob("*") if f.is_file()) / 1_048_576
    print(f"Built {OUT} ({size_mb:.1f} MB unzipped; Lambda limit is 250 MB)")
    if size_mb > 250:
        sys.exit("Bundle too large for Lambda")


if __name__ == "__main__":
    main()
