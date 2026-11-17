#!/usr/bin/env python3
"""package the lambda: handler + shredder package + pynacl, zipped."""
import os
import shutil
import subprocess
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "lambda.zip")
STAGE = os.path.join(ROOT, ".lambda-stage")


def main() -> int:
    shutil.rmtree(STAGE, ignore_errors=True)
    os.makedirs(STAGE)
    # the handler and the shredder package go in as plain source
    shutil.copy(os.path.join(ROOT, "lambda", "handler.py"), STAGE)
    shutil.copytree(os.path.join(ROOT, "shredder"),
                    os.path.join(STAGE, "shredder"),
                    ignore=shutil.ignore_patterns("__pycache__"))
    # pynacl's compiled wheel must come from the target runtime; in CI we
    # fetch it into the stage dir so the zip is self-contained
    deps = subprocess.run(
        [sys.executable, "-m", "pip", "install", "--target", STAGE,
         "--platform", "manylinux2014_x86_64", "--only-binary=:all:",
         "pynacl"],
        capture_output=True, text=True)
    if deps.returncode != 0:
        print(deps.stdout[-500:], deps.stderr[-500:])
        print("warning: could not fetch a manylinux pynacl wheel; "
              "packaging source-only")
    for junk in ("__pycache__", "bin"):
        shutil.rmtree(os.path.join(STAGE, junk), ignore_errors=True)

    with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as z:
        for dirpath, _dirs, names in os.walk(STAGE):
            for n in names:
                p = os.path.join(dirpath, n)
                z.write(p, os.path.relpath(p, STAGE))
    shutil.rmtree(STAGE, ignore_errors=True)
    size = os.path.getsize(OUT)
    print(f"lambda.zip built: {size} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
