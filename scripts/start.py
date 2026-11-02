"""One-command local launch on macOS/Linux/Windows. No Node.js required."""

from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import venv


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--lab", action="store_true")
    parser.add_argument("--skip-install", action="store_true")
    args = parser.parse_args()
    if sys.version_info < (3, 10):
        raise SystemExit("Python 3.10+ is required (3.12 tested).")
    root = Path(__file__).resolve().parents[1]
    environment = root / ".venv"
    python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if not python.exists():
        venv.EnvBuilder(with_pip=True).create(environment)
    if not args.skip_install:
        subprocess.run(
            [str(python), "-m", "pip", "install", "-r", str(root / "requirements.lock")], check=True, cwd=root
        )
        subprocess.run(
            [str(python), "-m", "pip", "install", "-e", str(root), "--no-deps"], check=True, cwd=root
        )
    env = dict(os.environ)
    if args.lab:
        file = Path.home() / ".netscope/lab.json"
        if not file.exists():
            raise SystemExit("Run python scripts/lab.py up first. Static mode does not need a lab.")
        lab = json.loads(file.read_text())
        if not lab.get("contexts"):
            raise SystemExit("Lab setup is incomplete. See docs/LIVE_LAB.md.")
        env.update(
            {
                "NETSCOPE_ALLOWED_CONTEXTS": json.dumps(lab["contexts"]),
                "KUBECONFIG": lab["kubeconfig"],
                "NETSCOPE_FIXTURE_IMAGE": lab["fixture_image"],
            }
        )
    print(f"\nNetScope → http://127.0.0.1:{args.port}\nPress Ctrl+C to stop.\n", flush=True)
    try:
        subprocess.run(
            [str(python), "-m", "app.cli", "serve", "--port", str(args.port)], env=env, cwd=root, check=True
        )
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
