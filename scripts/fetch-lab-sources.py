"""Clone Juice Shop and DVWA source trees into labs/ for static analysis."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LABS = ROOT / "labs"

REPOS = {
    "juice-shop": "https://github.com/juice-shop/juice-shop.git",
    "dvwa": "https://github.com/digininja/DVWA.git",
}


def run(cmd: list[str], cwd: Path | None = None) -> None:
    print("+", " ".join(cmd))
    subprocess.run(cmd, cwd=cwd, check=True)


def fetch(name: str, url: str) -> None:
    dest = LABS / name
    if dest.exists() and (dest / ".git").exists():
        print(f"{name}: already cloned, fetching updates")
        run(["git", "-C", str(dest), "fetch", "--depth", "1"])
        run(["git", "-C", str(dest), "reset", "--hard", "FETCH_HEAD"])
        return
    if dest.exists():
        print(f"{name}: {dest} exists but is not a git clone; skipping")
        return
    LABS.mkdir(parents=True, exist_ok=True)
    run(["git", "clone", "--depth", "1", url, str(dest)])


def main() -> int:
    if not shutil_which("git"):
        print("git is required on PATH to fetch lab sources.", file=sys.stderr)
        return 1
    for name, url in REPOS.items():
        try:
            fetch(name, url)
        except subprocess.CalledProcessError as exc:
            print(f"Failed to fetch {name}: {exc}", file=sys.stderr)
            return 1
    print(f"Lab sources ready under {LABS}")
    return 0


def shutil_which(name: str) -> str | None:
    from shutil import which

    return which(name)


if __name__ == "__main__":
    raise SystemExit(main())
