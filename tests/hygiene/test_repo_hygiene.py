"""The repo is public: no secrets or environment identifiers in tracked files, and the contract
version is stated once and agrees everywhere. Run in CI next to the unit tests."""

import pathlib
import re
import subprocess

ROOT = pathlib.Path(__file__).parents[2]
SKIP = {"package-lock.json"}
PATTERNS = {
    "private IPv4": re.compile(r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b"),
    "internal hostname": re.compile(r"\b[\w-]+\.(?:lan|home\.arpa|internal|corp)\b"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{40,}\b"),
    "private key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----\s*[A-Za-z0-9+/=\s]{60,}"),  # a body, not a bare header
    "email": re.compile(r"[\w.+-]+@(?!example\.(?:com|org)\b|users\.noreply\.github\.com\b|github\.com\b|anthropic\.com\b|openssh\.com\b)[\w-]+\.[a-z]{2,}\b"),
}


def tracked() -> list[pathlib.Path]:
    out = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z"], capture_output=True, text=True, check=True)
    return [ROOT / f for f in out.stdout.split("\0") if f and pathlib.Path(f).name not in SKIP]


def test_no_secrets_or_environment_identifiers_in_tracked_files():
    hits = []
    for f in tracked():
        try:
            text = f.read_text()
        except (UnicodeDecodeError, OSError):
            continue
        for name, rx in PATTERNS.items():
            hits += [f"{f.relative_to(ROOT)}: {name}: {m.group(0)}" for m in rx.finditer(text)]
    assert not hits, "\n".join(hits)


def test_contract_version_is_stated_once_and_agrees():
    version = (ROOT / "contract/VERSION").read_text().strip()
    init = (ROOT / "general/src/terracotta_general/__init__.py").read_text()
    assert re.search(rf"CONTRACT_VERSION\s*=\s*{version}\b", init)
    assert re.search(rf'version:\s*"{version}"', (ROOT / "contract/openapi.yaml").read_text())
