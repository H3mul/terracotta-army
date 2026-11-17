import re

_REPO = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$")


def parse_repo(value: str) -> str:
    """Validate an `owner/repo` argument. Raises ValueError otherwise."""
    if not _REPO.fullmatch(value) or value.endswith(".git") or ".." in value:
        raise ValueError(f"not an owner/repo: {value!r}")
    return value
