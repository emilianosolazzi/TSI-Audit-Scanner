"""Minimal env_loader stub - loads .env files into os.environ."""
import os
from pathlib import Path


def load_local_env_files(paths=(".env", ".env.local")):
    for candidate in paths:
        p = Path(candidate)
        if not p.is_file():
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except OSError:
            continue
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key:
                os.environ.setdefault(key, value)


__all__ = ["load_local_env_files"]
