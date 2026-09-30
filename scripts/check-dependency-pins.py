#!/usr/bin/env python3
"""Fail CI if a git dependency can float or the validated lock disagrees."""
from pathlib import Path
import re
import tomllib

root = Path(__file__).resolve().parent.parent
manifest = tomllib.loads((root / "Cargo.toml").read_text())
lock = tomllib.loads((root / "Cargo.lock").read_text())
sections = [manifest, *manifest.get("target", {}).values()]
checked = set()
for section in sections:
    for table in ["dependencies", "dev-dependencies", "build-dependencies"]:
        for name, dependency in section.get(table, {}).items():
            if not isinstance(dependency, dict) or "git" not in dependency:
                continue
            revision = dependency.get("rev", "")
            assert re.fullmatch(r"[0-9a-f]{40}", revision), f"{name}: require a full revision"
            assert "branch" not in dependency and "tag" not in dependency, f"{name}: floating source"
            source = f"git+{dependency['git']}?rev={revision}#{revision}"
            assert any(p["name"] == dependency.get("package", name) and p.get("source") == source
                       for p in lock["package"]), f"{name}: lock differs from reviewed revision"
            checked.add(name)
assert "crlt" in checked, "crlt must remain pinned"
print("Git dependency pins match the validated lock")
