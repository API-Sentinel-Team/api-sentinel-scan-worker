"""Every place this repo names a sentinel-core version must name the same one.

pyproject, Dockerfile, requirements and the CI workflows are edited by hand; if one is missed the
image, the tests and the deploy silently run different cores.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PIN = re.compile(r"api-sentinel-core\.git@(v\d+\.\d+\.\d+)|CORE_REF:\s*(v\d+\.\d+\.\d+)")
FILES = ["pyproject.toml", "requirements.txt", "Dockerfile", *(p.relative_to(ROOT).as_posix() for p in (ROOT / ".github" / "workflows").glob("*.yml"))]


def test_all_sentinel_core_pins_agree():
    found = {}
    for name in FILES:
        path = ROOT / name
        if path.is_file():
            for match in PIN.finditer(path.read_text(encoding="utf-8")):
                found.setdefault(match.group(1) or match.group(2), []).append(name)
    assert found, "no sentinel-core pin found - this guard is not checking anything"
    assert len(found) == 1, f"sentinel-core is pinned to different versions: {found}"
