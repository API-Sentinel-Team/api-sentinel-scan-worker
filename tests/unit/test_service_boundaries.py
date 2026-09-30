"""Architecture guard for api-sentinel-scan-worker: this repo may only depend on what its layout allows.

Repos are separate, so each one tests ITS OWN package; nothing here relies on sibling checkouts.
Cross-repo version compatibility is checked by a separate integration workflow.

Rules for package ``sentinel_worker``:
  - imports no other service package (in particular never server.*, the API).
"""
from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
NL = chr(10)
PACKAGE = "sentinel_worker"
FORBIDDEN = ('server', 'sentinel_scheduler', 'sentinel_archiver')


def _files():
    base = ROOT / PACKAGE
    # Fail loudly: a missing package must never turn this guard into a silent no-op.
    assert base.is_dir(), f"expected package directory {base} - the boundary test is not checking anything"
    found = [p for p in base.rglob("*.py") if "__pycache__" not in p.parts]
    assert found, f"no python files under {base}"
    return found


def _imports(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            yield node.lineno, node.module
        elif isinstance(node, ast.Import):
            for alias in node.names:
                yield node.lineno, alias.name


def test_sentinel_worker_does_not_import_forbidden_packages():
    violations = [
        f"{p.relative_to(ROOT)}:{line} imports {module}"
        for p in _files()
        for line, module in _imports(p)
        if module.split(".")[0] in FORBIDDEN
    ]
    assert not violations, "boundary violations:" + NL + "  " + (NL + "  ").join(sorted(violations))
