from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from server.config import BASE_DIR, settings
from server.models.core import EvidencePackage
from server.modules.utils.redactor import Redactor


def _resolve_archive_path(account_id: int, detection_type: str, detection_id: str, digest: str) -> Path:
    base_dir = settings.ARCHIVE_DIR or str(BASE_DIR / "data" / "archives")
    base = Path(base_dir)
    archive_dir = base / str(account_id) / detection_type
    archive_dir.mkdir(parents=True, exist_ok=True)
    filename = f"{detection_id}-{digest}.json"
    return archive_dir / filename


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def save_evidence_package(
    db: Any,
    account_id: int,
    detection_type: str,
    detection_id: str,
    payload: Dict[str, Any],
    metadata: Dict[str, Any],
) -> None:
    safe_payload = Redactor.redact_scan_result(payload or {})
    safe_metadata = Redactor.redact_scan_result(metadata or {})
    snapshot = {
        "payload": safe_payload,
        "metadata": safe_metadata,
        "created_at": _utc_now_iso(),
    }
    content = json.dumps(snapshot, default=str, separators=(",", ":"))
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    path = _resolve_archive_path(account_id, detection_type, detection_id, digest)
    path.write_text(content)
    db.add(EvidencePackage(
        account_id=account_id,
        detection_type=detection_type,
        detection_id=detection_id,
        path=str(path),
        metadata_blob=safe_metadata,
        digest=digest,
    ))
