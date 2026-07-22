"""JSON report renderer."""

from __future__ import annotations

import json

from previewshield.models import to_primitive
from previewshield.reporters import Report, _sanitize_primitive


def render_json(report: Report) -> str:
    """Serialize a report as pretty, stable, secret-safe JSON."""

    payload = _sanitize_primitive(to_primitive(report))
    return f"{json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False)}\n"


render = render_json

__all__ = ["render", "render_json"]
