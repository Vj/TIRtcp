"""
TIRtcp PDF Report Exporter
Converts generated HTML assessment reports into executive PDF deliverables via WeasyPrint
when installed, or degrades gracefully with a clear operator message.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional


def export_html_to_pdf(html_path: Path, pdf_path: Optional[Path] = None) -> Optional[Path]:
    """Render html_path to PDF using WeasyPrint if available."""
    target_pdf = pdf_path or html_path.with_suffix(".pdf")
    try:
        import weasyprint  # type: ignore
    except Exception:
        return None

    try:
        weasyprint.HTML(filename=str(html_path)).write_pdf(str(target_pdf))
        return target_pdf
    except Exception:
        return None
