import logging
from html import escape
from typing import Dict, Any, Optional
from server.modules.compliance.report_generator import sanitize_compliance_report_value

logger = logging.getLogger(__name__)


def _safe_html(value: Any) -> str:
    redacted = sanitize_compliance_report_value("" if value is None else value)
    return escape(str(redacted), quote=True)

class PDFRenderer:
    """
    Renders security reports as human-readable HTML/PDF.
    """
    def generate_html(self, report: Dict[str, Any]) -> str:
        """
        Takes the compliance report JSON and builds a CSS-styled HTML page.
        """
        framework = _safe_html(report.get('framework', 'Security Report'))
        summary = _safe_html(f"Total Open Vulnerabilities: {report.get('total_open', 0)}")
        
        sections_html = ""
        for section, vulns in report.get('sections', {}).items():
            vuln_rows = "".join([
                f"""<tr>
                    <td>{_safe_html(v.get('severity'))}</td>
                    <td>{_safe_html(v.get('title'))}</td>
                    <td>{_safe_html(v.get('endpoint'))}</td>
                    <td>{_safe_html(v.get('evidence'))}</td>
                </tr>""" for v in vulns
            ])
            
            sections_html += f"""
                <div class="section">
                    <h3>{_safe_html(section)}</h3>
                    <table>
                        <thead>
                            <tr><th>Severity</th><th>Problem</th><th>Endpoint</th><th>Evidence</th></tr>
                        </thead>
                        <tbody>{vuln_rows}</tbody>
                    </table>
                </div>
            """

        html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: sans-serif; padding: 20px; }}
                h1 {{ color: #d32f2f; }}
                .section {{ margin-bottom: 30px; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f5f5f5; }}
            </style>
        </head>
        <body>
            <h1>Compliance Report: {framework}</h1>
            <p><strong>{summary}</strong></p>
            {sections_html}
        </body>
        </html>
        """
        return html

    async def save_pdf(self, html: str, filepath: str) -> bool:
        """
        Render ``html`` to a real PDF at ``filepath``.

        Uses WeasyPrint when installed. If WeasyPrint is unavailable, returns
        ``False`` and logs a clear warning instead of silently writing HTML
        under a ``.pdf`` name.
        """
        try:
            from weasyprint import HTML  # type: ignore
        except ImportError:
            logger.warning(
                "save_pdf_failed_no_renderer: WeasyPrint is not installed; "
                "install `weasyprint` to enable PDF export. No file written."
            )
            return False

        try:
            HTML(string=html).write_pdf(filepath)
            return True
        except Exception as e:
            logger.error("save_pdf_failed: %s", e)
            return False
