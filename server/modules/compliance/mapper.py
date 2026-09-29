"""
Maps vulnerability categories to compliance frameworks:
- OWASP API Security Top 10 (2023)
- GDPR Article references
- HIPAA Safeguard references
"""
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from server.models.core import Vulnerability


# ── OWASP API Top 10 (2023) ─────────────────────────────────────────────────
OWASP_MAP = {
    "BOLA":             {"id": "API1:2023", "name": "Broken Object Level Authorization"},
    "NO_AUTH":          {"id": "API2:2023", "name": "Broken Authentication"},
    "MA":               {"id": "API3:2023", "name": "Broken Object Property Level Authorization"},
    "INPUT":            {"id": "API4:2023", "name": "Unrestricted Resource Consumption"},
    "BFLA":             {"id": "API5:2023", "name": "Broken Function Level Authorization"},
    "RL":               {"id": "API4:2023", "name": "Unrestricted Resource Consumption"},
    "SM":               {"id": "API8:2023", "name": "Security Misconfiguration"},
    "INJECT":           {"id": "API10:2023","name": "Unsafe Consumption of APIs"},
    "COMMAND_INJECTION":{"id": "API10:2023","name": "Unsafe Consumption of APIs"},
    "SSRF":             {"id": "API7:2023", "name": "Server Side Request Forgery"},
    "XSS":              {"id": "API8:2023", "name": "Security Misconfiguration"},
    "LFI":              {"id": "API8:2023", "name": "Security Misconfiguration"},
    "CORS":             {"id": "API8:2023", "name": "Security Misconfiguration"},
    "CRLF":             {"id": "API8:2023", "name": "Security Misconfiguration"},
    "SSTI":             {"id": "API10:2023","name": "Unsafe Consumption of APIs"},
    "MHH":              {"id": "API8:2023", "name": "Security Misconfiguration"},
    "IIM":              {"id": "API9:2023", "name": "Improper Inventory Management"},
    "SVD":              {"id": "API8:2023", "name": "Security Misconfiguration"},
    "UHM":              {"id": "API8:2023", "name": "Security Misconfiguration"},
    "VEM":              {"id": "API8:2023", "name": "Security Misconfiguration"},
}

# ── GDPR ─────────────────────────────────────────────────────────────────────
GDPR_MAP = {
    "BOLA":             "Art. 5(1)(f) — Integrity & Confidentiality",
    "NO_AUTH":          "Art. 32 — Security of Processing",
    "MA":               "Art. 25 — Data Protection by Design",
    "BFLA":             "Art. 5(1)(f) — Integrity & Confidentiality",
    "SM":               "Art. 32 — Security of Processing",
    "SSRF":             "Art. 32 — Security of Processing",
    "COMMAND_INJECTION":"Art. 32 — Security of Processing",
    "LFI":              "Art. 32 — Security of Processing",
}

# ── HIPAA ─────────────────────────────────────────────────────────────────────
HIPAA_MAP = {
    "BOLA":             "§164.312(a)(1) — Access Control",
    "NO_AUTH":          "§164.312(d) — Person or Entity Authentication",
    "BFLA":             "§164.312(a)(1) — Access Control",
    "MA":               "§164.308(a)(3) — Workforce Access Management",
    "SM":               "§164.312(a)(2)(iv) — Encryption and Decryption",
    "SSRF":             "§164.312(e)(1) — Transmission Security",
}

# -- PCI DSS v4 (selected mappings)
PCI_MAP = {
    "NO_AUTH":          "Req 6.3 - Access Control",
    "BOLA":             "Req 6.3 - Access Control",
    "BFLA":             "Req 6.3 - Access Control",
    "SM":               "Req 6.4 - Secure Configuration",
    "SSRF":             "Req 11.3 - Penetration Testing",
    "INJECT":           "Req 6.2 - Secure Development",
}

# -- SOC 2 (selected Trust Services Criteria)
SOC2_MAP = {
    "NO_AUTH":          "CC6.1 - Logical Access",
    "BOLA":             "CC6.1 - Logical Access",
    "SM":               "CC7.1 - Vulnerability Management",
    "INJECT":           "CC7.1 - Vulnerability Management",
}

# -- NIST SP 800-204C (API controls - simplified)
NIST_API_MAP = {
    "NO_AUTH":          "Control 3.2 - Authentication",
    "BOLA":             "Control 3.3 - Authorization",
    "BFLA":             "Control 3.3 - Authorization",
    "SM":               "Control 3.6 - Configuration",
}

# -- EU AI Act (Article 9 - risk management)
EU_AI_ACT_MAP = {
    "PROMPT_INJECTION": "Article 9 - Risk Management System",
    "DATA_EXFILTRATION":"Article 9 - Risk Management System",
    "MCP_PERMISSION_DRIFT": "Article 9 - Risk Management System",
}


class ComplianceMapper:
    """Maps vulnerability findings to compliance frameworks and generates reports."""

    def map_category(self, category: str) -> dict:
        cat = category.upper()
        return {
            "owasp_api": OWASP_MAP.get(cat, {"id": "UNKNOWN", "name": "Unclassified"}),
            "gdpr":      GDPR_MAP.get(cat, "No direct mapping"),
            "hipaa":     HIPAA_MAP.get(cat, "No direct mapping"),
            "pci":       PCI_MAP.get(cat, "No direct mapping"),
            "soc2":      SOC2_MAP.get(cat, "No direct mapping"),
            "nist":      NIST_API_MAP.get(cat, "No direct mapping"),
            "eu_ai_act": EU_AI_ACT_MAP.get(cat, "No direct mapping"),
        }

    async def generate_report(self, account_id: int, db: AsyncSession) -> dict:
        """Aggregate all open vulnerabilities into a compliance summary."""
        result = await db.execute(
            select(Vulnerability.type, func.count(Vulnerability.id))
            .where(Vulnerability.account_id == account_id, Vulnerability.status == "OPEN")
            .group_by(Vulnerability.type)
        )
        rows = result.all()

        owasp_summary = {}
        gdpr_violations = []
        hipaa_violations = []
        pci_violations = []
        soc2_violations = []
        nist_violations = []
        eu_ai_act_violations = []
        total_vulns = 0

        for category, count in rows:
            total_vulns += count
            mapping = self.map_category(category or "UNKNOWN")

            owasp = mapping["owasp_api"]
            owasp_id = owasp["id"]
            if owasp_id not in owasp_summary:
                owasp_summary[owasp_id] = {
                    "id": owasp_id,
                    "name": owasp["name"],
                    "count": 0,
                    "categories": [],
                }
            owasp_summary[owasp_id]["count"] += count
            owasp_summary[owasp_id]["categories"].append(category)

            gdpr = mapping["gdpr"]
            if gdpr != "No direct mapping" and gdpr not in gdpr_violations:
                gdpr_violations.append(gdpr)

            hipaa = mapping["hipaa"]
            if hipaa != "No direct mapping" and hipaa not in hipaa_violations:
                hipaa_violations.append(hipaa)

            pci = mapping["pci"]
            if pci != "No direct mapping" and pci not in pci_violations:
                pci_violations.append(pci)

            soc2 = mapping["soc2"]
            if soc2 != "No direct mapping" and soc2 not in soc2_violations:
                soc2_violations.append(soc2)

            nist = mapping["nist"]
            if nist != "No direct mapping" and nist not in nist_violations:
                nist_violations.append(nist)

            eu_ai = mapping["eu_ai_act"]
            if eu_ai != "No direct mapping" and eu_ai not in eu_ai_act_violations:
                eu_ai_act_violations.append(eu_ai)

        return {
            "account_id": account_id,
            "total_open_vulnerabilities": total_vulns,
            "owasp_api_top_10": {
                "compliant": len(owasp_summary) == 0,
                "violations": list(owasp_summary.values()),
            },
            "gdpr": {
                "compliant": len(gdpr_violations) == 0,
                "articles_violated": gdpr_violations,
            },
            "hipaa": {
                "compliant": len(hipaa_violations) == 0,
                "safeguards_violated": hipaa_violations,
            },
            "pci_dss_v4": {
                "compliant": len(pci_violations) == 0,
                "requirements_violated": pci_violations,
            },
            "soc2": {
                "compliant": len(soc2_violations) == 0,
                "controls_violated": soc2_violations,
            },
            "nist_sp_800_204c": {
                "compliant": len(nist_violations) == 0,
                "controls_violated": nist_violations,
            },
            "eu_ai_act": {
                "compliant": len(eu_ai_act_violations) == 0,
                "articles_violated": eu_ai_act_violations,
            },
        }
