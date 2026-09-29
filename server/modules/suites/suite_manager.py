"""
Test suite manager — groups YAML templates into named suites.
Mirrors Akto's default_test_suites collection.
"""
from server.modules.test_executor.wordlist_manager import WordlistManager


# OWASP API Security Top 10 (2023) mapping to our category codes
OWASP_API_TOP_10_SUITE = ["BOLA", "NO_AUTH", "MA", "BFLA", "INPUT", "RL", "SM", "SM", "INJECT", "SSRF"]

BUILTIN_SUITES = {
    "OWASP_API_TOP_10": ["BOLA", "NO_AUTH", "MA", "BFLA", "INPUT", "RL", "SM", "INJECT", "SSRF"],
    "HACKERONE_TOP_10": ["BOLA", "NO_AUTH", "MA", "COMMAND_INJECTION", "BFLA", "XSS", "SSRF", "LFI"],
    "CRITICAL_ONLY":    None,   # filter by severity
    "HIGH_AND_CRITICAL": None,
    "ALL":              None,   # run all templates
    "FAST":             None,   # duration: FAST templates only
    "NON_INTRUSIVE":    None,   # nature: NON_INTRUSIVE only
}


class SuiteManager:
    """
    Returns the set of templates that belong to a given suite name.
    """

    def get_suite_templates(self, suite_name: str) -> list[dict]:
        """Returns full template dicts for the given suite."""
        wm = WordlistManager.get_instance()
        all_templates = wm.templates

        name = suite_name.upper()

        if name == "ALL":
            return all_templates

        if name == "CRITICAL_ONLY":
            return [t for t in all_templates if self._severity(t) == "CRITICAL"]

        if name == "HIGH_AND_CRITICAL":
            return [t for t in all_templates if self._severity(t) in ("CRITICAL", "HIGH")]

        if name == "FAST":
            return [t for t in all_templates if t.get("attributes", {}).get("duration") == "FAST"]

        if name == "NON_INTRUSIVE":
            return [t for t in all_templates if t.get("attributes", {}).get("nature") == "NON_INTRUSIVE"]

        # Category-based suite
        categories = BUILTIN_SUITES.get(name)
        if categories:
            return [t for t in all_templates if self._category(t) in categories]

        return []

    def list_suites(self) -> list[dict]:
        """Return metadata about all built-in suites."""
        wm = WordlistManager.get_instance()
        result = []
        for name in BUILTIN_SUITES:
            templates = self.get_suite_templates(name)
            result.append({
                "name": name,
                "template_count": len(templates),
                "description": self._suite_description(name),
            })
        return result

    def _severity(self, t: dict) -> str:
        return t.get("info", {}).get("severity", "").upper()

    def _category(self, t: dict) -> str:
        return t.get("info", {}).get("category", {}).get("name", "").upper()

    def _suite_description(self, name: str) -> str:
        return {
            "OWASP_API_TOP_10": "Tests mapped to OWASP API Security Top 10 (2023)",
            "HACKERONE_TOP_10": "Tests mapped to HackerOne Top 10 API vulnerabilities",
            "CRITICAL_ONLY": "Only CRITICAL severity tests",
            "HIGH_AND_CRITICAL": "HIGH and CRITICAL severity tests",
            "ALL": "All 200+ security test templates",
            "FAST": "Fast-running tests only (duration: FAST)",
            "NON_INTRUSIVE": "Non-intrusive tests only (safe for production)",
        }.get(name, "")
