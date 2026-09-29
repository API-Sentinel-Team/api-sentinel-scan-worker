from .yaml_parser import YAMLParser


class WordlistManager:
    """
    Loads and manages fuzzing payloads from Akto's tests-library or custom lists.
    Uses a class-level global cache. Filters inactive templates.
    """
    _instance = None
    _templates_cache = []

    def __init__(self, templates_dir: str):
        import os
        self.parser = YAMLParser(os.path.normpath(templates_dir))

    @classmethod
    def get_instance(cls, templates_dir: str = None):
        if cls._instance is None:
            if templates_dir is None:
                from server.config import settings
                templates_dir = settings.TESTS_LIBRARY_PATH
            cls._instance = cls(templates_dir)
            cls._instance.refresh_templates()  # auto-load on first creation
        return cls._instance

    def refresh_templates(self):
        """
        Loads all templates from the directory into the class-level cache.
        Skips templates marked inactive: true.
        """
        print(f"Refreshing templates from {self.parser.templates_dir}...")
        results = self.parser.load_all_templates()
        # Filter out inactive templates
        active = [t for t in results if not t.get("inactive", False)]
        WordlistManager._templates_cache = active
        skipped = len(results) - len(active)
        print(f"Loaded {len(active)} active templates ({skipped} inactive skipped).")

    @property
    def templates(self):
        return WordlistManager._templates_cache

    def get_templates_by_severity(self, severity: str) -> list[dict]:
        return [t for t in WordlistManager._templates_cache
                if t.get("info", {}).get("severity", "").upper() == severity.upper()]

    def get_templates_by_category(self, category: str) -> list[dict]:
        return [t for t in WordlistManager._templates_cache
                if t.get("info", {}).get("category", {}).get("name", "").upper() == category.upper()]

    def list_all_template_ids(self) -> list[str]:
        return [t["id"] for t in WordlistManager._templates_cache]
