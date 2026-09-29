import yaml
import os

# Subdirectories of tests-library that are NOT security test templates
_EXCLUDED_DIRS = {"compliance", "remediation", "resources"}


class YAMLParser:
    """
    Parses Akto YAML files and returns a structured representation.
    """
    def __init__(self, templates_dir: str):
        self.templates_dir = templates_dir

    def load_all_templates(self) -> list[dict]:
        """
        Recursively finds and loads all YAML templates in the given directory.
        Skips compliance/, remediation/, and resources/ subdirectories which
        contain non-test YAML files with a different structure.
        """
        templates = []
        for root, dirs, files in os.walk(self.templates_dir):
            # Prune excluded top-level subdirectories in-place so os.walk skips them
            rel = os.path.relpath(root, self.templates_dir)
            top_part = rel.split(os.sep)[0]
            if top_part in _EXCLUDED_DIRS:
                dirs.clear()
                continue

            for file in files:
                if file.endswith(('.yaml', '.yml')):
                    path = os.path.join(root, file)
                    try:
                        with open(path, 'r', encoding='utf-8') as f:
                            data = yaml.safe_load(f)
                            # Ensure basic structure exists
                            if data and 'id' in data and 'execute' in data:
                                templates.append(data)
                    except Exception as e:
                        print(f"Error parsing template {path}: {e}")
        return templates

    def parse_template(self, template_id: str) -> dict:
        """
        Finds and parses a specific template by its ID.
        """
        # This would usually involve a pre-cached map or a recursive search
        all_templates = self.load_all_templates()
        for t in all_templates:
            if t['id'] == template_id:
                return t
        return None
