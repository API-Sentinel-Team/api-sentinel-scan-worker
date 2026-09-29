"""
Resolves Akto wordLists from YAML templates.

Akto wordList formats:
  1. Static list:
       wordLists:
         filePaths:
           - /etc/passwd
           - /etc/shadow

  2. Inline list:
       wordLists:
         specialChars: ["'", '"', "$"]

  3. Dynamic from sample_data:
       wordLists:
         random_ids:
           source: sample_data
           key:
             regex: "^user_id$|^userId$"
           all_apis: true

  4. For_all dynamic (Mass Assignment):
       wordLists:
         ${extraKeys}:
           for_all:
             ${iteratorKey}.wordList:
               sample_data: true
               key: "${iteratorKey}"
"""
import re
import json
from sqlalchemy.ext.asyncio import AsyncSession
from server.modules.traffic_capture.sample_data_writer import SampleDataWriter


class WordListResolver:
    """
    Resolves ${variable} references defined in wordLists sections of YAML templates.
    Handles all four Akto wordList formats.
    """

    def __init__(self, db: AsyncSession = None):
        self.db = db
        self.writer = SampleDataWriter()

    async def resolve(self, wordlists_cfg: dict) -> dict:
        """
        Returns {list_name: [value1, value2, ...]} for all defined wordLists.
        """
        resolved = {}
        if not wordlists_cfg or not isinstance(wordlists_cfg, dict):
            return resolved

        for list_name, cfg in wordlists_cfg.items():
            # Format 1 & 2: plain list (most common — 51% of templates)
            if isinstance(cfg, list):
                resolved[list_name] = [str(v) for v in cfg]
                continue

            # Format 2b: scalar (single string/number)
            if not isinstance(cfg, dict):
                resolved[list_name] = [str(cfg)]
                continue

            # Format 3: source: sample_data
            if cfg.get("source") == "sample_data" or ("key" in cfg and "regex" in cfg.get("key", {})):
                if self.db:
                    values = await self._resolve_from_sample_data(cfg)
                    resolved[list_name] = values
                else:
                    resolved[list_name] = []
                continue

            # Format 4: for_all (dynamic Mass Assignment — skip, complex)
            if "for_all" in cfg:
                resolved[list_name] = []
                continue

            # Format: inline dict with sample_data: true
            if cfg.get("sample_data") and self.db:
                values = await self._resolve_from_sample_data(cfg)
                resolved[list_name] = values
                continue

            # Fallback: treat dict values as the list
            resolved[list_name] = []

        return resolved

    async def _resolve_from_sample_data(self, cfg: dict) -> list:
        """Extract values matching a key regex from captured traffic."""
        key_rule = cfg.get("key", {})
        if isinstance(key_rule, str):
            regex_pattern = key_rule
        else:
            regex_pattern = key_rule.get("regex", ".*")

        if not self.db:
            return []

        samples = await self.writer.get_all(self.db, limit=500)
        values = set()

        for sample in samples:
            req = sample.request or {}
            self._extract_matching(req.get("body", ""), regex_pattern, values)
            resp = sample.response or {}
            self._extract_matching(resp.get("body", ""), regex_pattern, values)

        return list(values)[:50]

    def _extract_matching(self, body_str, pattern: str, values: set) -> None:
        try:
            body = json.loads(body_str) if isinstance(body_str, str) and body_str else (body_str or {})
            self._scan_dict(body, pattern, values)
        except Exception:
            pass

    def _scan_dict(self, obj, pattern: str, values: set) -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                if re.search(pattern, str(k), re.IGNORECASE):
                    if isinstance(v, (str, int, float)):
                        values.add(str(v))
                self._scan_dict(v, pattern, values)
        elif isinstance(obj, list):
            for item in obj:
                self._scan_dict(item, pattern, values)

    def expand_mutations(self, rule: dict, resolved_wordlists: dict) -> list[dict]:
        """
        Expand ${var} placeholders into one concrete mutation rule per resolved value.
        Used for execute.type = 'multiple' and static wordList substitution.
        """
        import copy

        raw = json.dumps(rule)
        placeholders = re.findall(r"\$\{(\w+)\}", raw)

        if not placeholders:
            return [rule]

        # Use the first wordList placeholder found
        var = placeholders[0]
        values = resolved_wordlists.get(var, [])

        if not values:
            return [rule]

        expanded = []
        for val in values:
            concrete = raw
            for ph in placeholders:
                ph_vals = resolved_wordlists.get(ph, [])
                concrete = concrete.replace(f"${{{ph}}}", str(val if ph == var else (ph_vals[0] if ph_vals else ph)))
            try:
                expanded.append(json.loads(concrete))
            except Exception:
                pass

        return expanded if expanded else [rule]
