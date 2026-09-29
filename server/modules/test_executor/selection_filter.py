import re
import json
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlparse

from server.modules.utils.redactor import Redactor


_PRIVATE_IDENTIFIER_KEY_RE = re.compile(
    r"(^|[_-])(user|account|tenant|org|organization|customer|member|owner|profile|order|invoice|project|resource|object|item|id|uuid)([_-]|$)|id$|uuid$",
    re.IGNORECASE,
)
_SENSITIVE_IDENTIFIER_KEY_RE = re.compile(
    r"password|passwd|pwd|token|secret|authorization|auth|cookie|session|csrf|credential|api[_-]?key",
    re.IGNORECASE,
)
_PATH_IDENTIFIER_RE = re.compile(
    r"^[0-9]{2,}$|^[0-9a-f]{16,}$|^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_CONTEXT_SELECTION_SIGNALS = (
    "auth_context",
    "traffic_context",
    "private_variable_context",
    "role_context",
    "param_context",
    "payload_context",
    "header_context",
    "response_code_context",
    "method_context",
    "url_context",
    "historical_finding_context",
)
_CONTEXT_SIGNAL_RECOMMENDATIONS = {
    "auth_context": [
        "capture observed auth schemes or configure authenticated test roles",
    ],
    "traffic_context": [
        "ingest request or response samples for target endpoints",
    ],
    "private_variable_context": [
        "capture non-secret object identifiers from path, query, request body, or response body",
    ],
    "role_context": [
        "configure at least one required role credential or test identity",
    ],
    "param_context": [
        "capture request parameters matching the template selection filters",
    ],
    "payload_context": [
        "capture request or response bodies with the required structural fields",
    ],
    "header_context": [
        "capture request or response headers required by selection filters",
    ],
    "response_code_context": [
        "capture recent response codes for target endpoints",
    ],
    "method_context": [
        "import endpoint HTTP methods from discovery or OpenAPI context",
    ],
    "url_context": [
        "import endpoint URLs or query strings from discovery or OpenAPI context",
    ],
    "historical_finding_context": [
        "link prior findings or vulnerability history to target endpoints",
    ],
}
_SECURITY_CATEGORY_MARKERS = (
    ("authorization", ("authorization", "authz", "bola", "bfla", "idor", "access_control", "access-control")),
    ("authentication", ("authentication", "authn", "login", "session")),
    ("injection", ("injection", "sql", "xss", "xxe", "command")),
    ("ssrf", ("ssrf",)),
    ("data_exposure", ("data_exposure", "data-exposure", "sensitive", "secret", "pii")),
    ("business_logic", ("business_logic", "business-logic", "workflow", "sequence")),
    ("llm", ("llm", "prompt", "tool_output", "tool-output")),
    ("schema", ("schema", "openapi", "contract")),
)


@dataclass(frozen=True)
class SelectionDecision:
    should_run: bool
    extracted: dict
    reason: str | None = None


class SelectionFilterEngine:
    """
    Decides whether a given YAML template should run against a given endpoint.
    Mirrors Akto's api_selection_filters DSL — all 10+ filter keys implemented.
    """

    def should_run(self, template: dict, endpoint: dict, roles_context: dict = None) -> tuple[bool, dict]:
        """
        Returns (should_run: bool, extracted_vars: dict).
        extracted_vars holds values like urlVar, userKey extracted by filters.
        """
        decision = self.evaluate(template, endpoint, roles_context=roles_context)
        return decision.should_run, decision.extracted

    def evaluate(self, template: dict, endpoint: dict, roles_context: dict = None) -> SelectionDecision:
        """Return an explainable selection decision for audit-ready skip evidence."""
        filters = template.get("api_selection_filters", {})
        extracted = {}

        auth_filter = self._auth_requirement(template, filters)
        if auth_filter == "CONFLICT":
            return SelectionDecision(False, {}, "auth_requirement_conflict")
        if auth_filter is True and not self._endpoint_has_auth(endpoint):
            return SelectionDecision(False, {}, "requires_authenticated_endpoint")
        if auth_filter is False and self._endpoint_has_auth(endpoint):
            return SelectionDecision(False, {}, "requires_unauthenticated_endpoint")

        # 1. Method filter
        method_rule = filters.get("method")
        if method_rule and not self._check_method(method_rule, endpoint.get("method", "")):
            return SelectionDecision(False, {}, "method_filter_mismatch")

        # 2. Response code filter
        code_rule = filters.get("response_code")
        if code_rule:
            last_code = endpoint.get("last_response_code", 200)
            # Allow extract from code filter
            if isinstance(code_rule, dict) and "extract" in code_rule:
                extracted[code_rule["extract"]] = last_code
                code_rule = {k: v for k, v in code_rule.items() if k != "extract"}
            if not self._check_code(code_rule, last_code):
                return SelectionDecision(False, {}, "response_code_filter_mismatch")

        # 3. URL filter — extract full URL for use in modify_url (90 templates)
        url_rule = filters.get("url")
        if url_rule:
            full_url = endpoint.get("url", "")
            if not full_url:
                proto = endpoint.get("protocol", "http")
                host = endpoint.get("host", "")
                path = endpoint.get("path", "/")
                full_url = f"{proto}://{host}{path}"
            if isinstance(url_rule, dict) and "extract" in url_rule:
                extracted[url_rule["extract"]] = full_url
            elif url_rule:  # plain extract shorthand: url: { extract: varName }
                pass

        # 4. Response payload filter
        payload_rule = filters.get("response_payload")
        if payload_rule:
            last_body = endpoint.get("last_response_body", "")
            if not self._check_payload(payload_rule, last_body):
                return SelectionDecision(False, {}, "response_payload_filter_mismatch")

        # 5. Response headers filter (response_headers plural — selection filter)
        resp_headers_rule = filters.get("response_headers")
        if resp_headers_rule:
            last_headers = endpoint.get("last_response_headers", {})
            if not self._check_header_filter(resp_headers_rule, last_headers):
                return SelectionDecision(False, {}, "response_headers_filter_mismatch")

        # 6. Request payload filter — extract variable names (e.g. userKey, payloadKeys)
        req_payload_rule = filters.get("request_payload")
        if req_payload_rule:
            ok, found = self._check_request_payload(req_payload_rule, endpoint.get("last_request_body", ""))
            if not ok:
                return SelectionDecision(False, {}, "request_payload_filter_mismatch")
            extracted.update(found)

        # 7. param_context — extract param name+value pair for BOLA tests
        param_ctx_rule = filters.get("param_context")
        if param_ctx_rule:
            ok, found = self._check_param_context(param_ctx_rule, endpoint)
            if not ok:
                return SelectionDecision(False, {}, "param_context_missing")
            extracted.update(found)

        # 8. OR logic across multiple filter branches
        or_rules = filters.get("or")
        if or_rules:
            passed_or = False
            for or_rule in or_rules:
                ok, found = self._check_or_rule(or_rule, endpoint)
                if ok:
                    extracted.update(found)
                    passed_or = True
                    break
            if not passed_or:
                return SelectionDecision(False, {}, "or_filter_mismatch")

        # 9. Roles access filter (BFLA)
        include_roles = filters.get("include_roles_access")
        normalized_roles_context = self._normalized_roles_context(roles_context)
        if include_roles:
            role_names = self._role_names_from_rule(include_roles)
            if not role_names or not any(role_name in normalized_roles_context for role_name in role_names):
                return SelectionDecision(False, {}, "required_role_context_missing")

        exclude_roles = filters.get("exclude_roles_access")
        if exclude_roles:
            role_names = self._role_names_from_rule(exclude_roles)
            if any(role_name in normalized_roles_context for role_name in role_names):
                return SelectionDecision(False, {}, "excluded_role_context_present")

        # 10. Private variable context (endpoint has user-specific params)
        pvc_rule = filters.get("private_variable_context")
        if pvc_rule:
            ok, found = self._check_private_variable_context(pvc_rule, endpoint)
            if not ok:
                return SelectionDecision(False, {}, "private_variable_context_missing")
            extracted.update(found)

        # 11. auth.authenticated — skip endpoints that have no auth headers observed
        # 12. endpoint_in_traffic_context — endpoint must have captured sample data
        if filters.get("endpoint_in_traffic_context"):
            has_sample = bool(
                endpoint.get("last_request_body")
                or endpoint.get("last_response_body")
            )
            if not has_sample:
                return SelectionDecision(False, {}, "endpoint_traffic_context_missing")

        historical_rule = filters.get("historical_finding_context")
        historical_reason = None
        if historical_rule:
            historical_ok, historical_reason = self._check_historical_finding_context(
                historical_rule,
                template,
                endpoint,
            )
            if not historical_ok:
                return SelectionDecision(False, {}, "historical_finding_context_missing")

        return SelectionDecision(True, extracted, historical_reason)

    def summarize_context_aware_selection(
        self,
        templates,
        endpoints,
        roles_context: dict | None = None,
    ) -> dict:
        """
        Summarize context-aware selection demand and available evidence.

        The result is intentionally non-secret: it only exposes signal names and
        counts, never captured headers, bodies, tokens, cookies, or payload data.
        """
        template_list = self._as_list(templates)
        endpoint_list = self._as_list(endpoints)
        required_counts = self._empty_context_signal_counts()
        available_counts = self._empty_context_signal_counts()

        for template in template_list:
            for signal in self._template_required_context_signals(template):
                required_counts[signal] += 1

        normalized_roles_context = self._normalized_roles_context(roles_context)
        if normalized_roles_context:
            available_counts["role_context"] = len(normalized_roles_context)

        for endpoint in endpoint_list:
            for signal in self._endpoint_available_context_signals(endpoint):
                available_counts[signal] += 1

        required_signals = self._signals_from_counts(required_counts)
        available_signals = self._signals_from_counts(available_counts)
        satisfied_signals = [
            signal
            for signal in _CONTEXT_SELECTION_SIGNALS
            if required_counts[signal] > 0 and available_counts[signal] > 0
        ]
        missing_signals = [
            signal
            for signal in _CONTEXT_SELECTION_SIGNALS
            if required_counts[signal] > 0 and available_counts[signal] == 0
        ]
        has_required_signals = bool(required_signals)
        has_satisfied_signals = bool(satisfied_signals)
        context_ready = has_required_signals and not missing_signals
        partial_context = has_required_signals and has_satisfied_signals and bool(missing_signals)

        return {
            "context_aware_selection": context_ready,
            "partial_context_aware_selection": partial_context,
            "context_aware_selection_status": (
                "ready"
                if context_ready
                else "partial"
                if partial_context
                else "missing"
                if has_required_signals
                else "not_required"
            ),
            "template_count": len(template_list),
            "endpoint_count": len(endpoint_list),
            "required_signals": required_signals,
            "available_signals": available_signals,
            "satisfied_signals": satisfied_signals,
            "missing_signals": missing_signals,
            "required_signal_count": len(required_signals),
            "available_signal_count": len(available_signals),
            "satisfied_signal_count": len(satisfied_signals),
            "missing_signal_count": len(missing_signals),
            "required_signal_counts": required_counts,
            "available_signal_counts": available_counts,
            "context_signal_gaps": self._context_signal_gaps(
                missing_signals,
                template_list,
                required_counts,
                available_counts,
            ),
            "selection_outcomes": self._selection_outcome_summary(
                template_list,
                endpoint_list,
                roles_context,
            ),
        }

    def _as_list(self, value) -> list:
        if value is None:
            return []
        if isinstance(value, dict):
            return [value]
        return list(value)

    def _empty_context_signal_counts(self) -> dict:
        return {signal: 0 for signal in _CONTEXT_SELECTION_SIGNALS}

    def _signals_from_counts(self, counts: dict) -> list[str]:
        return [signal for signal in _CONTEXT_SELECTION_SIGNALS if counts.get(signal, 0) > 0]

    def _context_signal_gaps(
        self,
        missing_signals: list[str],
        templates: list,
        required_counts: dict,
        available_counts: dict,
    ) -> list[dict[str, object]]:
        gaps = []
        for signal in _CONTEXT_SELECTION_SIGNALS:
            if signal not in missing_signals:
                continue
            affected_template_ids = [
                self._safe_template_id(template, template_index)
                for template_index, template in enumerate(templates)
                if signal in self._template_required_context_signals(template)
            ]
            gaps.append(
                {
                    "signal": signal,
                    "required_template_count": int(required_counts.get(signal) or 0),
                    "available_context_count": int(available_counts.get(signal) or 0),
                    "affected_template_count": len(affected_template_ids),
                    "affected_template_ids": affected_template_ids[:25],
                    "recommended_inputs": list(
                        _CONTEXT_SIGNAL_RECOMMENDATIONS.get(
                            signal,
                            ["provide the required context signal before active selection"],
                        )
                    ),
                }
            )
        return gaps

    def _selection_outcome_summary(
        self,
        templates: list,
        endpoints: list,
        roles_context: dict | None,
    ) -> dict[str, object]:
        selected_pair_count = 0
        skip_reason_counts: dict[str, int] = {}
        selected_templates: set[int] = set()
        selected_endpoints: set[int] = set()
        pair_decisions: list[dict[str, object]] = []
        template_stats = [
            {
                "template_index": template_index,
                "template_id": self._safe_template_id(template, template_index),
                "security_category": self._template_security_category(template),
                "required_signals": self._ordered_signals(
                    self._template_required_context_signals(template)
                ),
                "selected_endpoint_count": 0,
                "skipped_endpoint_count": 0,
                "skip_reason_counts": {},
            }
            for template_index, template in enumerate(templates)
        ]

        for template_index, template in enumerate(templates):
            for endpoint_index, endpoint in enumerate(endpoints):
                decision = self.evaluate(template, endpoint, roles_context=roles_context)
                template_stat = template_stats[template_index]
                pair_decisions.append(
                    {
                        "template_index": template_index,
                        "template_id": self._safe_template_id(template, template_index),
                        "endpoint_index": endpoint_index,
                        "endpoint_id": self._safe_endpoint_id(endpoint, endpoint_index),
                        "security_category": self._template_security_category(template),
                        "selected": bool(decision.should_run),
                        "reason": decision.reason or "selected" if decision.should_run else decision.reason or "selection_filter_mismatch",
                        "extracted_variable_names": sorted(str(key) for key in decision.extracted.keys()),
                    }
                )
                if decision.should_run:
                    selected_pair_count += 1
                    selected_templates.add(template_index)
                    selected_endpoints.add(endpoint_index)
                    template_stat["selected_endpoint_count"] += 1
                    continue

                reason = decision.reason or "selection_filter_mismatch"
                skip_reason_counts[reason] = skip_reason_counts.get(reason, 0) + 1
                template_stat["skipped_endpoint_count"] += 1
                template_skip_counts = template_stat["skip_reason_counts"]
                template_skip_counts[reason] = template_skip_counts.get(reason, 0) + 1

        pair_count = len(templates) * len(endpoints)
        skipped_pair_count = pair_count - selected_pair_count
        starved_templates = [
            stat
            for stat in template_stats
            if stat["selected_endpoint_count"] == 0 and stat["skipped_endpoint_count"] > 0
        ]
        category_coverage = self._security_category_coverage(template_stats)
        category_gaps = [
            item
            for item in category_coverage
            if item["coverage_status"] == "gap"
        ]
        return {
            "template_endpoint_pair_count": pair_count,
            "selected_pair_count": selected_pair_count,
            "skipped_pair_count": skipped_pair_count,
            "selected_template_count": len(selected_templates),
            "selected_endpoint_count": len(selected_endpoints),
            "skip_reason_counts": skip_reason_counts,
            "selection_starved": pair_count > 0 and selected_pair_count == 0,
            "starved_template_count": len(starved_templates),
            "starved_templates": starved_templates[:25],
            "starved_template_report_truncated": len(starved_templates) > 25,
            "security_category_coverage": category_coverage,
            "security_category_coverage_gap_count": len(category_gaps),
            "security_category_coverage_gaps": category_gaps[:25],
            "security_category_coverage_report_truncated": len(category_gaps) > 25,
            "pair_decisions": pair_decisions[:500],
            "pair_decision_count": len(pair_decisions),
            "pair_decision_report_truncated": len(pair_decisions) > 500,
        }

    def _security_category_coverage(self, template_stats: list[dict]) -> list[dict]:
        coverage: dict[str, dict] = {}
        for stat in template_stats:
            category = str(stat.get("security_category") or "uncategorized")
            bucket = coverage.setdefault(
                category,
                {
                    "security_category": category,
                    "template_count": 0,
                    "selected_template_count": 0,
                    "starved_template_count": 0,
                    "selected_pair_count": 0,
                    "skipped_pair_count": 0,
                    "skip_reason_counts": {},
                },
            )
            selected_count = int(stat.get("selected_endpoint_count") or 0)
            skipped_count = int(stat.get("skipped_endpoint_count") or 0)
            bucket["template_count"] += 1
            bucket["selected_pair_count"] += selected_count
            bucket["skipped_pair_count"] += skipped_count
            if selected_count > 0:
                bucket["selected_template_count"] += 1
            if selected_count == 0:
                bucket["starved_template_count"] += 1
            for reason, count in (stat.get("skip_reason_counts") or {}).items():
                bucket["skip_reason_counts"][reason] = (
                    bucket["skip_reason_counts"].get(reason, 0) + int(count or 0)
                )

        results = []
        for category in sorted(coverage):
            item = coverage[category]
            results.append(
                {
                    **item,
                    "coverage_status": (
                        "covered" if item["selected_template_count"] > 0 else "gap"
                    ),
                }
            )
        return results

    def _safe_template_id(self, template: dict, template_index: int) -> str:
        if isinstance(template, dict):
            raw_id = template.get("id") or template.get("template_id") or template.get("name")
        else:
            raw_id = None
        return Redactor.redact_text(str(raw_id or f"template_{template_index}"))[:120]

    def _safe_endpoint_id(self, endpoint: dict, endpoint_index: int) -> str:
        if isinstance(endpoint, dict):
            raw_id = endpoint.get("id") or endpoint.get("endpoint_id")
        else:
            raw_id = None
        return Redactor.redact_text(str(raw_id or f"endpoint_{endpoint_index}"))[:120]

    def _template_security_category(self, template: dict) -> str:
        if not isinstance(template, dict):
            return "uncategorized"

        candidates = []
        for key in ("security_category", "category", "type", "test_category"):
            value = template.get(key)
            if value:
                candidates.append(value)

        info = template.get("info")
        if isinstance(info, dict):
            for key in ("security_category", "category", "type"):
                value = info.get(key)
                if value:
                    candidates.append(value)
            tags = info.get("tags")
            if isinstance(tags, str):
                candidates.extend(item.strip() for item in tags.split(",") if item.strip())
            elif isinstance(tags, list):
                candidates.extend(tags)

        for candidate in candidates:
            category = self._normalize_security_category(candidate)
            if category != "uncategorized":
                return category
        return "uncategorized"

    def _normalize_security_category(self, value) -> str:
        text = str(value or "").strip()
        if not text:
            return "uncategorized"
        normalized = text.lower().replace(" ", "_")
        for category, markers in _SECURITY_CATEGORY_MARKERS:
            if any(marker in normalized for marker in markers):
                return category

        redacted = Redactor.redact_text(text).lower()
        cleaned = re.sub(r"[^a-z0-9]+", "_", redacted).strip("_")
        return cleaned[:80] if cleaned and cleaned != "****" else "uncategorized"

    def _ordered_signals(self, signals: set[str]) -> list[str]:
        return [signal for signal in _CONTEXT_SELECTION_SIGNALS if signal in signals]

    def _template_required_context_signals(self, template: dict) -> set[str]:
        if not isinstance(template, dict):
            return set()

        filters = template.get("api_selection_filters", {})
        if not isinstance(filters, dict):
            filters = {}

        signals = set()
        if self._auth_requirement(template, filters) is not None:
            signals.add("auth_context")
        if filters.get("endpoint_in_traffic_context"):
            signals.add("traffic_context")
        if filters.get("private_variable_context"):
            signals.add("private_variable_context")
        if filters.get("include_roles_access") or filters.get("exclude_roles_access"):
            signals.add("role_context")
        if filters.get("param_context"):
            signals.add("param_context")
        if filters.get("request_payload") or filters.get("response_payload"):
            signals.add("payload_context")
        if filters.get("response_headers") or filters.get("request_headers"):
            signals.add("header_context")
        if filters.get("response_code"):
            signals.add("response_code_context")
        if filters.get("method"):
            signals.add("method_context")
        if filters.get("url") or filters.get("query_param"):
            signals.add("url_context")
        if filters.get("historical_finding_context"):
            signals.add("historical_finding_context")

        for or_rule in filters.get("or") or []:
            if not isinstance(or_rule, dict):
                continue
            if or_rule.get("request_payload") or or_rule.get("response_payload"):
                signals.add("payload_context")
            if or_rule.get("query_param") or or_rule.get("url"):
                signals.add("url_context")

        return signals

    def _endpoint_available_context_signals(self, endpoint: dict) -> set[str]:
        if not isinstance(endpoint, dict):
            return set()

        signals = set()
        if self._endpoint_has_auth(endpoint):
            signals.add("auth_context")
        if self._endpoint_has_traffic_context(endpoint):
            signals.add("traffic_context")
        if self._endpoint_has_private_variable_context(endpoint):
            signals.add("private_variable_context")
        if self._endpoint_has_param_context(endpoint):
            signals.add("param_context")
        if self._endpoint_has_payload_context(endpoint):
            signals.add("payload_context")
        if self._endpoint_has_header_context(endpoint):
            signals.add("header_context")
        if self._endpoint_has_response_code_context(endpoint):
            signals.add("response_code_context")
        if endpoint.get("method"):
            signals.add("method_context")
        if self._endpoint_has_url_context(endpoint):
            signals.add("url_context")
        if self._endpoint_has_historical_finding_context(endpoint):
            signals.add("historical_finding_context")

        return signals

    # ── Method ────────────────────────────────────────────────────────────────

    def _auth_requirement(self, template: dict, filters: dict) -> bool | str | None:
        requirements = []
        for candidate in (template.get("auth"), filters.get("auth")):
            if isinstance(candidate, dict) and isinstance(candidate.get("authenticated"), bool):
                requirements.append(candidate["authenticated"])
        if True in requirements and False in requirements:
            return "CONFLICT"
        if True in requirements:
            return True
        if False in requirements:
            return False
        return None

    def _endpoint_has_auth(self, endpoint: dict) -> bool:
        auth_types = endpoint.get("auth_types_found") or []
        if isinstance(auth_types, str):
            auth_types = [item.strip() for item in auth_types.split(",") if item.strip()]
        return bool(endpoint.get("authenticated") or endpoint.get("has_auth") or auth_types)

    def _endpoint_has_traffic_context(self, endpoint: dict) -> bool:
        return bool(endpoint.get("last_request_body") or endpoint.get("last_response_body"))

    def _endpoint_has_private_variable_context(self, endpoint: dict) -> bool:
        return self._safe_int(endpoint.get("private_variable_count", 0)) > 0 or bool(
            self._private_variable_candidates(endpoint)
        )

    def _endpoint_has_param_context(self, endpoint: dict) -> bool:
        return bool(self._json_items(endpoint.get("last_request_body")))

    def _endpoint_has_payload_context(self, endpoint: dict) -> bool:
        return bool(endpoint.get("last_request_body") or endpoint.get("last_response_body"))

    def _endpoint_has_header_context(self, endpoint: dict) -> bool:
        header_keys = (
            "last_request_headers",
            "last_response_headers",
            "request_headers",
            "response_headers",
            "headers",
        )
        return any(isinstance(endpoint.get(key), dict) and bool(endpoint.get(key)) for key in header_keys)

    def _endpoint_has_response_code_context(self, endpoint: dict) -> bool:
        return any(
            key in endpoint and endpoint.get(key) is not None
            for key in ("last_response_code", "response_code", "status_code", "status")
        )

    def _endpoint_has_url_context(self, endpoint: dict) -> bool:
        return bool(endpoint.get("url") or endpoint.get("path") or endpoint.get("host"))

    def _endpoint_has_historical_finding_context(self, endpoint: dict) -> bool:
        return bool(self._historical_finding_categories(endpoint))

    def _check_historical_finding_context(
        self,
        rule,
        template: dict,
        endpoint: dict,
    ) -> tuple[bool, str | None]:
        categories = self._historical_finding_categories(endpoint)
        if not categories:
            return False, None

        expected_categories = self._historical_rule_categories(rule, template)
        if expected_categories and not (categories & expected_categories):
            return False, None

        selected_category = sorted(categories & expected_categories)[0] if expected_categories else sorted(categories)[0]
        return True, f"Selected because this endpoint has prior {selected_category} findings."

    def _historical_rule_categories(self, rule, template: dict) -> set[str]:
        values = []
        if isinstance(rule, dict):
            for key in ("category", "security_category", "type", "finding_type"):
                value = rule.get(key)
                if value:
                    values.append(value)
            tags = rule.get("tags")
            if isinstance(tags, str):
                values.extend(item.strip() for item in tags.split(",") if item.strip())
            elif isinstance(tags, list):
                values.extend(tags)
        elif isinstance(rule, str):
            values.append(rule)

        template_category = self._template_security_category(template)
        if template_category != "uncategorized":
            values.append(template_category)
        return {
            self._normalize_security_category(value)
            for value in values
            if self._normalize_security_category(value) != "uncategorized"
        }

    def _historical_finding_categories(self, endpoint: dict) -> set[str]:
        categories = set()
        for finding in self._historical_finding_items(endpoint):
            for key in ("category", "security_category", "type", "finding_type", "vulnerability_type", "cwe"):
                value = finding.get(key)
                if not value:
                    continue
                category = self._normalize_security_category(value)
                if category != "uncategorized":
                    categories.add(category)
        return categories

    def _historical_finding_items(self, endpoint: dict) -> list[dict]:
        items = []
        for key in (
            "finding_history",
            "historical_findings",
            "prior_findings",
            "previous_findings",
            "findings",
            "vulnerability_history",
        ):
            value = endpoint.get(key)
            if isinstance(value, dict):
                items.append(value)
            elif isinstance(value, list):
                items.extend(item for item in value if isinstance(item, dict))
        return items

    def _normalized_roles_context(self, roles_context: dict | None) -> dict:
        return {str(key).upper(): value for key, value in (roles_context or {}).items()}

    def _role_names_from_rule(self, rule) -> list[str]:
        if isinstance(rule, dict):
            values = [rule.get("param")]
        elif isinstance(rule, list):
            values = rule
        else:
            values = [rule]
        return [str(value).upper() for value in values if str(value or "").strip()]

    def _check_method(self, rule: dict, method: str) -> bool:
        method = method.upper()
        if "eq" in rule and method != rule["eq"].upper():
            return False
        if "neq" in rule and method == rule["neq"].upper():
            return False
        if "contains" in rule:
            methods = [m.upper() for m in (rule["contains"] if isinstance(rule["contains"], list) else [rule["contains"]])]
            if method not in methods:
                return False
        if "not_contains" in rule:
            methods = [m.upper() for m in (rule["not_contains"] if isinstance(rule["not_contains"], list) else [rule["not_contains"]])]
            if method in methods:
                return False
        return True

    # ── Code ──────────────────────────────────────────────────────────────────

    def _check_code(self, rule: dict, code: int) -> bool:
        if "gte" in rule and code < rule["gte"]:
            return False
        if "lt" in rule and code >= rule["lt"]:
            return False
        if "eq" in rule and code != rule["eq"]:
            return False
        if "neq" in rule and code == rule["neq"]:
            return False
        return True

    # ── Numeric ───────────────────────────────────────────────────────────────

    def _check_numeric(self, rule: dict, value) -> bool:
        if "gt" in rule and value <= rule["gt"]:
            return False
        if "gte" in rule and value < rule["gte"]:
            return False
        if "lt" in rule and value >= rule["lt"]:
            return False
        if "lte" in rule and value > rule["lte"]:
            return False
        return True

    # ── Payload ───────────────────────────────────────────────────────────────

    def _check_private_variable_context(self, rule: dict, endpoint: dict) -> tuple[bool, dict]:
        if rule is True:
            rule = {}
        if not isinstance(rule, dict):
            return True, {}

        candidates = self._private_variable_candidates(endpoint)
        observed_count = self._safe_int(endpoint.get("private_variable_count", 0))
        effective_count = max(observed_count, len(candidates))
        numeric_rule = {key: rule[key] for key in ("gt", "gte", "lt", "lte") if key in rule}
        if numeric_rule and not self._check_numeric(numeric_rule, effective_count):
            return False, {}
        if not numeric_rule and effective_count <= 0:
            return False, {}

        extracted = {}
        extract_as = rule.get("extract")
        extract_multiple_as = rule.get("extractMultiple")
        if (extract_as or extract_multiple_as) and not candidates:
            return False, {}
        if extract_as:
            extracted[extract_as] = candidates[0]
        if extract_multiple_as:
            extracted[extract_multiple_as] = candidates
        return True, extracted

    def _private_variable_candidates(self, endpoint: dict) -> list[dict]:
        candidates = []
        seen = set()

        def add_candidate(key: str, value, source: str) -> None:
            key_text = str(key or "")
            if not key_text or self._is_sensitive_identifier_key(key_text):
                return
            if value in (None, "", [], {}):
                return
            dedupe_key = (key_text, str(value), source)
            if dedupe_key in seen:
                return
            seen.add(dedupe_key)
            candidates.append({"key": key_text, "value": value, "source": source})

        for key, value in self._json_items(endpoint.get("last_request_body")):
            if self._is_private_identifier_key(key):
                add_candidate(key, value, "request_body")
        for key, value in self._query_items(endpoint):
            if self._is_private_identifier_key(key):
                add_candidate(key, value, "query")
        for key, value in self._json_items(endpoint.get("last_response_body")):
            if self._is_private_identifier_key(key):
                add_candidate(key, value, "response_body")
        for segment in self._path_identifier_segments(endpoint):
            add_candidate("path_id", segment, "path")

        return candidates

    def _json_items(self, value) -> list[tuple[str, object]]:
        if isinstance(value, str):
            try:
                value = json.loads(value) if value else {}
            except Exception:
                return []
        items = []

        def walk(node) -> None:
            if isinstance(node, dict):
                for key, child in node.items():
                    if isinstance(child, (dict, list)):
                        walk(child)
                    else:
                        items.append((str(key), child))
            elif isinstance(node, list):
                for child in node:
                    walk(child)

        walk(value)
        return items

    def _query_items(self, endpoint: dict) -> list[tuple[str, str]]:
        query_string = str(endpoint.get("last_query_string") or "").lstrip("?")
        if not query_string and endpoint.get("url"):
            query_string = urlparse(str(endpoint["url"])).query
        return [(key, value) for key, value in parse_qsl(query_string, keep_blank_values=False)]

    def _path_identifier_segments(self, endpoint: dict) -> list[str]:
        path = str(endpoint.get("path") or "")
        if not path and endpoint.get("url"):
            path = urlparse(str(endpoint["url"])).path
        return [segment for segment in path.split("/") if segment and _PATH_IDENTIFIER_RE.match(segment)]

    def _is_private_identifier_key(self, key: str) -> bool:
        return bool(_PRIVATE_IDENTIFIER_KEY_RE.search(key)) and not self._is_sensitive_identifier_key(key)

    def _is_sensitive_identifier_key(self, key: str) -> bool:
        return bool(_SENSITIVE_IDENTIFIER_KEY_RE.search(key))

    def _safe_int(self, value) -> int:
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return 0

    def _check_payload(self, rule: dict | list, body: str | None) -> bool:
        # Endpoints discovered from an OpenAPI/Postman import have never been
        # observed live, so last_response_body is NULL rather than absent —
        # dict.get(key, "") hands back None and every filter below would fail.
        body = body or ""
        if isinstance(rule, list):
            return all(self._check_payload(item, body) for item in rule)
        if not isinstance(rule, dict):
            return True

        if rule.get("for_one"):
            return self._check_payload_for_one(rule["for_one"], body)

        body_lower = body.lower()
        length_rule = rule.get("length")
        if length_rule and not self._check_numeric(length_rule, len(body)):
            return False

        for item in rule.get("not_contains", []):
            if item.lower() in body_lower:
                return False

        for item in rule.get("contains", []):
            if item.lower() not in body_lower:
                return False

        items_all = rule.get("contains_all", [])
        if isinstance(items_all, str):
            items_all = [items_all]
        for item in items_all:
            if item.lower() not in body_lower:
                return False

        items_either = rule.get("contains_either", [])
        if isinstance(items_either, str):
            items_either = [items_either]
        if items_either and not any(item.lower() in body_lower for item in items_either):
            return False

        return True

    def _check_payload_for_one(self, for_one: dict, body: str) -> bool:
        if not isinstance(for_one, dict):
            return True
        key_rule = for_one.get("key", {}) if isinstance(for_one.get("key", {}), dict) else {}
        value_rule = for_one.get("value", {}) if isinstance(for_one.get("value", {}), dict) else {}
        regex_pattern = key_rule.get("regex", ".*")
        not_contains = key_rule.get("not_contains")

        try:
            body_json = json.loads(body) if body else {}
        except Exception:
            return False
        if not isinstance(body_json, dict):
            return False

        for key, value in body_json.items():
            key_text = str(key)
            if not re.search(str(regex_pattern), key_text, re.IGNORECASE):
                continue
            if not_contains:
                blocked = not_contains if isinstance(not_contains, list) else [not_contains]
                if any(str(item) in key_text for item in blocked):
                    continue
            if self._check_payload_value(value_rule, value):
                return True
        return False

    def _check_payload_value(self, rule: dict, value) -> bool:
        if not rule:
            return True
        if "datatype" in rule:
            datatype = rule["datatype"]
            if datatype == "number" and not isinstance(value, (int, float)):
                return False
            if datatype == "string" and not isinstance(value, str):
                return False
            if datatype == "boolean" and not isinstance(value, bool):
                return False
        if "eq" in rule and value != rule["eq"]:
            return False
        if "neq" in rule and value == rule["neq"]:
            return False
        return True

    # ── Response headers (selection filter) ───────────────────────────────────

    def _check_header_filter(self, rule: dict, headers: dict) -> bool:
        lower_headers = {k.lower(): v for k, v in headers.items()}
        for_one = rule.get("for_one", {})
        if not for_one:
            return True
        key_rule = for_one.get("key", {})
        value_rule = for_one.get("value", {})
        for k, v in lower_headers.items():
            k_match = True
            if "eq" in key_rule and k != key_rule["eq"].lower():
                k_match = False
            if "regex" in key_rule and not re.search(key_rule["regex"], k, re.IGNORECASE):
                k_match = False
            if not k_match:
                continue
            if not value_rule:
                return True
            if "eq" in value_rule and v.lower() == value_rule["eq"].lower():
                return True
            if "regex" in value_rule and re.search(value_rule["regex"], v, re.IGNORECASE):
                return True
            if "contains" in value_rule and value_rule["contains"].lower() in v.lower():
                return True
        return False

    # ── Request payload ───────────────────────────────────────────────────────

    def _check_request_payload(self, rule: dict, body: str) -> tuple[bool, dict]:
        """Check for_one/for_all in request body; supports extract and extractMultiple."""
        extracted = {}
        for_one = rule.get("for_one")
        if not for_one:
            return True, extracted

        key_rule = for_one.get("key", {})
        value_rule = for_one.get("value", {})
        extract_as = key_rule.get("extract")
        extract_multiple_as = key_rule.get("extractMultiple")
        regex_pattern = key_rule.get("regex", ".*")
        not_contains = key_rule.get("not_contains")

        try:
            body_json = json.loads(body) if body else {}
        except Exception:
            return False, {}

        matched_keys = []
        for k in body_json.keys():
            k_str = str(k)
            if not re.search(regex_pattern, k_str, re.IGNORECASE):
                continue
            if not_contains:
                nc_list = not_contains if isinstance(not_contains, list) else [not_contains]
                if any(nc in k_str for nc in nc_list):
                    continue
            # Value filter
            if value_rule:
                v = body_json[k]
                if "datatype" in value_rule:
                    dt = value_rule["datatype"]
                    if dt == "number" and not isinstance(v, (int, float)):
                        continue
                    if dt == "string" and not isinstance(v, str):
                        continue
            matched_keys.append(k_str)

        if not matched_keys:
            return False, {}

        if extract_as:
            extracted[extract_as] = matched_keys[0]
        if extract_multiple_as:
            extracted[extract_multiple_as] = matched_keys

        return True, extracted

    # ── param_context ─────────────────────────────────────────────────────────

    def _check_param_context(self, rule: dict, endpoint: dict) -> tuple[bool, dict]:
        """
        Extract param name+value from endpoint's last request body
        where param name matches the given regex. Used by BOLA tests.
        Returns extracted {extract_var: {key: paramName, value: paramValue}}.
        """
        extracted = {}
        param_regex = rule.get("param", "")
        extract_as = rule.get("extract", "user_context")

        body = endpoint.get("last_request_body", "")
        try:
            body_json = json.loads(body) if body else {}
        except Exception:
            return False, {}

        for k, v in body_json.items():
            if re.search(param_regex, str(k), re.IGNORECASE):
                extracted[extract_as] = {"key": k, "value": v}
                return True, extracted

        return False, {}

    # ── OR rule ───────────────────────────────────────────────────────────────

    def _check_or_rule(self, or_rule: dict, endpoint: dict) -> tuple[bool, dict]:
        """Handle a single OR branch."""
        extracted = {}

        if "request_payload" in or_rule:
            ok, found = self._check_request_payload(
                or_rule["request_payload"], endpoint.get("last_request_body", "")
            )
            if ok:
                return True, found

        if "query_param" in or_rule:
            ok, found = self._check_query_param(
                or_rule["query_param"], endpoint.get("last_query_string", "")
            )
            if ok:
                return True, found

        return False, {}

    # ── Query param ───────────────────────────────────────────────────────────

    def _check_query_param(self, rule: dict, query_string: str) -> tuple[bool, dict]:
        extracted = {}
        for_one = rule.get("for_one")
        if not for_one:
            return True, extracted

        key_rule = for_one.get("key", {})
        value_rule = for_one.get("value", {})
        regex_pattern = key_rule.get("regex", ".*")
        extract_as = key_rule.get("extract")
        extract_multiple_as = key_rule.get("extractMultiple")

        params = {}
        for part in query_string.split("&"):
            if "=" in part:
                k, v = part.split("=", 1)
                params[k] = v

        matched = []
        for k, v in params.items():
            if re.search(regex_pattern, k, re.IGNORECASE):
                # Value filter
                if value_rule:
                    v_str = str(v)
                    if "contains_either" in value_rule:
                        clist = value_rule["contains_either"]
                        if isinstance(clist, str):
                            clist = [clist]
                        if not any(c.lower() in v_str.lower() for c in clist):
                            continue
                matched.append(k)

        if not matched:
            return False, {}

        if extract_as:
            extracted[extract_as] = matched[0]
        if extract_multiple_as:
            extracted[extract_multiple_as] = matched

        return True, extracted
