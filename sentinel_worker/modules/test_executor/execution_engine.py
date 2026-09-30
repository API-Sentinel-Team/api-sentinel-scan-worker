import asyncio
import email.utils
import json

import httpx
import jsonpath_ng
from sqlalchemy import select

from .baseline_capture import BaselineCapturer
from .context_manager import ContextManager
from .graph.graph import Graph, Node, NodeType
from .graph.graph_executor_factory import GraphExecutorFactory
from .request_mutator import RequestMutator
from sentinel_core.modules.test_executor.response_validator import ResponseValidator
from sentinel_core.modules.test_executor.state_change_guard import StateChangeBlocked, StateChangeGuard, state_change_policy_for_request
from sentinel_core.modules.test_executor.target_guard import TargetGuard, TargetGuardError
from .wordlist_resolver import WordListResolver
from sentinel_core.config import settings
from sentinel_core.models.core import TestAccount
from sentinel_core.modules.identity.auth_rotator import AuthRotator
from sentinel_core.modules.identity.eligibility import eligible_test_accounts
from sentinel_core.modules.identity.roles_context import RolesContextBuilder
from sentinel_worker.modules.llm.active_judge import build_active_llm_judge_validation, is_llm_security_template
from sentinel_worker.modules.business_logic.stateful_executor import execute_stateful_flow
from sentinel_core.modules.pentest.auth_preflight import _credential_value_has_material
from sentinel_core.modules.pentest.auth_scope import AuthScopeError, auth_scope_policy_for_error, validate_auth_profile_scope
from sentinel_core.modules.pentest.worker_isolation import worker_isolation_enforcement_metadata
from sentinel_core.modules.utils.redactor import Redactor


_BACKOFF_RESPONSE_STATUSES = {429, 500, 502, 503, 504}


class AuthResolutionError(RuntimeError):
    """Raised when a configured auth profile cannot safely produce runtime credentials."""


class ExecutionEngine:
    """
    Orchestrates authenticated template execution with graph-based request flows.
    """

    def __init__(
        self,
        concurrency: int = 10,
        test_id: str | None = None,
        timeout_seconds: float | None = None,
        db=None,
        auth_profile: object | None = None,
        follow_redirects: bool = False,
        allow_state_change: bool = False,
        allow_destructive_methods: bool = False,
        attacker_role: str = "ATTACKER",
        max_active_requests_per_test: int | None = None,
        worker_isolation_context: dict | None = None,
    ):
        self.mutator = RequestMutator()
        self.validator = ResponseValidator()
        self.baseliner = BaselineCapturer()
        self.auth_rotator = AuthRotator()
        self.roles_context_builder = RolesContextBuilder()
        self.limit = asyncio.Semaphore(max(1, concurrency))
        self.test_id = test_id or "test-run"
        self.timeout_seconds = float(timeout_seconds or settings.TEST_REQUEST_TIMEOUT)
        self.db = db
        self.auth_profile = auth_profile
        self.follow_redirects = bool(follow_redirects)
        self.allow_state_change = bool(allow_state_change)
        self.allow_destructive_methods = bool(allow_destructive_methods)
        self.attacker_role = attacker_role or "ATTACKER"
        raw_budget = (
            settings.PENTEST_MAX_ACTIVE_REQUESTS_PER_TEST
            if max_active_requests_per_test is None
            else max_active_requests_per_test
        )
        self.max_active_requests_per_test = max(0, int(raw_budget))
        self._runtime_auth_cache: dict[str, dict] = {}
        self.target_guard = TargetGuard.from_settings()
        self.worker_isolation_context = worker_isolation_context if isinstance(worker_isolation_context, dict) else None
        self.worker_isolation_enforcement = worker_isolation_enforcement_metadata(
            self.worker_isolation_context,
            engine="templates",
        )

    async def execute_test(self, endpoint: dict, template: dict, selection_context: dict | None = None) -> dict:
        """
        Runs a specific test template against a target endpoint using graph-based orchestration.
        """
        context_manager = ContextManager()
        execute_cfg = template.get("execute", {})
        requests = execute_cfg.get("requests", [])

        if not requests:
            return {"error": "No requests defined in template"}
        max_active_requests = self._effective_max_active_requests(execute_cfg)

        initial_context = await self._build_initial_context(endpoint)
        if selection_context:
            initial_context.update(selection_context)
        context_manager.store.update(initial_context)

        wordlists_cfg = template.get("wordLists", {})
        if wordlists_cfg:
            resolver = WordListResolver()
            resolved_wordlists = await resolver.resolve(wordlists_cfg)
            for var_name, values in resolved_wordlists.items():
                context_manager.store[var_name] = values[0] if values else ""

        base_url = endpoint.get("url") or f"{endpoint.get('protocol', 'http')}://{endpoint.get('host', '')}{endpoint.get('path', '/')}"
        try:
            self.target_guard.validate_url(base_url, base_url=base_url)
        except TargetGuardError as guard_err:
            safe_guard_error = Redactor.redact_text(str(guard_err))
            target_guard_policy = self._target_guard_policy_for_url(
                url=base_url,
                base_url=base_url,
                reason=safe_guard_error,
            )
            blocked_error = f"target_guard_blocked: {safe_guard_error}"
            return {
                "template_id": template["id"],
                "severity": template.get("info", {}).get("severity"),
                "is_vulnerable": False,
                "results": [
                    {
                        "vulnerable": False,
                        "error": blocked_error,
                        "target_guard_policy": target_guard_policy,
                    }
                ],
                "context_variables": list(context_manager.store.keys()),
                "sent_request": None,
                "received_response": None,
                "skip_reason": "target_guard",
                "evidence": "target_guard=blocked",
                "error": blocked_error,
                "target_guard_policy": target_guard_policy,
            }
        try:
            validate_auth_profile_scope(self.auth_profile, base_url)
        except AuthScopeError as scope_err:
            safe_error = Redactor.redact_text(str(scope_err))
            auth_profile_scope_policy = auth_scope_policy_for_error(
                scope_err,
                auth_profile=self.auth_profile,
                target_url=base_url,
                base_url=base_url,
            )
            return {
                "template_id": template["id"],
                "severity": template.get("info", {}).get("severity"),
                "is_vulnerable": False,
                "results": [
                    {
                        "vulnerable": False,
                        "error": safe_error,
                        "auth_profile_scope_policy": auth_profile_scope_policy,
                    }
                ],
                "context_variables": list(context_manager.store.keys()),
                "sent_request": None,
                "received_response": None,
                "skip_reason": "auth_profile_scope_guard",
                "evidence": "auth_profile_scope_guard=blocked",
                "error": safe_error,
                "auth_profile_scope_policy": auth_profile_scope_policy,
            }

        if max_active_requests <= 0:
            return {
                "template_id": template["id"],
                "severity": template.get("info", {}).get("severity"),
                "is_vulnerable": False,
                "results": [
                    {
                        "vulnerable": False,
                        "error": self._request_budget_error(max_active_requests),
                    }
                ],
                "context_variables": list(context_manager.store.keys()),
                "sent_request": None,
                "received_response": None,
                "skip_reason": "request_budget",
                "evidence": "request_budget=exceeded",
                "error": self._request_budget_error(max_active_requests),
                "request_budget": {
                    "max_active_requests": max_active_requests,
                    "active_requests_sent": 0,
                    "exceeded": True,
                },
            }

        try:
            runtime_auth = await self._resolve_runtime_auth(endpoint, base_url=base_url)
        except AuthResolutionError as auth_err:
            safe_error = Redactor.redact_text(str(auth_err))
            return {
                "template_id": template["id"],
                "severity": template.get("info", {}).get("severity"),
                "is_vulnerable": False,
                "results": [{"vulnerable": False, "error": f"auth_resolution_failed: {safe_error}"}],
                "context_variables": list(context_manager.store.keys()),
                "sent_request": None,
                "received_response": None,
                "skip_reason": "auth_resolution_failed",
                "error": f"auth_resolution_failed: {safe_error}",
            }

        state_guard = StateChangeGuard(
            allow_state_change=self._effective_allow_state_change(execute_cfg),
            allow_destructive_methods=self._effective_allow_destructive_methods(execute_cfg),
        )
        baseline = await self.baseliner.capture(
            endpoint,
            headers=runtime_auth["headers"],
            cookies=runtime_auth["cookies"],
            timeout_seconds=self.timeout_seconds,
            follow_redirects=self._guarded_follow_redirects(),
            auth=runtime_auth["basic_auth"],
            allow_state_change=state_guard.allow_state_change,
            allow_destructive_methods=state_guard.allow_destructive_methods,
            target_guard=self.target_guard,
        )
        context_manager.store["baseline"] = baseline
        graph = self._build_graph(requests)

        execute_type = execute_cfg.get("type", "single")
        executor = GraphExecutorFactory.get_executor(execute_type, context_manager)
        final_results = []
        last_request_sent = None
        last_response_data = None
        active_requests_sent = 0
        request_budget_exceeded = False

        async def run_node_step(node: Node, resolved_data: dict, current_context: dict):
            nonlocal last_request_sent, last_response_data, active_requests_sent, request_budget_exceeded
            async with self.limit:
                req_rules = resolved_data.get("req", [{}])
                if not req_rules:
                    req_rules = [{}]

                auth_cfg = template.get("auth", {})
                is_validation_node = node.data.get("validation_node", False) or (node.id == list(graph.nodes.keys())[-1])
                node_last_response = None

                async with httpx.AsyncClient(
                    timeout=self.timeout_seconds,
                    verify=True,
                    cookies=runtime_auth["cookies"],
                ) as client:
                    for rule_idx, current_rule in enumerate(req_rules):
                        current_rule = context_manager.substitute_recursive(current_rule)
                        auth_context = dict(current_context.get("auth_context", {}))
                        auth_context.setdefault("auth_header", runtime_auth["auth_header"])
                        auth_context.setdefault("attacker_token", current_context.get("attacker_token", ""))
                        mutated_req = self.mutator.mutate(endpoint, current_rule, auth_context=auth_context)

                        if active_requests_sent >= max_active_requests:
                            request_budget_exceeded = True
                            last_request_sent = Redactor.redact_http_message(
                                {
                                    "method": mutated_req.get("method"),
                                    "url": mutated_req.get("url"),
                                    "headers": mutated_req.get("headers") or {},
                                    "body": mutated_req.get("body"),
                                    "follow_redirects": self._guarded_follow_redirects(mutated_req),
                                }
                            )
                            final_results.append(
                                {
                                    "node_id": node.id,
                                    "rule_idx": rule_idx,
                                    "vulnerable": False,
                                    "error": self._request_budget_error(max_active_requests),
                                    "budget": {
                                        "active_requests_sent": active_requests_sent,
                                        "max_active_requests": max_active_requests,
                                    },
                                }
                            )
                            break

                        try:
                            state_guard.validate_request(mutated_req)
                        except StateChangeBlocked as guard_err:
                            safe_guard_error = Redactor.redact_text(str(guard_err))
                            state_change_policy = self._state_change_policy_for_request(
                                mutated_req,
                                state_guard,
                                reason=safe_guard_error,
                            )
                            last_request_sent = Redactor.redact_http_message(
                                {
                                    "method": mutated_req.get("method"),
                                    "url": mutated_req.get("url"),
                                    "headers": mutated_req.get("headers") or {},
                                    "body": mutated_req.get("body"),
                                    "follow_redirects": self._guarded_follow_redirects(mutated_req),
                                }
                            )
                            final_results.append(
                                {
                                    "node_id": node.id,
                                    "rule_idx": rule_idx,
                                    "vulnerable": False,
                                    "error": safe_guard_error,
                                    "state_change_policy": state_change_policy,
                                }
                            )
                            continue
                        state_change_policy = self._state_change_policy_for_request(
                            mutated_req,
                            state_guard,
                            blocked=False,
                        )

                        try:
                            self.target_guard.validate_url(mutated_req["url"], base_url=base_url)
                        except TargetGuardError as guard_err:
                            safe_guard_error = Redactor.redact_text(str(guard_err))
                            target_guard_policy = self._target_guard_policy_for_url(
                                url=mutated_req["url"],
                                base_url=base_url,
                                reason=safe_guard_error,
                            )
                            last_request_sent = Redactor.redact_http_message(
                                {
                                    "method": mutated_req["method"],
                                    "url": mutated_req["url"],
                                    "headers": mutated_req.get("headers") or {},
                                    "body": mutated_req.get("body"),
                                    "follow_redirects": self._guarded_follow_redirects(mutated_req),
                                }
                            )
                            final_results.append(
                                {
                                    "node_id": node.id,
                                    "rule_idx": rule_idx,
                                    "vulnerable": False,
                                    "error": f"target_guard_blocked: {safe_guard_error}",
                                    "target_guard_policy": target_guard_policy,
                                }
                            )
                            continue
                        target_guard_policy = self._target_guard_policy_for_url(
                            url=mutated_req["url"],
                            base_url=base_url,
                            reason="target_guard_allowed",
                            blocked=False,
                        )
                        try:
                            validate_auth_profile_scope(self.auth_profile, mutated_req["url"])
                        except AuthScopeError as scope_err:
                            safe_error = Redactor.redact_text(str(scope_err))
                            auth_profile_scope_policy = auth_scope_policy_for_error(
                                scope_err,
                                auth_profile=self.auth_profile,
                                target_url=mutated_req["url"],
                                base_url=base_url,
                            )
                            last_request_sent = Redactor.redact_http_message(
                                {
                                    "method": mutated_req["method"],
                                    "url": mutated_req["url"],
                                    "headers": mutated_req.get("headers") or {},
                                    "body": mutated_req.get("body"),
                                    "follow_redirects": self._guarded_follow_redirects(mutated_req),
                                }
                            )
                            final_results.append(
                                {
                                    "node_id": node.id,
                                    "rule_idx": rule_idx,
                                    "vulnerable": False,
                                    "error": safe_error,
                                    "auth_profile_scope_policy": auth_profile_scope_policy,
                                }
                            )
                            continue

                        mutated_req = self._apply_runtime_auth(
                            mutated_req,
                            runtime_auth,
                            auth_cfg,
                            current_rule,
                        )

                        headers = mutated_req.get("headers") or {}
                        headers.setdefault("X-APISecurity-Test-ID", self.test_id)
                        mutated_req["headers"] = headers
                        follow_redirects = self._guarded_follow_redirects(mutated_req)
                        last_request_sent = Redactor.redact_http_message(
                            {
                                "method": mutated_req["method"],
                                "url": mutated_req["url"],
                                "headers": headers,
                                "body": mutated_req.get("body"),
                                "follow_redirects": follow_redirects,
                            }
                        )

                        try:
                            active_requests_sent += 1
                            resp = await client.request(
                                method=mutated_req["method"],
                                url=mutated_req["url"],
                                headers=headers,
                                content=mutated_req.get("body"),
                                auth=runtime_auth["basic_auth"],
                                follow_redirects=follow_redirects,
                            )
                        except Exception as req_err:
                            final_results.append(
                                {
                                    "node_id": node.id,
                                    "rule_idx": rule_idx,
                                    "vulnerable": False,
                                    "error": str(req_err),
                                }
                            )
                            continue

                        response_data = {
                            "status_code": resp.status_code,
                            "headers": dict(resp.headers),
                            "body": resp.text,
                        }
                        backoff_seconds = await self._apply_response_backoff(resp)
                        node_last_response = response_data
                        last_response_data = Redactor.redact_http_message(response_data)

                        vulnerable = (
                            self.validator.validate(
                                response_data,
                                template.get("validate", {}),
                                original_response=baseline,
                            )
                            if is_validation_node
                            else (200 <= resp.status_code < 300)
                        )
                        llm_judge_validation = None
                        if is_llm_security_template(template):
                            llm_judge_validation = build_active_llm_judge_validation(
                                path=mutated_req.get("url") or endpoint.get("path"),
                                method=mutated_req.get("method"),
                                request_body=mutated_req.get("body"),
                                response_body=response_data.get("body"),
                            )
                            if int(llm_judge_validation.get("signal_count") or 0) > 0:
                                vulnerable = True

                        result_entry = {
                            "node_id": node.id,
                            "rule_idx": rule_idx,
                            "vulnerable": vulnerable,
                            "target_guard_policy": target_guard_policy,
                            "state_change_policy": state_change_policy,
                            "safety_policies": {
                                "target_guard_policy": target_guard_policy,
                                "state_change_policy": state_change_policy,
                            },
                            "response": {
                                "status_code": resp.status_code,
                                "headers": Redactor.redact_headers(response_data["headers"]),
                            },
                        }
                        if llm_judge_validation:
                            result_entry["llm_judge_validation"] = llm_judge_validation
                        if backoff_seconds > 0:
                            result_entry["response"]["backoff_seconds"] = backoff_seconds
                        final_results.append(result_entry)

                return node_last_response

        try:
            stateful_flow = execute_cfg.get("stateful_flow")
            if isinstance(stateful_flow, list) and stateful_flow:
                flow_steps = []
                for index, flow_step in enumerate(stateful_flow):
                    if not isinstance(flow_step, dict):
                        continue
                    request_data = flow_step.get("request")
                    if not isinstance(request_data, dict):
                        request_data = {key: value for key, value in flow_step.items() if key not in {"name", "phase"}}
                    flow_steps.append(
                        {
                            "name": flow_step.get("name") or f"flow_step_{index}",
                            "phase": flow_step.get("phase"),
                            "payload": request_data,
                        }
                    )

                async def execute_flow_step(flow_step):
                    node = Node(
                        id=flow_step.name,
                        type=NodeType.API,
                        data=flow_step.payload,
                    )
                    resolved = context_manager.substitute_recursive(flow_step.payload)
                    return await run_node_step(node, resolved, context_manager.store)

                lifecycle = await execute_stateful_flow(
                    flow_steps,
                    execute_flow_step,
                    max_steps=max(1, min(8, max_active_requests)),
                )
                response_lifecycle = lifecycle.as_dict()
            else:
                await executor.execute(graph, {}, run_node_step)
                response_lifecycle = None
        except Exception as exc:
            final_results.append({"error": str(exc)})
            response_lifecycle = {"status": "failed", "error": Redactor.redact_text(str(exc))}

        is_vulnerable = any(result.get("vulnerable", False) for result in final_results)

        response = {
            "template_id": template["id"],
            "severity": template.get("info", {}).get("severity"),
            "is_vulnerable": is_vulnerable,
            "results": final_results,
            "context_variables": list(context_manager.store.keys()),
            "sent_request": last_request_sent,
            "received_response": last_response_data,
            "request_budget": {
                "max_active_requests": max_active_requests,
                "active_requests_sent": active_requests_sent,
                "exceeded": request_budget_exceeded,
            },
        }
        if response_lifecycle is not None:
            response["stateful_flow"] = response_lifecycle
        business_logic_scenario = self._active_business_logic_metadata(template)
        if business_logic_scenario:
            response["security_category"] = "business_logic"
            response["active_business_logic"] = business_logic_scenario
            if is_vulnerable:
                scenario_type = str(business_logic_scenario.get("scenario_type") or "business_logic_scenario")
                abuse_family = str(business_logic_scenario.get("abuse_family") or "business_logic")
                response["matched_rule"] = {
                    "template_id": template["id"],
                    "rule_id": scenario_type,
                    "name": "Active business logic scenario accepted by target",
                    "matcher": "business_logic_response_code",
                    "condition": "scenario_response_code_matched",
                }
                response["similarity"] = {
                    "scenario_type": scenario_type,
                    "abuse_family": abuse_family,
                    "confidence_score": 0.75,
                }
                response["remediation"] = (
                    "Enforce server-side business workflow, rate, amount, and sequence controls for "
                    "the affected API flow, then rerun the bounded business-logic retest."
                )
        llm_judge_validation = self._combined_llm_judge_validation(final_results)
        if llm_judge_validation:
            response["security_category"] = "llm"
            response["llm_judge_validation"] = llm_judge_validation
            response["matched_rule"] = {
                "template_id": template["id"],
                "matcher": "deterministic_active_llm_signal_judge",
                "condition": "llm_signal_count_gt_0",
            }
            response["similarity"] = {
                "signal_count": int(llm_judge_validation.get("signal_count") or 0),
                "confidence_score": llm_judge_validation.get("max_confidence"),
            }
            response["remediation"] = (
                "Add LLM input/output guardrails, isolate system prompts from user-controlled context, "
                "filter secrets from model-visible data, and require tool/output allowlists."
            )
        if self._all_results_blocked_by_state_guard(final_results):
            response["skip_reason"] = "state_change_guard"
            response["evidence"] = "state_change_guard=blocked"
            response["error"] = final_results[0].get("error")
            response["state_change_policy"] = final_results[0].get("state_change_policy")
        elif self._all_results_blocked_by_request_budget(final_results):
            response["skip_reason"] = "request_budget"
            response["evidence"] = "request_budget=exceeded"
            response["error"] = final_results[0].get("error")
        elif request_budget_exceeded:
            response["evidence"] = "request_budget=exceeded"
        elif self._all_results_blocked_by_auth_scope(final_results):
            response["skip_reason"] = "auth_profile_scope_guard"
            response["evidence"] = "auth_profile_scope_guard=blocked"
            response["error"] = final_results[0].get("error")
            response["auth_profile_scope_policy"] = final_results[0].get("auth_profile_scope_policy")
        elif self._all_results_blocked_by_target_guard(final_results):
            response["skip_reason"] = "target_guard"
            response["evidence"] = "target_guard=blocked"
            response["error"] = final_results[0].get("error")
            response["target_guard_policy"] = final_results[0].get("target_guard_policy")
        return response

    @staticmethod
    def _active_business_logic_metadata(template: dict) -> dict:
        scenario = template.get("active_business_logic")
        if not isinstance(scenario, dict):
            return {}
        redacted = Redactor.redact_json(scenario)
        return redacted if isinstance(redacted, dict) else {}

    def _build_graph(self, requests: list) -> Graph:
        graph = Graph()
        prev_node_id = None
        for idx, req_cfg in enumerate(requests):
            node_id = f"step_{idx}"
            node = Node(id=node_id, type=NodeType.API, data=req_cfg)
            graph.add_node(node)
            if prev_node_id:
                graph.add_edge(prev_node_id, node_id)
            prev_node_id = node_id
        return graph

    def _effective_allow_state_change(self, execute_cfg: dict) -> bool:
        template_allows = bool(execute_cfg.get("allow_state_change", self.allow_state_change))
        return self.allow_state_change and template_allows

    def _effective_allow_destructive_methods(self, execute_cfg: dict) -> bool:
        template_allows = bool(
            execute_cfg.get("allow_destructive_methods", execute_cfg.get("allow_destructive", False))
        )
        return self.allow_state_change and self.allow_destructive_methods and template_allows

    def _effective_max_active_requests(self, execute_cfg: dict) -> int:
        raw_value = execute_cfg.get("max_active_requests_per_test", self.max_active_requests_per_test)
        try:
            template_budget = int(raw_value)
        except (TypeError, ValueError):
            template_budget = self.max_active_requests_per_test
        if self.max_active_requests_per_test <= 0:
            return 0
        return max(0, min(self.max_active_requests_per_test, template_budget))

    def _state_change_policy_for_request(
        self,
        request: dict,
        guard: StateChangeGuard,
        *,
        reason: str | None = None,
        blocked: bool = True,
    ) -> dict:
        return state_change_policy_for_request(
            request,
            guard,
            reason=reason,
            blocked=blocked,
        )

    @staticmethod
    def _effective_state_change_method(request: dict) -> str:
        return StateChangeGuard.effective_state_change_method(request)

    def _target_guard_policy_for_url(
        self,
        *,
        url: str,
        base_url: str | None,
        reason: str,
        blocked: bool = True,
    ) -> dict:
        return {
            "policy": "target_guard",
            "blocked": bool(blocked),
            "url": Redactor.redact_url(url),
            "base_url": Redactor.redact_url(base_url) if base_url else None,
            "reason": Redactor.redact_text(reason),
            "enforce": bool(getattr(self.target_guard, "enforce", True)),
            "allow_private_targets": bool(getattr(self.target_guard, "allow_private_targets", False)),
            "resolve_hosts": bool(getattr(self.target_guard, "resolve_hosts", False)),
            "allowlist_present": bool(getattr(self.target_guard, "allowlist", [])),
        }

    @staticmethod
    def _all_results_blocked_by_state_guard(results: list[dict]) -> bool:
        if not results:
            return False
        blocked_prefixes = ("state_change_blocked:", "destructive_method_blocked:")
        return all(str(result.get("error", "")).startswith(blocked_prefixes) for result in results)

    @staticmethod
    def _all_results_blocked_by_auth_scope(results: list[dict]) -> bool:
        if not results:
            return False
        return all(str(result.get("error", "")).startswith("auth_profile_scope_blocked:") for result in results)

    @staticmethod
    def _all_results_blocked_by_target_guard(results: list[dict]) -> bool:
        if not results:
            return False
        return all(str(result.get("error", "")).startswith("target_guard_blocked:") for result in results)

    def _request_budget_error(self, max_active_requests: int | None = None) -> str:
        budget = self.max_active_requests_per_test if max_active_requests is None else max_active_requests
        return f"request_budget_exceeded: maximum active requests per test is {budget}"

    @staticmethod
    def _combined_llm_judge_validation(results: list[dict]) -> dict | None:
        validations = [
            result.get("llm_judge_validation")
            for result in results
            if isinstance(result.get("llm_judge_validation"), dict)
        ]
        if not validations:
            return None
        if len(validations) == 1:
            return validations[0]
        combined = dict(validations[-1])
        combined["signal_types"] = sorted(
            {
                signal_type
                for validation in validations
                for signal_type in (validation.get("signal_types") or [])
            }
        )
        combined["signal_count"] = sum(int(validation.get("signal_count") or 0) for validation in validations)
        combined["signals"] = [
            signal
            for validation in validations
            for signal in (validation.get("signals") or [])
            if isinstance(signal, dict)
        ][:25]
        combined["deterministic_evidence"] = all(
            validation.get("deterministic_evidence") is True for validation in validations
        )
        return combined

    @staticmethod
    def _all_results_blocked_by_request_budget(results: list[dict]) -> bool:
        if not results:
            return False
        return all(str(result.get("error", "")).startswith("request_budget_exceeded:") for result in results)

    async def _apply_response_backoff(self, response: httpx.Response) -> float:
        delay = self._response_backoff_seconds(response)
        if delay > 0:
            await asyncio.sleep(delay)
        return delay

    def _response_backoff_seconds(self, response: httpx.Response) -> float:
        if not bool(getattr(settings, "PENTEST_RESPONSE_BACKOFF_ENABLED", True)):
            return 0.0
        if int(getattr(response, "status_code", 0) or 0) not in _BACKOFF_RESPONSE_STATUSES:
            return 0.0
        default_delay = max(0.0, float(getattr(settings, "PENTEST_DEFAULT_RESPONSE_BACKOFF_SECONDS", 1.0)))
        max_delay = max(0.0, float(getattr(settings, "PENTEST_MAX_RESPONSE_BACKOFF_SECONDS", 5.0)))
        header_value = ""
        headers = getattr(response, "headers", {}) or {}
        if hasattr(headers, "get"):
            header_value = headers.get("Retry-After") or headers.get("retry-after") or ""
        parsed_delay = self._parse_retry_after_seconds(str(header_value).strip()) if header_value else default_delay
        return min(max(0.0, parsed_delay), max_delay)

    @staticmethod
    def _parse_retry_after_seconds(value: str) -> float:
        if not value:
            return 0.0
        try:
            return float(value)
        except ValueError:
            try:
                parsed_date = email.utils.parsedate_to_datetime(value)
            except (TypeError, ValueError, IndexError, AttributeError):
                return 0.0
            now = email.utils.localtime()
            if parsed_date.tzinfo is None:
                parsed_date = parsed_date.replace(tzinfo=now.tzinfo)
            return max(0.0, (parsed_date - now).total_seconds())

    async def _build_initial_context(self, endpoint: dict) -> dict:
        roles_context = {}
        if self.db is not None:
            account_id = endpoint.get("account_id")
            if account_id is None:
                raise ValueError("endpoint account_id is required")
            result = await self.db.execute(
                select(TestAccount).where(TestAccount.account_id == account_id)
            )
            # COV-1: only active, unexpired, credential-bearing identities build roles.
            roles_context = self.roles_context_builder.build(eligible_test_accounts(result.scalars().all()))
        flat_roles = self.roles_context_builder.flatten(roles_context)
        attacker_token = self.roles_context_builder.get_attacker_token(roles_context, self.attacker_role)
        auth_header = self._profile_header_name()
        context = {
            **flat_roles,
            "roles_access_context": roles_context,
            "attacker_token": attacker_token,
            "auth_context": {
                "attacker_token": attacker_token,
                "auth_header": auth_header,
            },
            "auth_context.attacker_token": attacker_token,
            "auth_context.auth_header": auth_header,
        }
        return context

    async def _resolve_runtime_auth(self, endpoint: dict, *, base_url: str | None = None) -> dict:
        auth_profile = self.auth_profile
        if auth_profile is None:
            return {
                "headers": {},
                "cookies": {},
                "basic_auth": None,
                "auth_header": "Authorization",
            }

        cache_key = f"{getattr(auth_profile, 'id', 'inline')}:{endpoint.get('host')}:{endpoint.get('path')}"
        if cache_key in self._runtime_auth_cache:
            return self._runtime_auth_cache[cache_key]

        mode = (getattr(auth_profile, "auth_mode", "header") or "header").lower()
        headers = self._runtime_header_map(getattr(auth_profile, "static_headers", {}) or {})
        cookies = {}
        basic_auth = None
        auth_header = self._profile_header_name()

        if mode == "basic":
            if not self._present(getattr(auth_profile, "username", None)) or not self._present(
                getattr(auth_profile, "password", None)
            ):
                raise AuthResolutionError("basic auth profile is missing username or password")
            basic_auth = (
                str(getattr(auth_profile, "username", "")).strip(),
                str(getattr(auth_profile, "password", "")).strip(),
            )
        elif mode == "cookie":
            cookies.update(self._runtime_cookie_map(getattr(auth_profile, "cookies", None)))
            if self._present(getattr(auth_profile, "cookie_name", None)) and self._present(
                getattr(auth_profile, "cookie_value", None)
            ):
                cookies[str(auth_profile.cookie_name).strip()] = str(auth_profile.cookie_value).strip()
            if not cookies:
                raise AuthResolutionError("cookie auth profile has no cookies")
        elif mode in {"oauth", "bearer"} and _credential_value_has_material(
            getattr(auth_profile, "token", None) or getattr(auth_profile, "header_value", None)
        ):
            # "bearer" shares oauth's scheme-prefixing: RBAC.require_auth only
            # accepts an Authorization header starting with "bearer ", so a raw
            # token here would make every scan silently unauthenticated.
            token_value = getattr(auth_profile, "token", None) or getattr(auth_profile, "header_value", None)
            token_text = str(token_value).strip()
            headers[auth_header] = (
                token_text if token_text.lower().startswith("bearer ") else f"Bearer {token_text}"
            )
        elif mode in {"dynamic_bearer", "oauth"}:
            token_value = await self._fetch_dynamic_token(auth_profile, base_url=base_url)
            if _credential_value_has_material(token_value):
                headers[auth_header] = str(token_value).strip()
            else:
                raise AuthResolutionError(f"{mode} auth profile did not return a token")
        else:
            token_value = getattr(auth_profile, "token", None) or getattr(auth_profile, "header_value", None)
            if _credential_value_has_material(token_value):
                headers[auth_header] = str(token_value).strip()
            if not headers:
                raise AuthResolutionError(f"{mode} auth profile has no runtime headers")

        resolved = {
            "headers": headers,
            "cookies": cookies,
            "basic_auth": basic_auth,
            "auth_header": auth_header,
        }
        self._runtime_auth_cache[cache_key] = resolved
        return resolved

    async def _fetch_dynamic_token(self, auth_profile: object, *, base_url: str | None = None) -> str:
        login_url = getattr(auth_profile, "login_url", None)
        token_selector = getattr(auth_profile, "token_json_path", None)
        if not login_url or not token_selector:
            raise AuthResolutionError("dynamic bearer auth profile is missing login_url or token selector")

        try:
            self.target_guard.validate_url(login_url, base_url=base_url)
        except TargetGuardError as guard_err:
            raise AuthResolutionError(
                f"dynamic auth login target blocked: {Redactor.redact_text(str(guard_err))}"
            ) from guard_err
        try:
            validate_auth_profile_scope(auth_profile, login_url)
        except AuthScopeError as scope_err:
            raise AuthResolutionError(
                f"dynamic auth login scope blocked: {Redactor.redact_text(str(scope_err))}"
            ) from scope_err

        payload = dict(getattr(auth_profile, "login_payload", {}) or {})
        if getattr(auth_profile, "username", None) and "username" not in payload:
            payload["username"] = auth_profile.username
        if getattr(auth_profile, "password", None) and "password" not in payload:
            payload["password"] = auth_profile.password

        async with httpx.AsyncClient(timeout=self.timeout_seconds, verify=True) as client:
            response = await client.request(
                method=(getattr(auth_profile, "login_method", "POST") or "POST").upper(),
                url=login_url,
                json=payload,
                headers=dict(getattr(auth_profile, "login_headers", {}) or {}),
                follow_redirects=self._guarded_follow_redirects(),
            )
        if response.status_code >= 400:
            raise AuthResolutionError(f"dynamic bearer login failed with status {response.status_code}")
        return self._extract_token(response, token_selector)

    def _extract_token(self, response: httpx.Response, selector: str) -> str:
        if selector.startswith("$"):
            try:
                body_json = response.json()
                expression = jsonpath_ng.parse(selector)
                matches = expression.find(body_json)
                if matches:
                    return str(matches[0].value)
            except Exception:
                return ""
            return ""
        if selector.startswith("/"):
            try:
                body = response.json()
            except Exception:
                return ""
            current = body
            for part in [segment for segment in selector.split("/") if segment]:
                if isinstance(current, dict):
                    current = current.get(part)
                else:
                    return ""
            return str(current or "")
        return response.headers.get(selector, "")

    @staticmethod
    def _present(value: object) -> bool:
        return value is not None and str(value).strip() != ""

    def _runtime_header_map(self, headers: object) -> dict:
        if not isinstance(headers, dict):
            return {}
        return {
            str(key).strip(): str(value).strip()
            for key, value in headers.items()
            if self._present(key) and _credential_value_has_material(value)
        }

    def _runtime_cookie_map(self, cookies: object) -> dict:
        if isinstance(cookies, dict):
            return self._runtime_header_map(cookies)
        if not isinstance(cookies, list):
            return {}
        resolved = {}
        for item in cookies:
            if not isinstance(item, dict):
                continue
            key = item.get("key")
            value = item.get("value")
            if self._present(key) and self._present(value):
                resolved[str(key).strip()] = str(value).strip()
        return resolved

    def _apply_runtime_auth(
        self,
        request: dict,
        runtime_auth: dict,
        auth_cfg: dict,
        current_rule: dict | None = None,
    ) -> dict:
        mutated = dict(request)
        headers = dict(mutated.get("headers") or {})
        if self._rule_controls_auth(current_rule):
            mutated["headers"] = headers
            return mutated
        headers = self._strip_auth_headers(headers)
        for key, value in (runtime_auth.get("headers") or {}).items():
            headers[key] = value
        if auth_cfg.get("type") == "override" and self.db is not None:
            # Template requests can still fully override auth via RequestMutator.
            headers = {
                key: value
                for key, value in headers.items()
            }
        mutated["headers"] = headers
        return mutated

    def _rule_controls_auth(self, current_rule: dict | None) -> bool:
        if not isinstance(current_rule, dict):
            return False
        for action, params in current_rule.items():
            if action in {"remove_auth_header", "replace_auth_header"} and params:
                return True
            if action in {"add_header", "modify_header"} and isinstance(params, dict):
                if any(self._is_auth_header_name(key) for key in params):
                    return True
            if action == "delete_header" and self._delete_header_targets_auth(params):
                return True
        return False

    def _delete_header_targets_auth(self, params: object) -> bool:
        if isinstance(params, str):
            return self._is_auth_header_name(params)
        if isinstance(params, dict):
            return any(self._is_auth_header_name(key) for key in params)
        return False

    def _strip_auth_headers(self, headers: dict) -> dict:
        return {key: value for key, value in headers.items() if not self._is_auth_header_name(key)}

    def _is_auth_header_name(self, key: object) -> bool:
        return str(key).lower() in self.mutator.AUTH_HEADERS

    def _profile_header_name(self) -> str:
        if self.auth_profile is None:
            return "Authorization"
        return getattr(self.auth_profile, "header_name", None) or "Authorization"

    def _guarded_follow_redirects(self, request: dict | None = None) -> bool:
        """Disable automatic redirects so target guard cannot be bypassed by Location hops."""
        return False
