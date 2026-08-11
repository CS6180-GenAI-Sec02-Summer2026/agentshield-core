"""End-to-end AgentShield orchestration workflow."""

from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from agents.audit_judge import score_explanation
from agents.red_team_agent import RedTeamAgent, ScenarioSeed
from src.agent_runtime import AgentLLMRuntime
from src.app_settings import AppSettings
from src.baseline_analyzer import BaselineAnalyzer
from src.firewall_agent import FirewallAgent
from src.llm_client import StructuredLLMClient, create_llm_client
from src.llm_settings import LLMSettings
from src.metrics import EvaluationResult, MetricsEngine
from src.policy_compiler_agent import PolicyCompilerAgent
from src.scenario_store import available_datasets, get_scenario, load_scenarios
from src.schemas import WorkflowStateModel
from src.target_agent import TargetAgent
from src.tools import (
    ToolValidationError,
    blocked_tool_result,
    execute_mock_tool,
    list_tool_specs,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RULES_PATH = REPO_ROOT / "data" / "policy_rules.json"


class AgentShieldOrchestrator:
    """
    Connects Target Agent proposal, firewall decisioning, mock tool execution,
    audit logs, and metrics into one backend workflow.
    """

    def __init__(
        self,
        rules_path: str | Path | None = None,
        llm_settings: LLMSettings | None = None,
        llm_client: StructuredLLMClient | None = None,
    ):
        self.rules_path = str(_resolve_rules_path(rules_path))
        self.llm_settings = llm_settings or LLMSettings()
        self.llm_client = llm_client or create_llm_client(self.llm_settings)
        self.runtime = AgentLLMRuntime(self.llm_settings, self.llm_client)
        self.target_agent = TargetAgent(self.runtime)
        self.firewall = FirewallAgent(self.rules_path, self.runtime)
        self.policy_compiler = PolicyCompilerAgent(self.runtime)

    def health(self) -> dict[str, Any]:
        """Return backend health and available scenario/tool metadata."""
        return {
            "status": "ok",
            "service": "agentshield-core",
            "rules_loaded": len(self.firewall.rules),
            "tools": [tool["name"] for tool in list_tool_specs()],
            "datasets": available_datasets(),
            "llm": self.llm_settings.public_status(),
        }

    def run_scenario(
        self,
        scenario: dict[str, Any],
        execute_allowed_tool: bool = False,
        use_llm: bool | None = None,
    ) -> dict[str, Any]:
        """Run one scenario through target proposal, firewall, and optional mock execution."""
        request_id = f"run-{uuid4().hex[:12]}"
        started_at = datetime.now(timezone.utc).isoformat()
        stages = ["received"]
        scenario = dict(scenario)
        scenario.setdefault("id", "ad-hoc")

        target_result = self.target_agent.propose(scenario, use_llm=use_llm)
        proposed_tool_call = target_result.proposed_tool_call
        stages.append("target_agent_proposed_tool_call")

        firewall_input = dict(scenario)
        firewall_input["proposed_tool_call"] = proposed_tool_call
        decision = self.firewall.evaluate(firewall_input, use_llm=use_llm)
        stages.append("firewall_decision_recorded")

        judge_mode = "online" if self._agent_uses_llm("judge", use_llm) else "offline"
        decision.audit.quality_judge = score_explanation(
            {
                "user_request": scenario.get("user_request", ""),
                "external_context": scenario.get("external_context"),
                "proposed_tool_call": proposed_tool_call,
                "expected_decision": decision.decision,
                "policy_violations": decision.audit.policy_violations,
                "explanation": decision.explanation,
            },
            mode=judge_mode,
            runtime=self.runtime,
        )
        stages.append("audit_explanation_judged")

        tool_result = None
        if decision.decision == "ALLOW" and execute_allowed_tool:
            tool_result = execute_mock_tool(proposed_tool_call)
            stages.append("mock_tool_executed")
        else:
            tool_result = blocked_tool_result(proposed_tool_call, decision.decision)
            stages.append("mock_tool_not_executed")

        expected = scenario.get("expected_decision")
        completed_at = datetime.now(timezone.utc).isoformat()
        workflow_state = WorkflowStateModel(
            request_id=request_id,
            status="completed",
            stages=stages,
            started_at=started_at,
            completed_at=completed_at,
        )
        return {
            "scenario_id": scenario["id"],
            "request_id": request_id,
            "source_dataset": scenario.get("_source_dataset"),
            "user_request": scenario.get("user_request", ""),
            "attack_category": scenario.get("attack_category"),
            "expected_risk_level": scenario.get("risk_level"),
            "external_context_present": bool(scenario.get("external_context")),
            "workflow_state": _model_to_dict(workflow_state),
            "target_agent": target_result.to_dict(),
            "proposed_tool_call": proposed_tool_call,
            "firewall_decision": decision.to_dict(),
            "tool_execution": tool_result.to_dict(),
            "expected_decision": expected,
            "matched_expected": None if expected is None else expected == decision.decision,
            "audit": decision.audit.to_dict(),
        }

    def run_scenario_by_id(
        self,
        scenario_id: str,
        execute_allowed_tool: bool = False,
        use_llm: bool | None = None,
    ) -> dict[str, Any]:
        """Load and run one stored scenario by ID."""
        return self.run_scenario(get_scenario(scenario_id), execute_allowed_tool, use_llm)

    def run_batch(
        self,
        scenarios: list[dict[str, Any]] | None = None,
        dataset_names: list[str] | None = None,
        execute_allowed_tools: bool = False,
        use_llm: bool = False,
    ) -> dict[str, Any]:
        """Run a list of scenarios or the requested stored datasets."""
        if scenarios is None:
            scenarios = load_scenarios(dataset_names)
        if use_llm and len(scenarios) > self.llm_settings.max_online_batch_size:
            raise ValueError(
                f"Online batch contains {len(scenarios)} scenarios; configured maximum is "
                f"{self.llm_settings.max_online_batch_size}."
            )

        results = [
            self.run_scenario(scenario, execute_allowed_tools, use_llm) for scenario in scenarios
        ]
        return {
            "total": len(results),
            "summary": self._summary_for_results(results),
            "metrics": self._metrics_for_results(results),
            "results": results,
        }

    def list_scenarios(self, dataset_names: list[str] | None = None) -> dict[str, Any]:
        """Return stored demo scenarios without evaluating them."""
        scenarios = load_scenarios(dataset_names)
        return {
            "datasets": available_datasets(),
            "total": len(scenarios),
            "scenarios": scenarios,
        }

    def audit_log(self) -> dict[str, Any]:
        """Return the in-memory audit log for this orchestrator instance."""
        return {
            "summary": self.firewall.get_decision_summary(),
            "entries": [decision.audit.to_dict() for decision in self.firewall.decision_log],
        }

    def baseline_comparison(self, dataset_names: list[str] | None = None) -> dict[str, Any]:
        """Run baseline comparison on available stored scenarios."""
        scenarios = load_scenarios(dataset_names)
        analyzer = BaselineAnalyzer(self.rules_path)
        comparison = analyzer.run_comparison(scenarios)
        return comparison.to_dict()

    def metrics(self, dataset_names: list[str] | None = None) -> dict[str, Any] | None:
        """Compute dataset metrics without changing this instance's audit log."""
        evaluator = AgentShieldOrchestrator(
            self.rules_path,
            llm_settings=LLMSettings(mode="offline"),
        )
        return evaluator.run_batch(dataset_names=dataset_names)["metrics"]

    def generate_red_team_scenario(self, seed: dict[str, Any]) -> dict[str, Any]:
        """Generate one model-backed synthetic adversarial scenario."""
        agent = RedTeamAgent(mode="online", runtime=self.runtime)
        example = agent.generate_example(ScenarioSeed(**seed))
        return {"scenario": example, "llm": agent.last_call_metadata}

    def compile_policy_candidate(
        self,
        *,
        policy_id: str,
        name: str,
        policy_text: str,
        priority: int | None = None,
    ) -> dict[str, Any]:
        """Compile, validate, and return a disabled candidate policy rule."""
        rule = self.policy_compiler.compile_policy(
            policy_id=policy_id,
            name=name,
            full_text=policy_text,
            priority=priority,
            use_llm=True,
        )
        if rule is None:
            raise ValueError("Policy compilation did not produce a candidate rule.")
        return {
            "candidate_rule": rule.to_dict(),
            "activation_required": True,
            "mode": self.policy_compiler.last_mode,
            "llm": self.policy_compiler.last_call_metadata,
        }

    def close(self) -> None:
        """Release provider transport resources."""
        close = getattr(self.llm_client, "close", None)
        if callable(close):
            close()

    def _agent_uses_llm(self, agent_name: str, use_llm: bool | None) -> bool:
        return self.runtime.enabled(agent_name) if use_llm is None else use_llm

    def _summary_for_results(self, results: list[dict[str, Any]]) -> dict[str, Any]:
        decisions: dict[str, int] = {}
        risk_levels: dict[str, int] = {}
        for result in results:
            decision = result["firewall_decision"]["decision"]
            risk_level = result["firewall_decision"]["risk_level"]
            decisions[decision] = decisions.get(decision, 0) + 1
            risk_levels[risk_level] = risk_levels.get(risk_level, 0) + 1

        return {
            "total": len(results),
            "decisions": decisions,
            "risk_levels": risk_levels,
        }

    def _metrics_for_results(self, results: list[dict[str, Any]]) -> dict[str, Any] | None:
        evaluation_results = []
        for result in results:
            expected = result.get("expected_decision")
            if expected is None:
                continue
            decision = result["firewall_decision"]
            proposed = result["proposed_tool_call"]
            evaluation_results.append(
                EvaluationResult(
                    example_id=result["scenario_id"],
                    expected_decision=expected,
                    actual_decision=decision["decision"],
                    tool_name=proposed["tool_name"],
                    attack_category=result.get("attack_category") or "none",
                    risk_level=result.get("expected_risk_level") or decision["risk_level"],
                    tool_call_intact=True,
                    audit_score=3.0 if result["matched_expected"] else 1.0,
                )
            )

        if not evaluation_results:
            return None

        engine = MetricsEngine()
        engine.add_results(evaluation_results)
        return asdict(engine.compute_all())


def run_ad_hoc(user_request: str, external_context: str | None = None) -> dict[str, Any]:
    """Convenience helper for scripts and quick manual checks."""
    orchestrator = AgentShieldOrchestrator()
    return orchestrator.run_scenario(
        {
            "user_request": user_request,
            "external_context": external_context,
        }
    )


__all__ = [
    "AgentShieldOrchestrator",
    "ToolValidationError",
    "run_ad_hoc",
]


def _model_to_dict(model: Any) -> dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump()
    return model.dict()


def _resolve_rules_path(rules_path: str | Path | None) -> Path:
    configured = rules_path or AppSettings().rules_path or DEFAULT_RULES_PATH
    path = Path(configured)
    if path.is_absolute():
        return path
    cwd_path = Path.cwd() / path
    if cwd_path.exists():
        return cwd_path
    return REPO_ROOT / path
