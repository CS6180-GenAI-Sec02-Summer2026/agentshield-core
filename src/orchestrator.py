"""End-to-end AgentShield orchestration workflow."""

from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from src.baseline_analyzer import BaselineAnalyzer
from src.firewall_agent import FirewallAgent
from src.metrics import EvaluationResult, MetricsEngine
from src.scenario_store import available_datasets, get_scenario, load_scenarios
from src.schemas import WorkflowStateModel
from src.target_agent import TargetAgent
from src.tools import ToolValidationError, blocked_tool_result, execute_mock_tool, list_tool_specs


class AgentShieldOrchestrator:
    """
    Connects Target Agent proposal, firewall decisioning, mock tool execution,
    audit logs, and metrics into one backend workflow.
    """

    def __init__(self, rules_path: str = "data/policy_rules.json"):
        self.rules_path = rules_path
        self.target_agent = TargetAgent()
        self.firewall = FirewallAgent(rules_path)

    def health(self) -> dict[str, Any]:
        """Return backend health and available scenario/tool metadata."""
        return {
            "status": "ok",
            "service": "agentshield-core",
            "rules_loaded": len(self.firewall.rules),
            "tools": [tool["name"] for tool in list_tool_specs()],
            "datasets": available_datasets(),
        }

    def run_scenario(
        self,
        scenario: dict[str, Any],
        execute_allowed_tool: bool = False,
    ) -> dict[str, Any]:
        """Run one scenario through target proposal, firewall, and optional mock execution."""
        request_id = f"run-{uuid4().hex[:12]}"
        started_at = datetime.now(timezone.utc).isoformat()
        stages = ["received"]
        scenario = dict(scenario)
        scenario.setdefault("id", "ad-hoc")

        target_result = self.target_agent.propose(scenario)
        proposed_tool_call = target_result.proposed_tool_call
        stages.append("target_agent_proposed_tool_call")

        firewall_input = dict(scenario)
        firewall_input["proposed_tool_call"] = proposed_tool_call
        decision = self.firewall.evaluate(firewall_input)
        stages.append("firewall_decision_recorded")

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
    ) -> dict[str, Any]:
        """Load and run one stored scenario by ID."""
        return self.run_scenario(get_scenario(scenario_id), execute_allowed_tool)

    def run_batch(
        self,
        scenarios: list[dict[str, Any]] | None = None,
        dataset_names: list[str] | None = None,
        execute_allowed_tools: bool = False,
    ) -> dict[str, Any]:
        """Run a list of scenarios or the requested stored datasets."""
        if scenarios is None:
            scenarios = load_scenarios(dataset_names)

        results = [
            self.run_scenario(scenario, execute_allowed_tools)
            for scenario in scenarios
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
            evaluation_results.append(EvaluationResult(
                example_id=result["scenario_id"],
                expected_decision=expected,
                actual_decision=decision["decision"],
                tool_name=proposed["tool_name"],
                attack_category=result.get("attack_category") or "none",
                risk_level=result.get("expected_risk_level") or decision["risk_level"],
                tool_call_intact=True,
                audit_score=3.0 if result["matched_expected"] else 1.0,
            ))

        if not evaluation_results:
            return None

        engine = MetricsEngine()
        engine.add_results(evaluation_results)
        return asdict(engine.compute_all())


def run_ad_hoc(user_request: str, external_context: str | None = None) -> dict[str, Any]:
    """Convenience helper for scripts and quick manual checks."""
    orchestrator = AgentShieldOrchestrator()
    return orchestrator.run_scenario({
        "user_request": user_request,
        "external_context": external_context,
    })


__all__ = [
    "AgentShieldOrchestrator",
    "ToolValidationError",
    "run_ad_hoc",
]


def _model_to_dict(model: Any) -> dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump()
    return model.dict()
