"""Focused tests for Mrinal-owned orchestration/API integration layer."""

from src.orchestrator import AgentShieldOrchestrator, run_ad_hoc
from src.scenario_store import available_datasets, load_scenarios
from src.tools import ToolValidationError, normalize_tool_call


def test_tool_validation():
    normalize_tool_call({
        "tool_name": "send_email",
        "arguments": {"to": "alice@company.com", "subject": "Hi", "body": "Hello"},
    })

    try:
        normalize_tool_call({"tool_name": "send_email", "arguments": {"to": "alice@company.com"}})
    except ToolValidationError:
        return
    raise AssertionError("Invalid email tool call should fail validation")


def test_health_and_scenarios():
    orchestrator = AgentShieldOrchestrator()
    health = orchestrator.health()
    assert health["status"] == "ok"
    assert health["rules_loaded"] >= 1
    assert available_datasets()
    assert load_scenarios()


def test_run_one_stored_scenario():
    orchestrator = AgentShieldOrchestrator()
    scenario = load_scenarios(["sample"])[0]
    result = orchestrator.run_scenario(scenario)
    assert result["scenario_id"] == scenario["id"]
    assert result["proposed_tool_call"]["tool_name"]
    assert result["firewall_decision"]["decision"] in {"ALLOW", "BLOCK", "ASK_APPROVAL"}
    assert result["matched_expected"] is not None


def test_run_batch_metrics():
    orchestrator = AgentShieldOrchestrator()
    result = orchestrator.run_batch(dataset_names=["sample"])
    assert result["total"] >= 1
    assert result["metrics"]["total_examples"] == result["total"]
    assert "policy_compliance_accuracy" in result["metrics"]


def test_ad_hoc_inference():
    result = run_ad_hoc("Email Bob the project update at bob@company.com")
    assert result["proposed_tool_call"]["tool_name"] == "send_email"
    assert result["firewall_decision"]["decision"] in {"ALLOW", "BLOCK", "ASK_APPROVAL"}


def main():
    tests = [
        test_tool_validation,
        test_health_and_scenarios,
        test_run_one_stored_scenario,
        test_run_batch_metrics,
        test_ad_hoc_inference,
    ]
    passed = 0
    for test in tests:
        test()
        passed += 1
        print(f"PASS {test.__name__}")
    print(f"{passed}/{len(tests)} orchestration tests passed.")


if __name__ == "__main__":
    main()
