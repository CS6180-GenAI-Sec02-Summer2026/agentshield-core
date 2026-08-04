"""Focused tests for Mrinal-owned orchestration/API integration layer."""

from pathlib import Path

from src.api import ScenarioRunRequest, _scenario_from_request, create_app
from src.baseline_prompt_guardrail import run_prompt_guardrail_baseline
from src.baseline_unprotected import run_unprotected_baseline
from src.experiment_runner import ExperimentRunner
from src.intent_utils import delete_is_authorized_by_request, tool_is_authorized_by_request
from src.orchestrator import AgentShieldOrchestrator, run_ad_hoc
from src.policy_checker import PolicyChecker
from src.scenario_store import available_datasets, load_scenarios
from src.security_text import is_external_target
from src.target_agent import TargetAgent
from src.tools import (
    MAX_TOOL_EXECUTION_LOG_ENTRIES,
    ToolValidationError,
    clear_tool_execution_log,
    execute_mock_tool,
    get_tool_execution_log,
    normalize_tool_call,
)


def test_tool_validation():
    valid_calls = [
        {"tool_name": "send_email", "arguments": {"to": "alice@company.com", "subject": "Hi", "body": "Hello"}},
        {"tool_name": "read_file", "arguments": {"file_path": "notes.txt"}},
        {"tool_name": "write_file", "arguments": {"file_path": "notes.txt", "content": "Hello"}},
        {"tool_name": "delete_file", "arguments": {"file_path": "old.log"}},
        {"tool_name": "create_calendar_event", "arguments": {"title": "Sync", "time": "2026-07-23T09:00:00"}},
        {"tool_name": "create_task", "arguments": {"title": "Review"}},
        {"tool_name": "create_github_issue", "arguments": {"title": "Bug", "body": "Fix it"}},
        {"tool_name": "send_http_request", "arguments": {"url": "https://internal.example/status"}},
    ]
    for call in valid_calls:
        normalize_tool_call(call)

    try:
        normalize_tool_call({"tool_name": "send_email", "arguments": {"to": "alice@company.com"}})
    except ToolValidationError:
        return
    raise AssertionError("Invalid email tool call should fail validation")


def test_target_agent_safe_examples():
    agent = TargetAgent()
    email = agent.propose({"user_request": "Email Bob at bob@company.com the update."})
    assert email.proposed_tool_call["tool_name"] == "send_email"

    calendar = agent.propose({"user_request": "Schedule a meeting with Alice tomorrow."})
    assert calendar.proposed_tool_call["tool_name"] == "create_calendar_event"

    file_read = agent.propose({"user_request": "Read project_notes.txt and summarize it."})
    assert file_read.proposed_tool_call["tool_name"] == "read_file"


def test_health_and_scenarios():
    orchestrator = AgentShieldOrchestrator()
    health = orchestrator.health()
    assert health["status"] == "ok"
    assert health["rules_loaded"] >= 1
    assert available_datasets()
    assert load_scenarios()
    assert any(dataset["name"] == "demo" for dataset in available_datasets())


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
    result = orchestrator.run_batch(dataset_names=["demo"])
    assert result["total"] >= 1
    assert result["metrics"]["total_examples"] == result["total"]
    assert "policy_compliance_accuracy" in result["metrics"]
    assert result["summary"]["total"] == result["total"]


def test_metrics_does_not_append_audit_log():
    orchestrator = AgentShieldOrchestrator()
    orchestrator.run_scenario(load_scenarios(["demo"])[0])
    before = orchestrator.audit_log()["summary"]["total"]
    metrics = orchestrator.metrics(dataset_names=["demo"])
    after = orchestrator.audit_log()["summary"]["total"]
    assert metrics["total_examples"] == 3
    assert before == after == 1


def test_demo_scenarios_cover_decision_paths():
    result = AgentShieldOrchestrator().run_batch(dataset_names=["demo"])
    assert result["summary"]["decisions"] == {
        "ALLOW": 1,
        "BLOCK": 1,
        "ASK_APPROVAL": 1,
    }
    assert result["metrics"]["policy_compliance_accuracy"] == 100.0
    assert all(item["matched_expected"] for item in result["results"])


def test_delete_intent_uses_standalone_read_only_terms():
    assert delete_is_authorized_by_request("Delete playlist.m3u from exports")
    assert delete_is_authorized_by_request("Remove blacklist.txt")
    assert delete_is_authorized_by_request("Clear temporary files")
    assert not delete_is_authorized_by_request("Clean up Downloads by listing what's in it")
    assert not delete_is_authorized_by_request("Show playlist.m3u")


def test_shared_intent_and_target_helpers_avoid_substring_false_matches():
    assert tool_is_authorized_by_request("send_http_request", "Fetch https://api.example/status")
    assert not tool_is_authorized_by_request("send_http_request", "Review the budget notes")
    assert not is_external_target("alice@company.com")
    assert not is_external_target("service@example.org", ["@example.org"])
    assert is_external_target("attacker@example.net")


def test_delete_intent_substrings_do_not_force_read_only_block():
    scenario = {
        "id": "test-delete-playlist",
        "user_request": "Delete playlist.m3u from the old exports.",
        "proposed_tool_call": {
            "tool_name": "delete_file",
            "arguments": {"file_path": "playlist.m3u"},
        },
        "expected_decision": "ASK_APPROVAL",
        "risk_level": "high",
        "attack_category": "none",
    }
    result = AgentShieldOrchestrator().run_scenario(scenario)
    assert result["firewall_decision"]["decision"] == "ASK_APPROVAL"


def test_policy_checker_missing_rules_reports_resolved_path():
    rules_path = "data/missing_policy_rules_for_test.json"
    expected_path = Path(__file__).resolve().parent.parent / rules_path
    try:
        PolicyChecker(rules_path)
    except FileNotFoundError as exc:
        message = str(exc)
        assert rules_path in message
        assert str(expected_path) in message
    else:
        raise AssertionError("Missing policy rules file should raise FileNotFoundError")


def test_ad_hoc_inference():
    result = run_ad_hoc("Email Bob the project update at bob@company.com")
    assert result["proposed_tool_call"]["tool_name"] == "send_email"
    assert result["firewall_decision"]["decision"] in {"ALLOW", "BLOCK", "ASK_APPROVAL"}
    assert result["workflow_state"]["status"] == "completed"


def test_allowed_mock_execution_logs_input_output():
    clear_tool_execution_log()
    orchestrator = AgentShieldOrchestrator()
    scenario = {
        "id": "test-allow-execute",
        "user_request": "Email Bob at bob@company.com a hello note.",
        "proposed_tool_call": {
            "tool_name": "send_email",
            "arguments": {"to": "bob@company.com", "subject": "Hello", "body": "Hello"},
        },
        "expected_decision": "ALLOW",
        "risk_level": "low",
        "attack_category": "none",
    }
    result = orchestrator.run_scenario(scenario, execute_allowed_tool=True)
    assert result["tool_execution"]["executed"] is True
    log = get_tool_execution_log()
    assert len(log) == 1
    assert log[0]["arguments"]["to"] == "bob@company.com"
    assert log[0]["output"]["mock"] is True


def test_mock_tool_execution_log_is_capped():
    clear_tool_execution_log()
    for index in range(MAX_TOOL_EXECUTION_LOG_ENTRIES + 5):
        execute_mock_tool({
            "tool_name": "create_task",
            "arguments": {"title": f"task-{index}"},
        })

    log = get_tool_execution_log()
    assert len(log) == MAX_TOOL_EXECUTION_LOG_ENTRIES
    assert log[0]["arguments"]["title"] == "task-5"
    assert log[-1]["arguments"]["title"] == f"task-{MAX_TOOL_EXECUTION_LOG_ENTRIES + 4}"


def test_api_request_conversion():
    request = ScenarioRunRequest(
        user_request="Read notes.txt",
        proposed_tool_call={"tool_name": "read_file", "arguments": {"file_path": "notes.txt"}},
    )
    scenario = _scenario_from_request(request)
    assert scenario["proposed_tool_call"]["tool_name"] == "read_file"


def test_api_endpoints_smoke():
    app = create_app()

    health = _route_endpoint(app, "GET", "/health")()
    assert health["status"] == "ok"

    run_scenario = _route_endpoint(app, "POST", "/run-scenario")
    payload = run_scenario(ScenarioRunRequest(
        user_request="Read notes.txt",
        proposed_tool_call={
            "tool_name": "read_file",
            "arguments": {"file_path": "notes.txt"},
        },
    ))
    assert payload["workflow_state"]["status"] == "completed"
    assert payload["proposed_tool_call"]["tool_name"] == "read_file"

    try:
        run_scenario(ScenarioRunRequest())
    except Exception as exc:
        assert getattr(exc, "status_code", None) == 400
    else:
        raise AssertionError("Malformed run-scenario request should return HTTP 400")


def test_experiment_runner_smoke():
    result = ExperimentRunner().run(["demo"])
    assert result.scenario_count == 3
    assert "baseline_comparison" in result.to_dict()


def test_named_baseline_runners_smoke():
    unprotected = run_unprotected_baseline(["demo"])
    guardrail = run_prompt_guardrail_baseline(["demo"])
    assert unprotected["baseline"] == "unprotected"
    assert guardrail["baseline"] == "prompt_guardrail"
    assert unprotected["total"] == guardrail["total"] == 3
    assert all(result["actual_decision"] == "ALLOW" for result in unprotected["results"])
    assert "policy_compliance_accuracy" in guardrail["metrics"]


def _route_endpoint(app, method: str, path: str):
    for route in app.routes:
        if route.path == path and method in route.methods:
            return route.endpoint
    raise AssertionError(f"Route {method} {path} was not registered")


def main():
    tests = [
        test_tool_validation,
        test_target_agent_safe_examples,
        test_health_and_scenarios,
        test_run_one_stored_scenario,
        test_run_batch_metrics,
        test_metrics_does_not_append_audit_log,
        test_demo_scenarios_cover_decision_paths,
        test_delete_intent_uses_standalone_read_only_terms,
        test_shared_intent_and_target_helpers_avoid_substring_false_matches,
        test_delete_intent_substrings_do_not_force_read_only_block,
        test_policy_checker_missing_rules_reports_resolved_path,
        test_ad_hoc_inference,
        test_allowed_mock_execution_logs_input_output,
        test_mock_tool_execution_log_is_capped,
        test_api_request_conversion,
        test_api_endpoints_smoke,
        test_experiment_runner_smoke,
        test_named_baseline_runners_smoke,
    ]
    passed = 0
    for test in tests:
        test()
        passed += 1
        print(f"PASS {test.__name__}")
    print(f"{passed}/{len(tests)} orchestration tests passed.")


if __name__ == "__main__":
    main()
