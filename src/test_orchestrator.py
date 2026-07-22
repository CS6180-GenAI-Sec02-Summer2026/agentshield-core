"""Focused tests for Mrinal-owned orchestration/API integration layer."""

from src.api import ScenarioRunRequest, _scenario_from_request
from src.experiment_runner import ExperimentRunner
from src.orchestrator import AgentShieldOrchestrator, run_ad_hoc
from src.scenario_store import available_datasets, load_scenarios
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


def test_demo_scenarios_cover_decision_paths():
    result = AgentShieldOrchestrator().run_batch(dataset_names=["demo"])
    assert result["summary"]["decisions"] == {
        "ALLOW": 1,
        "BLOCK": 1,
        "ASK_APPROVAL": 1,
    }
    assert result["metrics"]["policy_compliance_accuracy"] == 100.0
    assert all(item["matched_expected"] for item in result["results"])


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


def test_experiment_runner_smoke():
    result = ExperimentRunner().run(["demo"])
    assert result.scenario_count == 3
    assert "baseline_comparison" in result.to_dict()


def main():
    tests = [
        test_tool_validation,
        test_target_agent_safe_examples,
        test_health_and_scenarios,
        test_run_one_stored_scenario,
        test_run_batch_metrics,
        test_demo_scenarios_cover_decision_paths,
        test_ad_hoc_inference,
        test_allowed_mock_execution_logs_input_output,
        test_mock_tool_execution_log_is_capped,
        test_api_request_conversion,
        test_experiment_runner_smoke,
    ]
    passed = 0
    for test in tests:
        test()
        passed += 1
        print(f"PASS {test.__name__}")
    print(f"{passed}/{len(tests)} orchestration tests passed.")


if __name__ == "__main__":
    main()
