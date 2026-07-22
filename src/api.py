"""FastAPI app for AgentShield backend integration."""

from typing import Any

from src.orchestrator import AgentShieldOrchestrator
from src.scenario_store import available_datasets
from src.schemas import (
    BatchRunRequest,
    DatasetQuery,
    ScenarioRunRequest,
    ScenarioRunResponse,
)
from src.tools import ToolValidationError, list_tool_specs

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.middleware.cors import CORSMiddleware
except ImportError:  # pragma: no cover - exercised only in environments without FastAPI
    FastAPI = None
    HTTPException = None
    CORSMiddleware = None


def create_app() -> Any:
    """Create the FastAPI application."""
    if FastAPI is None:
        raise RuntimeError("FastAPI is not installed. Install requirements.txt to run the API.")

    app = FastAPI(
        title="AgentShield Core API",
        version="0.1.0",
        description="Backend orchestration API for AgentShield scenario simulation and firewall decisions.",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    orchestrator = AgentShieldOrchestrator()

    @app.get("/health")
    def health() -> dict[str, Any]:
        return orchestrator.health()

    @app.get("/tools")
    def tools() -> dict[str, Any]:
        return {"tools": list_tool_specs()}

    @app.get("/scenarios")
    def scenarios() -> dict[str, Any]:
        return orchestrator.list_scenarios()

    @app.post("/run-scenario", response_model=ScenarioRunResponse)
    def run_scenario(request: ScenarioRunRequest) -> dict[str, Any]:
        try:
            scenario = _scenario_from_request(request)
            return orchestrator.run_scenario(scenario, request.execute_allowed_tool)
        except (ToolValidationError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/run-batch")
    def run_batch(request: BatchRunRequest) -> dict[str, Any]:
        try:
            scenarios = None
            if request.scenarios is not None:
                scenarios = [_model_to_dict(scenario) for scenario in request.scenarios]
            return orchestrator.run_batch(
                scenarios=scenarios,
                dataset_names=request.dataset_names,
                execute_allowed_tools=request.execute_allowed_tools,
            )
        except (ToolValidationError, ValueError, FileNotFoundError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/metrics")
    def metrics() -> dict[str, Any]:
        return orchestrator.run_batch()["metrics"] or {"message": "No labeled scenarios available."}

    @app.post("/metrics")
    def metrics_for_datasets(request: DatasetQuery) -> dict[str, Any]:
        return orchestrator.run_batch(dataset_names=request.dataset_names)["metrics"] or {
            "message": "No labeled scenarios available."
        }

    @app.get("/audit-log")
    def audit_log() -> dict[str, Any]:
        return orchestrator.audit_log()

    @app.post("/baseline-comparison")
    def baseline_comparison(request: DatasetQuery) -> dict[str, Any]:
        return orchestrator.baseline_comparison(dataset_names=request.dataset_names)

    @app.get("/datasets")
    def datasets() -> dict[str, Any]:
        return {"datasets": available_datasets()}

    return app


def _scenario_from_request(request: ScenarioRunRequest) -> dict[str, Any]:
    if request.scenario is not None:
        return _model_to_dict(request.scenario)
    if not request.user_request:
        raise ValueError("Either scenario or user_request is required.")
    scenario = {
        "user_request": request.user_request,
        "external_context": request.external_context,
    }
    if request.proposed_tool_call:
        scenario["proposed_tool_call"] = _model_to_dict(request.proposed_tool_call)
    return scenario


def _model_to_dict(model: Any) -> dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump(exclude_none=True)
    return model.dict(exclude_none=True)


try:
    app = create_app()
except RuntimeError:
    app = None
