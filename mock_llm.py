"""Deterministic stand-in for the LLM, used only when MOCK_LLM=1 (local tests)."""
import json
import re


def mock_plan(user_prompt):
    meta = json.loads(user_prompt.split("\n", 1)[1].split("\n\nTRANSCRIPT", 1)[0])
    title = meta["incident"]["title"]
    svc = meta["incident"]["service"]
    if "parallel" in title:
        return {"rootCause": "dependency_saturation", "evidence": ["ev_a1", "ev_b2", "ev_c3"],
                "diagnostics": [
                    {"toolName": "query_metrics", "arguments": {"service": svc, "metric": "cpu"}, "evidence": ["ev_a1"]},
                    {"toolName": "check_dependency", "arguments": {"dependency": "redis-main"}, "evidence": ["ev_b2"]}],
                "effect": {"toolName": "scale_service", "arguments": {"service": svc, "replicas": "12"}},
                "pageFallback": {"toolName": "page_owner", "arguments": {"service": svc}}}
    if "rollback" in title:
        return {"rootCause": "bad_deploy", "evidence": ["ev_a1", "ev_c3"],
                "diagnostics": [{"toolName": "get_deployment", "arguments": {"service": svc, "deploymentId": "dep-42"},
                                 "evidence": ["ev_c3"]}],
                "effect": {"toolName": "rollback_deployment", "arguments": {"service": svc, "deploymentId": "dep-42"}},
                "pageFallback": None}
    return {"rootCause": "dependency_saturation", "evidence": ["ev_a1", "ev_b2"],
            "diagnostics": [{"toolName": "query_metrics", "arguments": {"service": svc, "metric": "cpu", "junk": 1},
                             "evidence": ["ev_a1"]}],
            "effect": {"toolName": "scale_service", "arguments": {"service": svc, "replicas": 12}},
            "pageFallback": {"toolName": "page_owner", "arguments": {"service": svc}}}
