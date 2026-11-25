"""CI metadata for the frozen D-039 business-context inputs."""
import re

from push_assessment import workload_branch

KEYS = ("environment", "asset_criticality", "data_sensitivity")
DOMAINS = (("dev", "prod"), ("low", "high"), ("low", "high"))
PROFILES = {
    ("dev", "low", "low"): "CTX01",
    ("dev", "low", "high"): "CTX02",
    ("dev", "high", "low"): "CTX03",
    ("dev", "high", "high"): "CTX04",
    ("prod", "low", "low"): "CTX05",
    ("prod", "low", "high"): "CTX06",
    ("prod", "high", "low"): "CTX07",
    ("prod", "high", "high"): "CTX08",
}
SOURCES = {
    "automatic_push": "trusted_workload_config",
    "automatic_pr": "trusted_workload_config",
    "on_demand_pr": "dispatch_parameters",
    "fixture": "trusted_fixture_profile",
}
CONFIG = "config/business-context.json"
VERSION = "ci5c-context-v1"


def values(document):
    if not isinstance(document, dict) or set(document) != set(KEYS):
        raise ValueError("Expected exactly the three D-039 context keys")
    result = tuple(document[key] for key in KEYS)
    if any(value not in domain for value, domain in zip(result, DOMAINS)):
        raise ValueError("Unsupported D-039 business context value")
    return result


def provenance(kind, revision, *, config_sha=None, expected_head=None, source_branch=None):
    result = dict(schema_version=VERSION, assessment_type=kind, context_source=SOURCES[kind],
                control_revision=revision, configuration_sha256=config_sha, expected_head_sha=expected_head)
    if kind == "automatic_push":
        result["source_branch"] = source_branch
    return result


def validate_provenance(info, context, profile, *, pr_number, input_commit, event):
    if not isinstance(info, dict):
        raise ValueError("Missing context provenance object")
    kind = info.get("assessment_type")
    if kind not in SOURCES:
        raise ValueError("Invalid assessment type")
    revision = info.get("control_revision")
    config_sha = info.get("configuration_sha256")
    expected = info.get("expected_head_sha")
    if not isinstance(revision, str) or not re.fullmatch(r"[a-f0-9]{40}", revision):
        raise ValueError("Invalid context control revision")
    branch = info.get("source_branch")
    if info != provenance(kind, revision, config_sha=config_sha, expected_head=expected, source_branch=branch):
        raise ValueError("Unexpected context provenance fields")
    if profile != PROFILES[values(context)]:
        raise ValueError("Business context/profile mismatch")
    if kind == "automatic_push":
        valid = (event == "workflow_run" and pr_number is None and workload_branch(branch)
                 and isinstance(expected, str) and re.fullmatch(r"[a-f0-9]{40}", expected)
                 and expected == input_commit and isinstance(config_sha, str) and re.fullmatch(r"[a-f0-9]{64}", config_sha))
    elif kind == "automatic_pr":
        valid = (event == "workflow_run" and type(pr_number) is int and pr_number > 0 and expected is None
                 and isinstance(config_sha, str) and re.fullmatch(r"[a-f0-9]{64}", config_sha))
    elif kind == "on_demand_pr":
        valid = (event == "workflow_dispatch" and type(pr_number) is int and pr_number > 0 and config_sha is None
                 and isinstance(expected, str) and re.fullmatch(r"[a-f0-9]{40}", expected)
                 and expected == input_commit)
    else:
        valid = (event == "workflow_dispatch" and pr_number is None and config_sha is None and expected is None
                 and input_commit == revision and profile in {"CTX01", "CTX08"})
    if not valid:
        raise ValueError("Context provenance does not match the assessment")
