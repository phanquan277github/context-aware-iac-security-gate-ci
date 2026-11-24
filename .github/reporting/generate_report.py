"""Produce CI-4 artifacts from a single verified Gate snapshot (or wrapper diagnostics)."""
import argparse
import csv
from datetime import datetime, timedelta
import io
import json
import os
from pathlib import Path
import re
import sys
import tempfile

# The workflow runs this file only from its independently checked-out control tree.
HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE.parent)]
import ci_gate as gate
from render import html_report, markdown

STAGES = ("terraform_init", "terraform_validate", "checkov_scan", "feature_extraction", "model_scoring")
MODEL_ID = "rf_severity_context_deployment_v1"
EXEC_SCHEMA = "ci4-advisory-execution-v1"
RESULT_SCHEMA = "ci4-advisory-gate-result-v1"


def json_bytes(obj):
    return (json.dumps(obj, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True) + "\n").encode()


def utc(value):
    stamp = datetime.fromisoformat(value)
    gate.require(stamp.utcoffset() == timedelta(0), "Expected a UTC timestamp")
    return stamp


def history_name(record):
    run, attempt = record["github_run_id"], record["github_run_attempt"]
    gate.require(all(type(n) is int and n > 0 for n in (run, attempt)), "Missing run or attempt")
    return f"security-gate-{utc(record['started_utc']):%Y%m%dT%H%M%SZ}_run-{run}_attempt-{attempt}"


def public_result(doc, raw_digest, bundle, fixture):
    runtime = bundle / "runtime"
    severity = gate.regular(runtime / "results/main_benchmark/severity_mapping_v1.csv").decode()
    titles = {r["check_id"]: r["check_name"] for r in csv.DictReader(io.StringIO(severity))}
    types = set(re.findall(r"resource_type: (aws_[a-z0-9_]+),",
                           gate.regular(runtime / "dataset/main/context/resource_role_taxonomy.yaml").decode()))
    def finding(row, scored):
        rule = row["check_id"]
        check_id = rule if re.fullmatch(r"CKV2?_AWS_[0-9]{1,6}", rule) else None
        resource_type = row.get("resource_type")
        # Free-text titles and identifiers can carry secrets even if syntactically valid.
        # Disclose only a matching frozen title, and an identifier from the public fixture.
        name = titles.get(rule)
        resource = row.get("resource") if fixture and row.get("resource") == "aws_vpc.demonstration" else None
        path = "main.tf" if row["source_path"] == "main.tf" else None
        return {
            "finding_id": row["finding_id"], "check_id": check_id,
            "check_name": name if name == row["check_name"] else None,
            "resource_type": resource_type if isinstance(resource_type, str) and resource_type in types else None,
            "resource": resource, "source_path": path,
            "line_start": row["line_start"] if path and row["line_end"] <= 2**20 else None,
            "line_end": row["line_end"] if path and row["line_end"] <= 2**20 else None,
            "classification": "scored" if scored else row["unsupported_reason"].lower(),
            "severity_numeric": row["severity_numeric"] if scored else None,
            "context_features": row["context_features"] if scored else None,
            "priority_score": row["priority_score"], "priority_rank_expected": row.get("priority_rank_expected"),
            "priority_tie_group_size": row.get("priority_tie_group_size"),
            "unsupported_reason": None if scored else row["unsupported_reason"],
        }
    states = {}
    for stage in STAGES:
        value = doc["execution_status"][stage]
        states[stage] = value["status"] if isinstance(value, dict) else value
    scored = [finding(row, True) for row in doc["ranked_supported_findings"]]
    result = {
        "schema_version": RESULT_SCHEMA, "source_gate_json_sha256": raw_digest,
        "gate_status": doc["gate_status"], "gate_exit_code": doc["exit_code"],
        "counts": gate.result_counts(doc)[0], "execution_status": states,
        "ranked_supported_findings": sorted(scored, key=lambda r: (r["priority_rank_expected"], r["finding_id"])),
        "unsupported_findings": [finding(row, False) for row in doc["unsupported_findings"]],
    }
    # jsonschema is already pinned in the CI-3B0 venv. Bootstrap diagnostics use stdlib only.
    from jsonschema import Draft202012Validator
    validator = Draft202012Validator(json.loads((HERE / "gate-result-v1.schema.json").read_bytes()))
    gate.require(validator.is_valid(result), "Report export violates CI-4 schema")
    return result


def prepare(args, env):
    record, doc = gate.collect_record(args, env)
    event = env.get("GITHUB_EVENT_NAME")
    fixture = env.get("FIXTURE") if event == "workflow_dispatch" else None
    if doc is None and args.exit < 0:
        record["process_exit_code"] = None
        for variable, stage in (("PINS_OUTCOME", "TRUST_OR_PR_RESOLUTION"), ("ARCHIVE_OUTCOME", "RUNTIME_ACQUISITION"),
                                ("PROVISION_OUTCOME", "TOOLCHAIN_PROVISION"), ("INPUT_OUTCOME", "TERRAFORM_INPUT")):
            if env.get(variable) != "success":
                record["failure_stage"] = stage
                break
    record["publication_fixture"] = fixture if fixture in gate.FIXTURES else None
    signal = env.get("CI_SIGNAL_ID", "")
    record["signal_run_id"] = int(signal) if event == "workflow_run" and re.fullmatch(r"[1-9][0-9]{0,19}", signal) else None
    verified_archive = env.get("ARCHIVE_OUTCOME") == "success"
    pin = env.get("RUNTIME_ARCHIVE_SHA", "")
    terraform_digest = doc["input"]["artifact_sha256"] if doc is not None else None
    record.update(
        schema_version=EXEC_SCHEMA, artifact_name=history_name(record),
        execution_origin="github_actions" if env.get("GITHUB_ACTIONS") == "true" else "local_preview",
        duration_seconds=(utc(record["finished_utc"]) - utc(record["started_utc"])).total_seconds(),
        trigger_event=event if event in {"workflow_run", "workflow_dispatch"} else None,
        workflow_ref="refs/heads/main" if env.get("GITHUB_REF") == "refs/heads/main" else None,
        runtime_archive_sha256=pin if verified_archive and gate.SHA64.fullmatch(pin) else None,
        scan_complete=gate.result_counts(doc)[1] if doc is not None else None,
        terraform_artifact_sha256=(terraform_digest if isinstance(terraform_digest, str)
                                   and gate.SHA64.fullmatch(terraform_digest) else None),
        deployment_model_id=MODEL_ID if doc is not None else None,
        model_trust_status=doc["model_provenance"]["trust_status"] if doc is not None else None,
    )
    if not verified_archive:
        record.update(model_sha256=None, manifest_sha256=None)
    if event == "workflow_dispatch":
        expected = gate.FIXTURES.get(fixture)
        matched = expected is not None and expected == record["gate_exit_code"]
        record.update(fixture_expected_gate_exit_code=expected, fixture_expectation="PASS" if matched else "FAIL")
        if not matched:
            record.update(wrapper_status="ERROR", wrapper_exit_code=20,
                          failure_stage=record["failure_stage"] or "FIXTURE_EXPECTATION")
    return record, doc


def file_set(record, result, *, diagnostic=False):
    files = {}
    def with_sidecar(name, payload):
        digest = gate.sha(payload)
        files[name] = payload
        files[name + ".sha256"] = f"{digest}  {name}\n".encode()
        return digest
    export_hash = with_sidecar("gate-result.json", json_bytes(result)) if result is not None else None
    record["gate_result_sha256"] = export_hash
    execution_hash = with_sidecar("execution.json", json_bytes(record))
    if diagnostic:
        from html import escape
        text = (f"## Security Gate · ADVISORY_ONLY\nGate: {record['gate_status']} / {record['gate_exit_code']}\n"
                f"Wrapper: ERROR/20 · REPORT_GENERATION\nRun {record['github_run_id']} · attempt {record['github_run_attempt']}\n"
                f"Artifact: {record['artifact_name']}\n")
        files["report.md"] = text.encode()
        files["report.html"] = ('<!doctype html><meta charset="utf-8"><title>Security Gate</title><pre>'
                                + escape(text) + '</pre>').encode()
    else:
        files["report.html"] = html_report(record, result, execution_hash, export_hash).encode()
        files["report.md"] = markdown(record, result).encode()
    files["checksums.sha256"] = "".join(f"{gate.sha(files[n])}  {n}\n" for n in sorted(files)).encode()
    return files


def generate(args, env):
    record, doc = prepare(args, env)
    try:
        result = public_result(doc, record["gate_json_sha256"], args.bundle,
                               env.get("GITHUB_EVENT_NAME") == "workflow_dispatch") if doc is not None else None
        files = file_set(record, result)
    except (ValueError, OSError, KeyError, TypeError, OverflowError, RuntimeError, ImportError):
        record.update(wrapper_status="ERROR", wrapper_exit_code=20, failure_stage="REPORT_GENERATION")
        files = file_set(record, None, diagnostic=True)
    # The destination is inside a fresh runner-owned directory. Publish only complete sets.
    with tempfile.TemporaryDirectory(dir=args.output.parent) as staging:
        pending = Path(staging) / "report"
        pending.mkdir()
        for name, payload in files.items():
            (pending / name).write_bytes(payload)
        if args.output.exists():
            raise FileExistsError("Report directory already exists")
        pending.rename(args.output)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new directory in trusted runner temp")
    args = parser.parse_args()
    env = os.environ
    args.bundle, args.raw = Path(env["BUNDLE_DIR"]), Path(env["RAW_DIR"])
    args.start = env["STARTED_UTC"]
    args.runtime_sha = env.get("RUNTIME_SHA", "")
    args.commit = env.get("PR_SHA") if env.get("GITHUB_EVENT_NAME") == "workflow_run" else env.get("GITHUB_SHA")
    args.commit = args.commit or ""
    code = env.get("GATE_EXIT", "")
    args.exit = int(code) if re.fullmatch("[0-9]{1,3}", code) else -1
    print(generate(args, env)["wrapper_exit_code"])


if __name__ == "__main__":
    main()
