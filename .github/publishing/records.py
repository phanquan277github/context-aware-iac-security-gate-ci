"""Validate the CI-4 artifact at the disclosure boundary. Never extract archive paths."""
from datetime import datetime, timedelta
from hashlib import sha256
from io import BytesIO
import json
import math
from pathlib import Path
import re
import stat
import sys
from zipfile import ZipFile

from jsonschema import Draft202012Validator

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parent / "reporting"), str(HERE.parent)]
import business_context as bc
from render import html_report

REPO = "phanquan277github/context-aware-iac-security-gate-ci"
SITE = "https://phanquan277github.github.io/context-aware-iac-security-gate-ci/"
MODEL = "5ed8eb2bb44af178a748c1d6902917f5459a4361ba8171a5181960a06c6eb4c1"
ARCHIVE = "975ae49a69a61af6e06d64c081368d31ed0308856677f2e7a64fadb97d76d434"
RUNTIME = "bfb442e830511c657520d1477931593564459e29"
MODEL_ID = "rf_severity_context_deployment_v1"
MANIFEST = "e9c723e256dfbe31ea927ad74990686b94b2f8d7831bc7c665b55ba109a73fa2"
DEMO = json.loads((HERE/"demo-scope.json").read_bytes())
SCHEMA = Draft202012Validator(json.loads((HERE.parent/"reporting/gate-result-v1.schema.json").read_bytes()))
EXIT = {"PASS": 0, "REVIEW": 10, "ERROR": 20}
STAGES = ("terraform_init","terraform_validate","checkov_scan","feature_extraction","model_scoring")
FAILURES = {None,"GATE","GATE_EXECUTION","GATE_OUTPUT_VERIFICATION","WORKFLOW_PREPARATION","CONTROL_CHECKOUT",
            "REPORT_GENERATION","FIXTURE_EXPECTATION","TRUST_OR_PR_RESOLUTION","RUNTIME_ACQUISITION",
            "TOOLCHAIN_PROVISION","TERRAFORM_INPUT","BUSINESS_CONTEXT"}
BASE = {"report.html","report.md","execution.json","execution.json.sha256","checksums.sha256"}
FULL = BASE | {"gate-result.json","gate-result.json.sha256"}


def need(value, message):
    if not value:
        raise ValueError(message)


def positive(n):
    return type(n) is int and 0 < n < 10**20


def digest(data):
    return sha256(data).hexdigest()


def parse(data):
    def pairs(items):
        obj = dict(items)
        need(len(obj) == len(items), "Duplicate JSON key")
        return obj
    def finite(token):
        value = float(token)
        need(math.isfinite(value), "Invalid number")
        return value
    return json.loads(data, object_pairs_hook=pairs, parse_float=finite, parse_constant=finite)


def utc(s):
    need(isinstance(s,str) and re.fullmatch(r"[0-9T:.+-]{19,32}Z?",s), "Unsafe timestamp")
    d = datetime.fromisoformat(s)
    need(d.utcoffset()==timedelta(0),"Expected UTC")
    return d


def package(blob, expected):
    need(len(blob)<=2_000_000 and "sha256:"+digest(blob)==expected,"ZIP digest or size")
    with ZipFile(BytesIO(blob)) as z:
        members=z.infolist()
        names={x.filename for x in members}
        need(names in (BASE,FULL) and len(names)==len(members),"ZIP inventory")
        need(sum(x.file_size for x in members)<=4_000_000 and all(
            stat.S_IFMT(x.external_attr >> 16) in (0,stat.S_IFREG) and not x.flag_bits & 1
            for x in members),"Unsafe ZIP entry")
        data={x.filename:z.read(x) for x in members}
    lines=data["checksums.sha256"].decode("ascii").splitlines()
    expected_lines={digest(data[n])+"  "+n for n in names-{"checksums.sha256"}}
    need(len(lines)==len(expected_lines) and set(lines)==expected_lines,"Manifest mismatch")
    for n in names & {"execution.json","gate-result.json"}:
        need(data[n+".sha256"]==(digest(data[n])+"  "+n+"\n").encode(),"Sidecar mismatch")
    return data


def validate(e,g,scope):
    need(scope in DEMO and e["schema_version"]=="ci4-advisory-execution-v1" and
         e["enforcement"]=="ADVISORY_ONLY","Execution schema or scope")
    for k in ("github_run_id","github_run_number","github_run_attempt"):
        need(positive(e[k]),"Invalid execution identity")
    start,end=utc(e["started_utc"]),utc(e["finished_utc"])
    need(end>=start and e["artifact_name"]==f"security-gate-{start:%Y%m%dT%H%M%SZ}_run-{e['github_run_id']}_attempt-{e['github_run_attempt']}","Artifact identity")
    need(e["failure_stage"] in FAILURES and e["wrapper_status"] in EXIT and
         type(e["wrapper_exit_code"]) is int and EXIT[e["wrapper_status"]]==e["wrapper_exit_code"],"Wrapper")
    for k,length in (("input_commit_sha",40),("scanned_commit_sha",40),("gate_json_sha256",64),("gate_result_sha256",64)):
        need(e.get(k) is None or re.fullmatch(f"[0-9a-f]{{{length}}}",e[k]),"Invalid digest")
    need(e.get("pr_number") is None or positive(e["pr_number"]),"Invalid PR")
    if e.get("process_exit_code") is not None:
        need(type(e["process_exit_code"]) is int and -1<=e["process_exit_code"]<=255,"Process code")
    ctx=e.get("business_context")
    dev=dict(environment="dev",asset_criticality="low",data_sensitivity="low")
    prod=dict(environment="prod",asset_criticality="high",data_sensitivity="high")
    provenance = e.get("context_provenance")
    if provenance is not None:
        bc.validate_provenance(provenance, ctx, e.get("context_profile_id"), pr_number=e.get("pr_number"),
                               input_commit=e.get("input_commit_sha"), event=e.get("trigger_event"))
        if provenance["assessment_type"] == "fixture" and e.get("context_profile_id") == "CTX08":
            need(scope == "ci5", "Fixture profile outside approved scope")
    else:
        need(ctx is None or ctx == dev or (scope == "ci5" and e.get("pr_number") is None and ctx == prod), "Legacy context")
        need(e.get("context_profile_id") in (None, "CTX08" if ctx == prod else "CTX01"), "Legacy profile")
    if g is not None:
        if provenance is None:
            need("context_provenance" not in g and "business_context" not in g, "Unexpected context export")
        else:
            need(g.get("context_provenance") == provenance and g.get("business_context") == ctx,
                 "Export context provenance mismatch")
    for k,value in dict(trusted_runtime_commit_sha=RUNTIME,runtime_archive_sha256=ARCHIVE,model_sha256=MODEL,
                        deployment_model_id=MODEL_ID,manifest_sha256=MANIFEST,release_id="ci-gate-v1").items():
        need(e.get(k)==value or (g is None and e.get(k) is None),"Unexpected runtime or model")
    need(e.get("terraform_artifact_sha256") in (None,DEMO[scope]["input"]),"Unapproved input digest")
    need(e.get("fixture_expectation") in (None,"PASS","FAIL") and e.get("model_trust_status") in (None,"verified","not_verified"),"Diagnostics")
    need(e.get("trigger_event") in (None,"workflow_dispatch","workflow_run") and
         e.get("workflow_ref") in (None,"refs/heads/main") and e.get("execution_origin") in (None,"github_actions"),"Trigger metadata")
    if g is not None:
        need(e.get("execution_origin")=="github_actions" and e.get("workflow_ref")=="refs/heads/main" and
             e.get("trigger_event") in ("workflow_dispatch","workflow_run") and
             re.fullmatch("[0-9a-f]{40}",e["input_commit_sha"]),"Missing execution provenance")
    if g is None and e.get("gate_status") is not None:
        # CI-4 may verify Gate successfully and subsequently fail to render the export.
        state=e["gate_status"]
        counts=e.get("counts") or {}
        keys={"failed_findings_total","supported_findings","unsupported_findings","unscorable_findings"}
        need(state in EXIT and e["wrapper_status"]=="ERROR" and e["failure_stage"]=="REPORT_GENERATION"
             and type(e["gate_exit_code"]) is int and e["gate_exit_code"]==e.get("process_exit_code")==EXIT[state]
             and e.get("gate_result_sha256") is None and e.get("gate_json_sha256") and
             type(e.get("scan_complete")) is bool and (state=="ERROR" or e["scan_complete"])
             and set(counts)==keys and all(type(n) is int and 0<=n<=64 for n in counts.values())
             and counts["failed_findings_total"]==sum(counts[k] for k in keys-{"failed_findings_total"})
             and (state=="ERROR" or state==("REVIEW" if counts["failed_findings_total"] else "PASS")),
             "Invalid renderer diagnostic")
        return
    if g is None:
        need(e["wrapper_status"]=="ERROR" and e["failure_stage"] and e.get("gate_status") is None and
             all(e.get(k) is None for k in ("gate_exit_code","counts","scan_complete","gate_json_sha256","gate_result_sha256")),"Unverified diagnostic")
        return
    SCHEMA.validate(g)
    state=g["gate_status"]
    need(ctx and e.get("terraform_artifact_sha256")==DEMO[scope]["input"] and
         e["gate_status"]==state and type(e["gate_exit_code"]) is int and
         e["process_exit_code"]==e["gate_exit_code"]==g["gate_exit_code"]==EXIT[state] and
         e["gate_json_sha256"]==g["source_gate_json_sha256"] and
         (e["wrapper_status"]==state or e["wrapper_status"]=="ERROR" and e["failure_stage"]=="FIXTURE_EXPECTATION"),"Gate/exit mismatch")
    need(e["failure_stage"]==("GATE" if state=="ERROR" else None) or e["failure_stage"]=="FIXTURE_EXPECTATION","Failure stage")
    stages=g["execution_status"]
    need(e["scan_complete"] is (stages["checkov_scan"]=="success") and
         e["scanned_commit_sha"]==(e["input_commit_sha"] if e["scan_complete"] else None),"Scan provenance")
    if state!="ERROR":
        need(all(v=="success" for v in stages.values()) and e["model_trust_status"]=="verified","Incomplete scan")
    scored,others=g["ranked_supported_findings"],g["unsupported_findings"]
    scores=[r["priority_score"] for r in scored]
    need(len(scored)+len(others)<=64 and scores==sorted(scores,reverse=True),"Ranking order")
    seen=set()
    for r in scored+others:
        rule=r["check_id"]
        desc=DEMO[scope]["descriptors"].get(rule)
        need(desc is not None and [r[k] for k in ("check_name","resource_type","source_path")]==[desc[0],desc[1],desc[3]]
             and r["resource"] in (None,desc[2]),"Undisclosed finding fields")
        need(r["finding_id"] not in seen and all(type(r[k]) is int and 1<=r[k]<=10000 for k in ("line_start","line_end"))
             and r["line_start"]<=r["line_end"],"Finding identity or span")
        seen.add(r["finding_id"])
        if r["classification"]=="scored":
            score=r["priority_score"]
            tied=scores.count(score)
            need(math.isfinite(score) and 0<=score<=1 and r["priority_tie_group_size"]==tied and
                 r["priority_rank_expected"]==1+sum(x>score for x in scores)+(tied-1)/2 and
                 all(r["context_features"][k]==v for k,v in ctx.items()),"Score, rank or feature context")
        else:
            need(r["classification"]==r["unsupported_reason"].lower(),"Unsupported classification")
    n=sum(r["classification"]=="unsupported_rule" for r in others)
    counts=dict(failed_findings_total=len(seen),supported_findings=len(scored),unsupported_findings=n,unscorable_findings=len(others)-n)
    need(g["counts"]==e["counts"]==counts and all(type(v) is int for v in e["counts"].values()),"Finding counts")
    need(state=="ERROR" or state==("REVIEW" if seen else "PASS"),"Gate/count mismatch")


FIELDS = """schema_version enforcement started_utc finished_utc github_run_id github_run_number github_run_attempt
artifact_name execution_origin trigger_event workflow_ref pr_number input_commit_sha scanned_commit_sha trusted_runtime_commit_sha
release_id manifest_sha256 model_sha256 business_context gate_status gate_exit_code process_exit_code wrapper_status wrapper_exit_code
failure_stage gate_json_sha256 gate_result_sha256 counts scan_complete runtime_archive_sha256 deployment_model_id model_trust_status
fixture_expectation context_profile_id terraform_artifact_sha256""".split()


def record(e,g,scope,source_sha,export_sha):
    validate(e,g,scope)
    public={k:e.get(k) for k in FIELDS}
    if "context_provenance" in e:
        public["context_provenance"] = e["context_provenance"]
    public["duration_seconds"]=(utc(e["finished_utc"])-utc(e["started_utc"])).total_seconds()
    return dict(repository=REPO,scope=scope,execution=public,result=g,execution_digest=source_sha,export_digest=export_sha)
