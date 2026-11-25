"""GitHub Actions ingestion and PR feedback. All endpoints are repository-scoped."""
import base64
import binascii
from hashlib import sha1, sha256
import json
import os
from pathlib import Path
import re
import sys
import urllib.request as http

sys.path.insert(0,str(Path(__file__).resolve().parent))
from records import (bc, FIXTURES, MAX_PUBLIC_FINDINGS, PUBLIC_SCOPE, REPO, SITE, digest, need, package,
                     parse, positive, public_projection, record, utc)
import push_assessment as push

MARK = "<!-- context-aware-iac-security-gate -->"
GATE = ".github/workflows/security-gate.yml"
SIGNAL = ".github/workflows/security-gate-pr.yml"
GIT_SHA = re.compile("[0-9a-f]{40}")
TERRAFORM_NAME = re.compile(r"[A-Za-z0-9_.-]+\.tf")
MAX_FILES = 64
MAX_FILE_BYTES = 1024 * 1024
MAX_INPUT_BYTES = 2 * MAX_FILE_BYTES


class PublicationSkipped(ValueError):
    """Source or report is outside the public repository policy."""


def skip_notice(reason):
    # Only fixed diagnostics may enter Actions logs and the step summary.
    message = "Publication skipped: " + reason
    print(message)
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(summary, "a", encoding="utf-8") as stream:
            print(message, file=stream)



def api(path, *, method="GET", payload=None, binary=False):
    req=http.Request("https://api.github.com/repos/"+REPO+"/"+path,method=method,
                     data=json.dumps(payload).encode() if payload is not None else None,
                     headers={"User-Agent":"CI-4E","Accept":"application/vnd.github+json","Content-Type":"application/json"})
    req.add_unredirected_header("Authorization","Bearer "+os.environ["GH_TOKEN"])
    with http.urlopen(req,timeout=45) as response:
        data=response.read(4_000_001)
    need(len(data)<=4_000_000,"Oversized GitHub response")
    return data if binary else parse(data)


def outputs(**kwargs):
    with open(os.environ["GITHUB_OUTPUT"],"a") as stream:
        for key,value in kwargs.items():
            need("\n" not in str(value),"Invalid output")
            print(f"{key}={value}",file=stream)


def packed(obj):
    return base64.b64encode(json.dumps(obj,separators=(",",":"),allow_nan=False).encode()).decode()


def unpack_env():
    return parse(base64.b64decode(os.environ["RECORD"],validate=True))


def accepted_run(run,number,attempt,workflow_id):
    need(run["id"]==number and run["run_attempt"]==attempt and run["workflow_id"]==workflow_id and
         run["path"]==GATE and run["status"]=="completed" and run["event"] in ("workflow_dispatch","workflow_run") and
         run["head_branch"]=="main" and all(run[k]["full_name"]==REPO for k in ("repository","head_repository")) and
         re.fullmatch("[0-9a-f]{40}",run["head_sha"]),"Untrusted Gate run")


def validate_context_origin(e, run):
    info = e.get("context_provenance")
    if info is None:
        if run["event"] == "workflow_run":
            need(e.get("business_context") == dict(environment="dev", asset_criticality="low", data_sensitivity="low"),
                 "Legacy PR context")
        return
    bc.validate_provenance(info, e.get("business_context"), e.get("context_profile_id"),
                           pr_number=e.get("pr_number"), input_commit=e.get("input_commit_sha"), event=run["event"])
    revision = info["control_revision"]
    need(revision == run["head_sha"], "Context revision differs from trusted Gate run")
    if info["assessment_type"] in {"automatic_pr", "automatic_push"}:
        file = api(f"contents/{bc.CONFIG}?ref={revision}")
        need(file["type"] == "file" and file["encoding"] == "base64" and 0 < file["size"] <= 4096,
             "Unexpected trusted context file")
        raw = base64.b64decode("".join(file["content"].splitlines()), validate=True)
        need(len(raw) == file["size"] and digest(raw) == info["configuration_sha256"]
             and bc.values(parse(raw)) == bc.values(e["business_context"]), "Trusted context differs from GitHub blob")


def blob_bytes(entry):
    object_id = entry["sha"]
    need(isinstance(object_id, str) and GIT_SHA.fullmatch(object_id), "Invalid Terraform blob identity")
    size = entry["size"]
    if type(size) is not int or not 0 <= size <= MAX_FILE_BYTES:
        raise PublicationSkipped("Terraform file size is outside the input contract.")
    encoding = entry["encoding"]
    need(encoding == "base64", "Unsupported GitHub Terraform blob encoding")
    try:
        data = base64.b64decode("".join(entry["content"].splitlines()), validate=True)
    except binascii.Error:
        raise ValueError("Invalid GitHub Terraform blob encoding") from None
    git_object = f"blob {size}\0".encode() + data
    need(len(data) == size and sha1(git_object, usedforsecurity=False).hexdigest() == object_id,
         "Terraform blob differs from GitHub object identity")
    return data


def artifact_digest(files):
    # D-039 hashes ordered POSIX relative names and bytes as length-prefixed fields.
    digest = sha256(b"phase8-artifact-v1\0")
    for name, data in sorted(files):
        for value in (name.encode("utf-8"), data):
            digest.update(len(value).to_bytes(8, "big"))
            digest.update(value)
    return digest.hexdigest()


def pr_digest(sha):
    root = api(f"git/trees/{sha}")
    directories = [entry for entry in root["tree"] if entry["path"] == "terraform" and entry["type"] == "tree"]
    if root["truncated"] or len(directories) != 1:
        raise PublicationSkipped("Expected a complete Terraform tree at the evaluated commit.")
    tree_id = directories[0]["sha"]
    need(GIT_SHA.fullmatch(tree_id), "Invalid Terraform tree identity")
    tree = api(f"git/trees/{tree_id}")
    if tree["truncated"]:
        raise PublicationSkipped("GitHub did not return a complete Terraform directory.")
    inventory = {}
    total = 0
    for entry in tree["tree"]:
        name = entry["path"]
        if entry["mode"] not in {"100644", "100755"} or entry["type"] != "blob":
            raise PublicationSkipped("Terraform directory contains an unsupported tree entry.")
        if name.endswith((".tf.json", ".tfvars", ".tfvars.json")):
            raise PublicationSkipped("Terraform directory contains an unsupported file format.")
        if not name.endswith(".tf"):
            continue
        if not TERRAFORM_NAME.fullmatch(name) or name == ".tf":
            raise PublicationSkipped("Terraform directory contains an unsupported filename.")
        size = entry["size"]
        if type(size) is not int or not 0 <= size <= MAX_FILE_BYTES:
            raise PublicationSkipped("Terraform file size is outside the input contract.")
        need(name not in inventory and GIT_SHA.fullmatch(entry["sha"]), "Invalid Terraform tree inventory")
        inventory[name] = entry
        total += size
        if len(inventory) > MAX_FILES or total > MAX_INPUT_BYTES:
            raise PublicationSkipped("Terraform directory exceeds the input contract size limits.")
    if not inventory:
        raise PublicationSkipped("Terraform directory contains no supported .tf files.")
    files = []
    blobs = {}
    for name, entry in inventory.items():
        object_id = entry["sha"]
        if object_id not in blobs:
            response = api(f"git/blobs/{object_id}")
            need(response["sha"] == object_id and response["size"] == entry["size"],
                 "Terraform blob metadata differs from evaluated tree")
            blobs[object_id] = blob_bytes(response)
        need(len(blobs[object_id]) == entry["size"], "Terraform tree size mismatch")
        files.append((name, blobs[object_id]))
    return artifact_digest(files)


def resolve_input_digest(e, run):
    info = e.get("context_provenance") or {}
    if info.get("assessment_type") == "automatic_push":
        signal = e.get("signal_run_id")
        need(run["event"] == "workflow_run" and positive(signal) and e.get("pr_number") is None
             and e.get("publication_fixture") is None, "Push report linkage")
        source = api(f"actions/runs/{signal}")
        branch, sha = push.source_identity(source, run["repository"]["id"])
        need(branch == info["source_branch"] and sha == e.get("input_commit_sha") == info["expected_head_sha"]
             and source["workflow_id"] == api(f"actions/workflows/{push.SIGNAL_PATH.rsplit('/', 1)[1]}")["id"]
             and source["repository"]["id"] == run["repository"]["id"]
             and source["head_repository"]["full_name"] == REPO, "Push signal identity")
        return pr_digest(sha)
    manual_pr = info.get("assessment_type") == "on_demand_pr"
    if run["event"] == "workflow_dispatch" and not manual_pr:
        need(e.get("pr_number") is None and e.get("input_commit_sha") in (None, run["head_sha"]), "Fixture provenance")
        name = e.get("publication_fixture")
        if name not in FIXTURES:
            raise PublicationSkipped("Dispatch lacks an approved fixture identity or verified PR pin.")
        fixture = api(f"contents/.github/ci_gate_fixtures/{name}/main.tf?ref={run['head_sha']}")
        need(fixture["type"] == "file", "Invalid trusted fixture source")
        return artifact_digest([("main.tf", blob_bytes(fixture))])
    pr = e.get("pr_number")
    sha = e.get("input_commit_sha") or ""
    if not positive(pr) or not GIT_SHA.fullmatch(sha):
        raise PublicationSkipped("Report lacks the PR number or evaluated PR head SHA.")
    if manual_pr:
        need(run["event"] == "workflow_dispatch" and sha == info["expected_head_sha"]
             and e.get("signal_run_id") is None and e.get("publication_fixture") is None,
             "Manual PR provenance")
        current = api(f"pulls/{pr}")
        # The trusted Gate resolved an open PR and pinned SHA before checkout. The head may
        # advance before publication or recovery. Inspect the evaluated commit's tree below.
        need(current["number"] == pr and current["base"]["ref"] == "main"
             and all((current[side].get("repo") or {}).get("id") == run["repository"]["id"]
                     for side in ("head", "base")), "Manual PR association")
    else:
        signal = e.get("signal_run_id")
        if not positive(signal):
            raise PublicationSkipped("Report lacks verified PR signal linkage.")
        source = api(f"actions/runs/{signal}")
        need(source["event"]=="pull_request" and source["conclusion"]=="success" and source["path"]==SIGNAL
             and source["head_sha"]==sha and source["head_repository"]["full_name"]==REPO
             and source["workflow_id"]==api("actions/workflows/security-gate-pr.yml")["id"],"PR signal identity")
        need(any(x["number"]==pr and x["head"]["sha"]==sha and x["base"]["ref"]=="main" and
                 x["head"]["repo"]["id"]==x["base"]["repo"]["id"]==run["repository"]["id"]
                 for x in source["pull_requests"]),"PR association")
    return pr_digest(sha)

def ingest(number, attempt):
    try:
        ingest_verified(number, attempt)
    except PublicationSkipped as exc:
        skip_notice(str(exc))
    except (KeyError, OSError, TypeError, ValueError):
        skip_notice("Source or report could not be verified. See the publisher error for the failed check.")
        raise


def ingest_verified(number, attempt):
    need(positive(number) and positive(attempt),"Invalid run or attempt")
    prefix=f"actions/runs/{number}"
    run=api(f"{prefix}/attempts/{attempt}")
    accepted_run(run,number,attempt,api("actions/workflows/security-gate.yml")["id"])
    control=os.environ["GITHUB_SHA"]
    need(re.fullmatch("[0-9a-f]{40}",control) and api(f"compare/{run['head_sha']}...{control}")["status"] in
         ("ahead","identical"),"Gate control is not an ancestor of publisher main")
    listing=api(f"{prefix}/artifacts?per_page=100")
    need(listing["total_count"]==len(listing["artifacts"]),"Artifact listing incomplete")
    pattern=rf"security-gate-[0-9]{{8}}T[0-9]{{6}}Z_run-{number}_attempt-{attempt}"
    matches=[a for a in listing["artifacts"] if re.fullmatch(pattern,a["name"])]
    jobs=api(f"{prefix}/attempts/{attempt}/jobs")["jobs"]
    need(len(jobs)==1 and jobs[0]["run_attempt"]==attempt,"Unexpected Gate job identity")
    job=jobs[0]
    if (not matches and run["event"] == "workflow_run" and run.get("conclusion") == "success"
            and any(step["name"] == "Skip push covered by the official PR lane" and step["conclusion"] == "success"
                    for step in job["steps"])):
        skip_notice("An eligible open PR covers the exact pushed revision.")
        return
    need(len(matches)==1,"Exact attempt artifact unavailable")
    art=matches[0]
    provenance=art["workflow_run"]
    need(not art["expired"] and provenance["id"]==number and provenance["head_sha"]==run["head_sha"] and
         provenance["repository_id"]==provenance["head_repository_id"]==run["repository"]["id"],"Artifact provenance")
    need(any(x["name"]=="Upload the run record for PASS, REVIEW or ERROR"
             and x["conclusion"]=="success" for x in job["steps"]),"Missing trusted upload")
    need(utc(job["started_at"]) <= utc(art["created_at"]) <= utc(job["completed_at"]),"Artifact outside trusted attempt")
    data=package(api(f"actions/artifacts/{art['id']}/zip",binary=True),art["digest"])
    e=parse(data["execution.json"])
    need((e["github_run_id"],e["github_run_attempt"],e["github_run_number"],e["artifact_name"])==
         (number,attempt,run["run_number"],art["name"]) and e.get("trigger_event",run["event"])==run["event"],"Execution metadata")
    g = parse(data["gate-result.json"]) if "gate-result.json" in data else None
    export = digest(data["gate-result.json"]) if g is not None else None
    need(export == e.get("gate_result_sha256"), "Export checksum")
    if e.get("trigger_event") is None and g is None:
        e["trigger_event"] = run["event"]
    evaluated_digest = resolve_input_digest(e, run)
    if g is not None or e.get("terraform_artifact_sha256") is not None:
        need(e.get("terraform_artifact_sha256") == evaluated_digest,
             "Terraform artifact SHA-256 differs from the evaluated revision")
    validate_context_origin(e, run)
    projected = public_projection(g)
    if projected and sum(len(projected[key]) for key in ("ranked_supported_findings", "unsupported_findings")) > MAX_PUBLIC_FINDINGS:
        raise PublicationSkipped(f"Report exceeds the {MAX_PUBLIC_FINDINGS}-finding public report limit.")
    result = record(e, projected, PUBLIC_SCOPE, digest(data["execution.json"]), export)
    outputs(ready="yes", payload=packed(result), pr=(e.get("pr_number") or "") if official_pr(e) else "")


def comment_body(r,online):
    e=r["execution"];g=r["result"];n=e["github_run_id"];a=e["github_run_attempt"]
    ctx=e.get("business_context") or {}
    counts=e.get("counts") or {}
    lines=[MARK,f"<!-- ci4e {n} {a} -->","## Security Gate · ADVISORY_ONLY",
           f"Gate **{e['gate_status'] or 'N/A'}** · Wrapper **{e['wrapper_status']}** · Scan hoàn tất: {e['scan_complete']} · Bước lỗi: {e['failure_stage'] or 'N/A'}",
           "Bối cảnh: "+" / ".join(ctx.get(k,"N/A") for k in ("environment","asset_criticality","data_sensitivity")),
           "Failed / scored / unsupported / unscorable: "+" / ".join(str(counts.get(k,"N/A")) for k in
           ("failed_findings_total","supported_findings","unsupported_findings","unscorable_findings"))]
    if e.get("context_provenance"):
        info = e["context_provenance"]
        lines.append(f"Bối cảnh chính thức · {e['context_profile_id']} · cấu hình `{info['configuration_sha256']}` tại commit `{info['control_revision']}`")
    if g and (g["ranked_supported_findings"] or g["unsupported_findings"]):
        lines+=["","| Hạng | Rule | Severity D-022 | Score | Phân loại |","|---:|---|---:|---:|---|"]
        for row in g["ranked_supported_findings"][:5]+g["unsupported_findings"][:3]:
            lines.append("| "+" | ".join(str(row[k]) if row[k] is not None else "—" for k in
                         ("priority_rank_expected","check_id","severity_numeric","priority_score","classification"))+" |")
    lines+=["",f"PR #{e['pr_number']} · `{e['input_commit_sha']}` · {e['finished_utc']}",
            f"Model: `{e['deployment_model_id'] or 'N/A'}` · [Run {n}, attempt {a}](https://github.com/{REPO}/actions/runs/{n}/attempts/{a})"]
    lines.append(f"[Báo cáo HTML]({SITE}reports/{n}/attempt-{a}/report.html) · [Dashboard]({SITE})" if online
                 else "Báo cáo trực tuyến chưa khả dụng. Artifact nằm trong Actions run.")
    return "\n\n".join(lines[:5])+"\n"+"\n".join(lines[5:])


def official_pr(e):
    info = e.get("context_provenance")
    return info["assessment_type"] == "automatic_pr" if info is not None else e.get("trigger_event") == "workflow_run"


def feedback(r,online,call=api):
    e=r["execution"];pr=e["pr_number"]
    if pr is None or not official_pr(e):
        return
    matches=[]
    page=1
    while True:
        comments=call(f"issues/{pr}/comments?per_page=100&page={page}")
        matches.extend(c for c in comments if c["user"]["id"]==41898282 and c["user"]["login"]=="github-actions[bot]"
                       and c["body"].startswith(MARK+"\n"))
        if len(comments)<100: break
        page+=1
    need(len(matches)<=1,"Ambiguous bot comment")
    if matches:
        marker=re.search(r"<!-- ci4e (\d+) (\d+) -->",matches[0]["body"])
        need(marker,"Unknown existing bot comment identity")
        if tuple(map(int,marker.groups()))>(e["github_run_id"],e["github_run_attempt"]):
            return
    current=call(f"pulls/{pr}")
    if (current["state"]!="open" or current["head"]["sha"]!=e["input_commit_sha"] or
        current["head"]["repo"]["full_name"]!=REPO or current["base"]["ref"]!="main" or current["base"]["repo"]["full_name"]!=REPO):
        return
    body={"body":comment_body(r,online)}
    if matches:
        call(f"issues/comments/{matches[0]['id']}",method="PATCH",payload=body)
    else:
        call(f"issues/{pr}/comments",method="POST",payload=body)


if __name__=="__main__":
    if sys.argv[1]=="ingest":
        if os.environ["SOURCE_RUN"]:
            ingest(int(os.environ["SOURCE_RUN"]),int(os.environ["SOURCE_ATTEMPT"]))
        else:
            need(os.environ["GITHUB_EVENT_NAME"]=="workflow_dispatch","Missing event")
            outputs(ready="yes",initialize="yes",payload="",pr="")
    elif sys.argv[1]=="comment":
        feedback(unpack_env(),os.environ["DEPLOYED"]=="success" and os.environ["PAGE_URL"].rstrip("/")+"/"==SITE)
