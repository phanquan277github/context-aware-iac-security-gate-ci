"""GitHub Actions ingestion and PR feedback. All endpoints are repository-scoped."""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import sys
import urllib.request as http

sys.path.insert(0,str(Path(__file__).resolve().parent))
from records import DEMO, REPO, SITE, digest, need, package, parse, positive, record, utc

MARK = "<!-- context-aware-iac-security-gate -->"
GATE = ".github/workflows/security-gate.yml"
SIGNAL = ".github/workflows/security-gate-pr.yml"


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


def get_scope(e,run):
    if run["event"]=="workflow_dispatch":
        need(e.get("pr_number") is None and e.get("input_commit_sha") in (None,run["head_sha"]),"Fixture provenance")
        name=e.get("publication_fixture")
        if name not in {"pass","review","error","ci5"}:
            return None
        file=api(f"contents/.github/ci_gate_fixtures/{name}/main.tf?ref={run['head_sha']}")
        return name if file["sha"]==DEMO[name]["blob"] else None
    pr=e.get("pr_number")
    signal=e.get("signal_run_id")
    if not positive(pr) or not positive(signal):
        return None
    source=api(f"actions/runs/{signal}")
    sha=e["input_commit_sha"]
    need(re.fullmatch("[0-9a-f]{40}",sha) and source["event"]=="pull_request" and source["conclusion"]=="success" and
         source["path"]==SIGNAL and source["head_sha"]==sha and source["head_repository"]["full_name"]==REPO and
         source["workflow_id"]==api("actions/workflows/security-gate-pr.yml")["id"],"PR signal identity")
    need(any(x["number"]==pr and x["head"]["sha"]==sha and x["base"]["ref"]=="main" and
             x["head"]["repo"]["id"]==x["base"]["repo"]["id"]==run["repository"]["id"]
             for x in source["pull_requests"]),"PR association")
    tree=api("git/trees/"+sha)
    dirs=[x for x in tree["tree"] if x["path"]=="terraform" and x["type"]=="tree"]
    if tree["truncated"] or len(dirs)!=1:
        return None
    content=api("git/trees/"+dirs[0]["sha"])
    entries=content["tree"]
    if content["truncated"] or len(entries)!=1 or entries[0]["path"]!="main.tf" or entries[0]["mode"]!="100644":
        return None
    return next((k for k,v in DEMO.items() if v["blob"]==entries[0]["sha"]),None)


def ingest(number,attempt):
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
    need(len(matches)==1,"Exact attempt artifact unavailable")
    art=matches[0]
    provenance=art["workflow_run"]
    need(not art["expired"] and provenance["id"]==number and provenance["head_sha"]==run["head_sha"] and
         provenance["repository_id"]==provenance["head_repository_id"]==run["repository"]["id"],"Artifact provenance")
    jobs=api(f"{prefix}/attempts/{attempt}/jobs")["jobs"]
    need(len(jobs)==1 and jobs[0]["run_attempt"]==attempt and any(x["name"]=="Upload the run record for PASS, REVIEW or ERROR"
         and x["conclusion"]=="success" for x in jobs[0]["steps"]),"Missing trusted upload")
    job=jobs[0]
    need(utc(job["started_at"]) <= utc(art["created_at"]) <= utc(job["completed_at"]),"Artifact outside trusted attempt")
    data=package(api(f"actions/artifacts/{art['id']}/zip",binary=True),art["digest"])
    e=parse(data["execution.json"])
    need((e["github_run_id"],e["github_run_attempt"],e["github_run_number"],e["artifact_name"])==
         (number,attempt,run["run_number"],art["name"]) and e.get("trigger_event",run["event"])==run["event"],"Execution metadata")
    scope=get_scope(e,run)
    if scope is None:
        print("Publication skipped: input outside approved demo scope or missing linkage")
        return
    g=parse(data["gate-result.json"]) if "gate-result.json" in data else None
    export=digest(data["gate-result.json"]) if g is not None else None
    need(export==e.get("gate_result_sha256"),"Export checksum")
    if e.get("trigger_event") is None and g is None:
        e["trigger_event"]=run["event"]
    if e["trigger_event"]=="workflow_run":
        need(e.get("business_context")==dict(environment="dev",asset_criticality="low",data_sensitivity="low"),"PR context")
    result=record(e,g,scope,digest(data["execution.json"]),export)
    outputs(ready="yes",payload=packed(result),pr=e.get("pr_number") or "")


def comment_body(r,online):
    e=r["execution"];g=r["result"];n=e["github_run_id"];a=e["github_run_attempt"]
    ctx=e.get("business_context") or {}
    counts=e.get("counts") or {}
    lines=[MARK,f"<!-- ci4e {n} {a} -->","## Security Gate · ADVISORY_ONLY",
           f"Gate **{e['gate_status'] or 'N/A'}** · Wrapper **{e['wrapper_status']}** · Scan hoàn tất: {e['scan_complete']} · Bước lỗi: {e['failure_stage'] or 'N/A'}",
           "Bối cảnh: "+" / ".join(ctx.get(k,"N/A") for k in ("environment","asset_criticality","data_sensitivity")),
           "Failed / scored / unsupported / unscorable: "+" / ".join(str(counts.get(k,"N/A")) for k in
           ("failed_findings_total","supported_findings","unsupported_findings","unscorable_findings"))]
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


def feedback(r,online,call=api):
    e=r["execution"];pr=e["pr_number"]
    if pr is None:
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
