"""Local publication acceptance. CI4_HOSTED_ROOT points to the three downloaded CI-4 archives."""
import copy
import io
from hashlib import sha1
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch, Mock
from zipfile import ZipFile, ZipInfo

sys.path.insert(0,str(Path(__file__).resolve().parent))
import publisher as pub
import build_dashboard as site
from records import *


def git_blob(data):
    header = f"blob {len(data)}\0".encode()
    return dict(sha=sha1(header + data, usedforsecurity=False).hexdigest(), size=len(data),
                encoding="base64", content=pub.base64.b64encode(data).decode())


def pr_tree(sha, files):
    directory = "d" * 40
    entries = []
    responses = {f"git/trees/{sha}": {"truncated": False, "tree": [
        dict(path="terraform", type="tree", mode="040000", sha=directory)]}}
    for filename, data in files.items():
        blob = git_blob(data)
        entries.append(dict(path=filename, sha=blob["sha"], size=blob["size"], mode="100644", type="blob"))
        responses["git/blobs/" + blob["sha"]] = blob
    responses["git/trees/" + directory] = dict(truncated=False, tree=entries)
    return responses


def synthetic(scope):
    """Portable unit sample. Only the optional archive reader below uses hosted bytes."""
    ctx=dict(environment="dev",asset_criticality="low",data_sensitivity="low")
    failed=scope=="error"
    code=EXIT[scope.upper()]
    rid={"pass":1,"review":2,"error":3}[scope]
    scored=[];other=[]
    if scope=="review":
        features=dict(ctx,internet_exposure="not_applicable",reachability="not_applicable",
                      privilege_impact="not_applicable",resource_role="network",logging_missing="yes",
                      public_access="not_applicable",wildcard_action="not_applicable",
                      wildcard_resource="not_applicable",encryption_missing="not_applicable")
        for rule,desc in LEGACY[scope]["descriptors"].items():
            supported=rule=="CKV2_AWS_11"
            row=dict(finding_id=("1" if supported else "2")*64,check_id=rule,check_name=desc[0],
                     resource_type=desc[1],resource=desc[2],source_path=desc[3],line_start=1,line_end=2,
                     classification="scored" if supported else "unsupported_rule",
                     severity_numeric=2 if supported else None,context_features=features if supported else None,
                     priority_score=0.009356597052396097 if supported else None,
                     priority_rank_expected=1.0 if supported else None,priority_tie_group_size=1 if supported else None,
                     unsupported_reason=None if supported else "UNSUPPORTED_RULE")
            (scored if supported else other).append(row)
    counts=dict(failed_findings_total=len(scored)+len(other),supported_findings=len(scored),
                unsupported_findings=len(other),unscorable_findings=0)
    stages={k:"success" for k in STAGES}
    if failed:stages.update(terraform_validate="error",checkov_scan="not_run",feature_extraction="not_run",model_scoring="not_run")
    g=dict(schema_version="ci4-advisory-gate-result-v1",source_gate_json_sha256="a"*64,gate_status=scope.upper(),
           gate_exit_code=code,counts=counts,execution_status=stages,ranked_supported_findings=scored,unsupported_findings=other)
    export=digest(site.canonical(g))
    e=dict(schema_version="ci4-advisory-execution-v1",enforcement="ADVISORY_ONLY",started_utc="2026-01-01T00:00:00Z",
           finished_utc="2026-01-01T00:01:00Z",github_run_id=rid,github_run_number=rid,github_run_attempt=1,
           artifact_name=f"security-gate-20260101T000000Z_run-{rid}_attempt-1",execution_origin="github_actions",
           trigger_event="workflow_dispatch",workflow_ref="refs/heads/main",pr_number=None,input_commit_sha="a"*40,
           scanned_commit_sha=None if failed else "a"*40,trusted_runtime_commit_sha=RUNTIME,release_id="ci-gate-v1",
           manifest_sha256=MANIFEST,model_sha256=MODEL,business_context=ctx,gate_status=scope.upper(),gate_exit_code=code,
           process_exit_code=code,wrapper_status=scope.upper(),wrapper_exit_code=code,failure_stage="GATE" if failed else None,
           gate_json_sha256="a"*64,gate_result_sha256=export,counts=counts,scan_complete=not failed,runtime_archive_sha256=ARCHIVE,
           deployment_model_id=MODEL_ID,model_trust_status="not_verified" if failed else "verified",context_profile_id="CTX01",
           terraform_artifact_sha256=LEGACY[scope]["input"],fixture_expectation="PASS")
    return record(e,g,scope,digest(site.canonical(e)),export)


def samples():
    root=Path(os.environ.get("CI4_HOSTED_ROOT","docs/ci4_hosted_acceptance/6597c7e"))
    for scope in ("pass","review","error"):
        if not root.is_dir():
            yield scope,synthetic(scope)
            continue
        path,=list((root/scope).glob("*/artifact.zip"))
        metadata=parse(path.with_name("github-metadata.json").read_bytes())
        data=package(path.read_bytes(),metadata["artifact"]["digest"])
        e=parse(data["execution.json"])
        # Replay old artifacts locally with the new input attestation. Never send this to GitHub.
        e.update(terraform_artifact_sha256=LEGACY[scope]["input"],publication_fixture=scope)
        g=parse(data["gate-result.json"])
        yield scope,record(e,g,scope,digest(data["execution.json"]),digest(data["gate-result.json"]))


class PublishingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.samples=dict(samples())

    def setUp(self):
        self.r=copy.deepcopy(self.samples["review"])
        self.e=self.r["execution"]
        self.g=self.r["result"]

    def test_all_gate_states(self):
        records={}
        with tempfile.TemporaryDirectory() as tmp:
            for scope,r in self.samples.items():
                path=site.insert(records,r)
                site.build(records,Path(tmp))
                self.assertIn(r["execution"]["gate_status"],(Path(tmp)/path).with_name("report.html").read_text())
            history=parse((Path(tmp)/"history.json").read_bytes())["records"]
            self.assertEqual(len(history),3)
            self.assertTrue(all((Path(tmp)/v["report_url"]).is_file() for v in history))
            self.assertEqual({v["gate_status"] for v in history},set(EXIT))

    def test_diagnostic(self):
        for k in ("scan_complete","counts","gate_exit_code","gate_status","gate_json_sha256","gate_result_sha256","scanned_commit_sha"):
            self.e[k]=None
        self.e.update(failure_stage="TOOLCHAIN_PROVISION",wrapper_status="ERROR",wrapper_exit_code=20)
        validate(self.e,None,"review")

    def test_renderer_error_keeps_verified_gate_without_details(self):
        self.e.update(wrapper_status="ERROR",wrapper_exit_code=20,failure_stage="REPORT_GENERATION",gate_result_sha256=None)
        r=record(self.e,None,"review","a"*64,None)
        self.assertEqual(r["execution"]["gate_status"],"REVIEW")
        self.assertIsNone(r["result"])

    def test_schema_model_counts_ties(self):
        for k,v in [("schema_version","v0"),("gate_exit_code",0),("model_sha256","0"*64),("trusted_runtime_commit_sha","0"*40),
                    ("github_run_attempt",0),("business_context",{}),("terraform_artifact_sha256","0"*64)]:
            with self.subTest(k=k),self.assertRaises(ValueError):
                validate(dict(self.e,**{k:v}),self.g,"review")
        for k,v in [("priority_score",float("inf")),("priority_tie_group_size",3),("priority_rank_expected",2),
                    ("check_name","<img onerror=1>"),("resource","arn:aws:iam::123456789012:root"),
                    ("source_path","[open](https://invalid)")]:
            g=copy.deepcopy(self.g);g["ranked_supported_findings"][0][k]=v
            with self.subTest(k=k),self.assertRaises(Exception):
                validate(self.e,g,"review")
        with self.assertRaises(ValueError):
            validate(dict(self.e,counts={}),self.g,"review")

    def test_zip(self):
        root=Path(os.environ.get("CI4_HOSTED_ROOT","docs/ci4_hosted_acceptance/6597c7e"))
        if root.is_dir():
            blob=next((root/"review").glob("*/artifact.zip")).read_bytes()
        else:
            pieces={"execution.json":site.canonical(self.e),"gate-result.json":site.canonical(self.g),
                    "report.html":b"test","report.md":b"test"}
            for name in ("execution.json","gate-result.json"):
                pieces[name+".sha256"]=(digest(pieces[name])+"  "+name+"\n").encode()
            pieces["checksums.sha256"]="".join(digest(v)+"  "+k+"\n" for k,v in pieces.items()).encode()
            out=io.BytesIO()
            with ZipFile(out,"w") as z:
                for k,v in pieces.items():z.writestr(k,v)
            blob=out.getvalue()
        with self.assertRaises(ValueError):package(blob,"sha256:"+"0"*64)
        for mutant in ("traversal","symlink","manifest","extra","oversize"):
            out=io.BytesIO()
            with ZipFile(io.BytesIO(blob)) as src, ZipFile(out,"w") as dst:
                for name in src.namelist():
                    body=src.read(name)
                    info=ZipInfo("../report.html" if mutant=="traversal" and name=="report.html" else name)
                    if mutant=="symlink" and name=="report.html":info.external_attr=(stat.S_IFLNK|0o777)<<16
                    if mutant=="manifest" and name=="report.md":body+=b"tampered"
                    if mutant=="oversize" and name=="report.md":body=b"x"*2_000_001
                    dst.writestr(info,body)
                if mutant=="extra":dst.writestr("extra","")
            b=out.getvalue()
            with self.subTest(mutant=mutant),self.assertRaises(ValueError):package(b,"sha256:"+digest(b))

    def test_idempotent_conflict_and_rerun(self):
        records={}
        first=site.insert(records,self.r)
        self.assertEqual(site.insert(records,self.r),first)
        clash=copy.deepcopy(self.r);clash["execution_digest"]="0"*64
        with self.assertRaises(ValueError):site.insert(records,clash)
        rerun=copy.deepcopy(self.r);rerun["execution"]["github_run_attempt"]=2
        rerun["execution"]["artifact_name"]=self.e["artifact_name"].replace("attempt-1","attempt-2")
        self.assertNotEqual(first,site.insert(records,rerun))
        self.assertEqual(len(records),2)

    def test_push_retry(self):
        competing = {}
        site.insert(competing, self.samples["pass"])
        snapshots = [({}, {}), (competing, {})]
        with tempfile.TemporaryDirectory() as tmp, patch.object(site, "git", return_value=b""), patch.object(
            site, "snapshot", side_effect=snapshots
        ), patch.object(site.subprocess, "run", side_effect=[Mock(returncode=1), Mock(returncode=0)]) as push:
            site.publish(Path(tmp), self.r)
            self.assertEqual(push.call_count, 2)
            self.assertFalse(any("--force" in call.args[0] for call in push.call_args_list))
            history = parse((Path(tmp) / "history.json").read_bytes())["records"]
            self.assertEqual({row["gate_status"] for row in history}, {"PASS", "REVIEW"})
            self.assertTrue(all((Path(tmp) / row["report_url"]).is_file() for row in history))

    def test_manual_recovery_and_provenance(self):
        run=dict(id=10,run_attempt=2,workflow_id=11,path=pub.GATE,status="completed",event="workflow_dispatch",head_branch="main",repository={"full_name":REPO},head_repository={"full_name":REPO},head_sha="a"*40)
        pub.accepted_run(run,10,2,11)
        for k,v in [("id",9),("run_attempt",1),("path","other"),("head_branch","feature"),("workflow_id",12),("event","pull_request")]:
            with self.subTest(k=k),self.assertRaises(ValueError):
                pub.accepted_run(dict(run,**{k:v}),10,2,11)
        source = b'terraform {}\n'
        with patch.object(pub,"api",return_value={**git_blob(source), "type": "file"}):
            resolved = pub.resolve_input_digest(dict(publication_fixture="review",input_commit_sha="a"*40),run)
            self.assertEqual(resolved, pub.artifact_digest([("main.tf", source)]))
        with self.assertRaises(pub.PublicationSkipped):
            pub.resolve_input_digest({},run)

    def test_feedback(self):
        for case,want in [("create","POST"),("user-marker","POST"),("update","PATCH"),("stale",None),
                          ("newer",None),("closed",None),("fixture",None),("pages-failure","POST")]:
            with self.subTest(case=case):
                self.e["pr_number"]=None if case=="fixture" else 7
                self.e["trigger_event"]="workflow_dispatch" if case=="fixture" else "workflow_run"
                who={"login":"github-actions[bot]","id":41898282}
                comments=[]
                if case in {"user-marker","update","newer"}:
                    n=self.e["github_run_id"]+(1 if case=="newer" else 0)
                    comments=[dict(body=f"{pub.MARK}\n<!-- ci4e {n} 1 -->",user=who if case!="user-marker" else {"id":4,"login":"dev"},id=8)]
                writes=[]
                def call(path,**kw):
                    if kw:writes.append(kw);return
                    if path.startswith("issues/"):return comments
                    return dict(state="closed" if case=="closed" else "open",head=dict(sha="0"*40 if case=="stale" else self.e["input_commit_sha"],repo={"full_name":REPO}),base=dict(ref="main",repo={"full_name":REPO}))
                pub.feedback(self.r,case!="pages-failure",call)
                self.assertEqual([w["method"] for w in writes],[want] if want else [])
                if writes:
                    body=writes[0]["payload"]["body"]
                    self.assertIn("0.009356597052396097",body)
                    self.assertIn("UNSUPPORTED".lower(),body)
                    self.assertEqual(pub.SITE in body,case!="pages-failure")

    def test_recovery_ingests_same_artifact_and_refuses_wrong_attempt(self):
        from zipfile import ZIP_DEFLATED
        file = (HERE.parent / "ci_gate_fixtures/review/main.tf").read_bytes()
        e = dict(self.e, publication_fixture="review",
                 terraform_artifact_sha256=pub.artifact_digest([("main.tf", file)]))
        data={"execution.json":site.canonical(e),"gate-result.json":site.canonical(self.g),
              "report.md":b"[unsafe](https://invalid)", "report.html":b"<script>unsafe()</script>"}
        e["gate_result_sha256"]=digest(data["gate-result.json"])
        data["execution.json"]=site.canonical(e)
        for name in ("gate-result.json","execution.json"):
            data[name+".sha256"]=(digest(data[name])+"  "+name+"\n").encode()
        data["checksums.sha256"]="".join(digest(b)+"  "+n+"\n" for n,b in data.items()).encode()
        out=io.BytesIO()
        with ZipFile(out,"w",ZIP_DEFLATED) as zipfile:
            for name,body in data.items():zipfile.writestr(name,body)
        blob=out.getvalue()
        rid=e["github_run_id"]
        sha=e["input_commit_sha"]
        prefix=f"actions/runs/{rid}"
        repo={"full_name":REPO,"id":123}
        run=dict(id=rid,run_attempt=1,run_number=e["github_run_number"],workflow_id=4,path=pub.GATE,
                 status="completed",event="workflow_dispatch",head_branch="main",head_sha=sha,
                 repository=repo,head_repository=repo)
        art=dict(id=5,name=e["artifact_name"],created_at=e["finished_utc"],expired=False,digest="sha256:"+digest(blob),
                 workflow_run=dict(id=rid,head_sha=sha,repository_id=123,head_repository_id=123))
        responses={prefix+"/attempts/1":run,"actions/workflows/security-gate.yml":{"id":4},
                   f"compare/{sha}...{sha}":{"status":"identical"},
                   prefix+"/artifacts?per_page=100":{"total_count":1,"artifacts":[art]},
                   prefix+"/attempts/1/jobs":{"jobs":[dict(run_attempt=1,started_at=e["started_utc"],completed_at=e["finished_utc"],
                   steps=[dict(name="Upload the run record for PASS, REVIEW or ERROR",conclusion="success")])]},
                   "actions/artifacts/5/zip":blob,f"contents/.github/ci_gate_fixtures/review/main.tf?ref={sha}":{**git_blob(file), "type": "file"}}
        with patch.object(pub,"api",side_effect=lambda path,**kw:responses[path]),patch.object(pub,"outputs") as output,patch.dict(os.environ,GITHUB_SHA=sha):
            pub.ingest(rid,1)
            body=parse(pub.base64.b64decode(output.call_args.kwargs["payload"]))
            self.assertNotIn("unsafe",str(body))
            self.assertEqual(body["execution"]["gate_status"],"REVIEW")
            self.assertEqual(body["scope"], PUBLIC_SCOPE)
            self.assertTrue(all(row[key] is None for key in REDACTED_FIELDS
                                for row in body["result"]["ranked_supported_findings"]))
            self.assertEqual(body["export_digest"], e["gate_result_sha256"])
            path = f"contents/.github/ci_gate_fixtures/review/main.tf?ref={sha}"
            responses[path] = {**git_blob(file + b"\n"), "type": "file"}
            with self.assertRaisesRegex(ValueError, "differs from the evaluated revision"):
                pub.ingest(rid, 1)
            # A disallowed input yields a safe diagnostic and leaves the verified Gate artifact alone.
            reason = "Terraform directory contains an unsupported tree entry."
            responses[path] = {**git_blob(file), "type": "file"}
            with patch.object(pub, "resolve_input_digest", side_effect=pub.PublicationSkipped(reason)), \
                 patch.object(pub, "skip_notice") as notice:
                pub.ingest(rid, 1)
                notice.assert_called_once_with(reason)
                self.assertEqual(output.call_count, 1)
            art["workflow_run"]["id"]+=1
            with self.assertRaises(ValueError):pub.ingest(rid,1)
            self.assertEqual(output.call_count,1)

    def test_pr_digest_bound_to_signal_supports_unregistered_multifile_input(self):
        run = {"event":"workflow_run", "repository":{"id":3}}
        sha = self.e["input_commit_sha"]
        signal = dict(event="pull_request", conclusion="success", path=pub.SIGNAL, head_sha=sha, workflow_id=12,
                      head_repository={"full_name":REPO}, pull_requests=[dict(number=9, head=dict(sha=sha, repo={"id":3}),
                      base=dict(ref="main", repo={"id":3}))])
        files = {"network.tf": b"# arbitrary source bytes", "providers.tf": b"terraform {}"}
        responses = pr_tree(sha, files)
        responses.update({"actions/runs/8":signal, "actions/workflows/security-gate-pr.yml":{"id":12}})
        e = dict(self.e, signal_run_id=8, pr_number=9)
        with patch.object(pub,"api",side_effect=responses.__getitem__):
            resolved = pub.resolve_input_digest(e,run)
            self.assertEqual(resolved, pub.artifact_digest(files.items()))
            self.assertNotIn(resolved, {row["input"] for row in LEGACY.values()})
            with self.assertRaises(ValueError):
                pub.resolve_input_digest(dict(e,pr_number=99),run)
            table = responses["git/trees/" + "d"*40]["tree"]
            for mode, name in [("120000","symlink.tf"), ("040000","nested"), ("100644","vars.tfvars"),
                               ("100644","name with space.tf")]:
                with self.subTest(mode=mode,name=name):
                    table.append(dict(type="blob",mode=mode,path=name,size=1))
                    with self.assertRaises(pub.PublicationSkipped):
                        pub.resolve_input_digest(e,run)
                    table.pop()
            oid = table[0]["sha"]
            responses["git/blobs/"+oid]["content"] = pub.base64.b64encode(b"x" * table[0]["size"]).decode()
            with self.assertRaisesRegex(ValueError, "differs from GitHub object identity"):
                pub.resolve_input_digest(e,run)

    def test_public_projection_is_strict_and_history_keeps_original_bytes(self):
        prior = self.r
        projected = public_projection(prior["result"])
        public = record(dict(prior["execution"], publication_fixture="review"), projected, PUBLIC_SCOPE,
                        prior["execution_digest"], prior["export_digest"])
        self.assertNotEqual(projected, prior["result"])
        records = {}
        key = site.insert(records, prior)
        self.assertEqual(site.insert(records, public), key)
        self.assertEqual(records[key], prior)
        malicious = copy.deepcopy(projected)
        malicious["ranked_supported_findings"][0]["check_name"] = "synthetic secret"
        with self.assertRaisesRegex(ValueError, "source details"):
            record(public["execution"], malicious, PUBLIC_SCOPE, public["execution_digest"], public["export_digest"])
        malicious["ranked_supported_findings"][0]["secret"] = "synthetic secret"
        with self.assertRaisesRegex(ValueError, "Gate export schema"):
            public_projection(malicious)

    def test_fail_closed_before_feedback(self):
        original=copy.deepcopy(self.e)
        with self.assertRaises(ValueError):
            record(dict(self.e,model_sha256="bad"),self.g,"review","0"*64,"0"*64)
        self.assertEqual(self.e,original)


if __name__=="__main__":
    unittest.main()
