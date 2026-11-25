"""Push signal, exact-source provenance, and advisory publication regressions."""
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from zipfile import ZipFile

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE.parent)]
import build_dashboard as site
import business_context as bc
import ci_gate as gate
import publisher as pub
import push_assessment as push
from records import LEGACY, PUBLIC_SCOPE, digest, parse
from test_publishing import git_blob, pr_tree, synthetic

COMMIT = "c" * 40
CONTROL = "a" * 40
BRANCH = "workload/new-module"
REPO = {"id": 17, "full_name": pub.REPO, "default_branch": "main"}
SIGNAL = dict(event="push", path=push.SIGNAL_PATH, conclusion="success", head_branch=BRANCH,
              head_sha=COMMIT, workflow_id=4, repository=REPO, head_repository=REPO)


class PushTests(unittest.TestCase):
    def test_signal_filter_and_git_tree_delta(self):
        import yaml
        workflow = yaml.safe_load((HERE.parent.parent / push.SIGNAL_PATH).read_text())
        incoming = workflow[True]["push"]
        self.assertEqual(incoming, {"branches": ["**", "!gh-pages"], "paths": ["terraform/**"]})
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        step = workflow["jobs"]["signal"]["steps"][0]["run"]
        with tempfile.TemporaryDirectory() as tmp:
            gh = Path(tmp) / "gh"
            gh.write_text('#!/bin/bash\ncase "$2" in */a*) echo "$OLD_TREE";; *) echo "$NEW_TREE";; esac\n')
            gh.chmod(0o700)
            env = dict(os.environ, PATH=f"{tmp}:{os.environ['PATH']}", DELETED="false",
                       BEFORE="a"*40, AFTER=COMMIT, GITHUB_SHA=COMMIT, GITHUB_REPOSITORY=pub.REPO,
                       OLD_TREE="", NEW_TREE="modified")
            for label, changes, expected in [
                ("new Terraform", {}, 0),
                ("modified Terraform", {"OLD_TREE": "original"}, 0),
                ("unrelated push", {"NEW_TREE": ""}, 1),
                ("branch creation", {"BEFORE": "0"*40}, 0),
                ("deleted branch", {"DELETED": "true"}, 1),
                ("different SHA", {"GITHUB_SHA": "b"*40}, 1),
            ]:
                with self.subTest(label=label):
                    proc = subprocess.run(["bash","-eu","-c",step], env={**env,**changes}, capture_output=True)
                    self.assertEqual(proc.returncode, expected, proc.stderr)

    def test_trusted_event_config_and_exact_head_without_pr(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "event.json"
            path.write_text(json.dumps({"repository": REPO, "workflow_run": SIGNAL}))
            env = dict(GITHUB_EVENT_NAME="workflow_run", GITHUB_REF="refs/heads/main", GITHUB_REPOSITORY=pub.REPO,
                       GITHUB_SHA=CONTROL, GITHUB_EVENT_PATH=str(path), CI_INPUT_ENVIRONMENT="dev")
            wf = (HERE.parent.parent / push.SIGNAL_PATH).read_bytes()
            response = {**git_blob(wf), "type": "file"}
            def fetch(endpoint):
                if endpoint == f"contents/{push.SIGNAL_PATH}?ref={COMMIT}":
                    return response
                self.assertIn("head=phanquan277github%3Aworkload%2Fnew-module", endpoint)
                return []
            self.assertEqual(gate.resolve_push(env, fetch), COMMIT)
            profile, context, info = gate.trusted_context(env)
            raw = (HERE.parent.parent / bc.CONFIG).read_bytes()
            self.assertEqual(context, bc.values(parse(raw)))
            self.assertEqual(profile, bc.PROFILES[context])
            self.assertEqual(info, bc.provenance("automatic_push", CONTROL, config_sha=digest(raw),
                                                 source_branch=BRANCH, expected_head=COMMIT))
            for field, value in [("head_branch", "gh-pages"), ("head_sha", "0"*40), ("event", "pull_request"),
                                 ("conclusion", "failure"), ("head_repository", {"id": 2})]:
                path.write_text(json.dumps({"repository": REPO, "workflow_run": {**SIGNAL, field:value}}))
                with self.subTest(field=field), self.assertRaises(ValueError):
                    gate.resolve_push(env, fetch)
            path.write_text(json.dumps({"repository": REPO, "workflow_run": SIGNAL}))
            eligible = dict(number=7, state="open", head=dict(ref=BRANCH, sha=COMMIT, repo=REPO),
                            base=dict(ref="main", repo=REPO))
            self.assertIsNone(gate.resolve_push(env, Mock(side_effect=[response, [eligible],
                                                                     [{"filename": "terraform/network.tf"}]])))
            self.assertEqual(gate.resolve_push(env, Mock(side_effect=[response, OSError()])), COMMIT)
            response["content"] = git_blob(wf.replace(b"terraform/**", b"docs/**/*"))["content"]
            with self.assertRaisesRegex(ValueError, "differs from trusted main"):
                gate.resolve_push(env, fetch)

    def test_skip_only_when_official_pr_covers_exact_commit_and_path(self):
        pr = dict(number=7, state="open", head=dict(sha=COMMIT, repo=REPO, ref=BRANCH),
                  base=dict(ref="main", repo=REPO))
        for mode in ("eligible", "nonterraform", "different_sha", "fork", "closed", "main"):
            candidate = copy.deepcopy(pr)
            files = [{"filename": "README.md"}]
            if mode != "nonterraform":
                files.append({"filename": "terraform/network.tf"})
            if mode == "different_sha": candidate["head"]["sha"] = "b" * 40
            if mode == "fork": candidate["head"]["repo"] = {"id": 18}
            if mode == "closed": candidate["state"] = "closed"
            fetch = Mock(side_effect=[[candidate],files])
            with self.subTest(mode=mode):
                branch = "main" if mode == "main" else BRANCH
                self.assertEqual(push.has_eligible_pr(fetch, REPO, branch, COMMIT), mode=="eligible")
                if mode == "main":
                    fetch.assert_not_called()

    def test_publisher_accepts_new_multifile_push_and_preserves_history(self):
        files = {"network.tf": b"terraform {}\n", "context.tf": b"# publication unit sample\n"}
        artifact = pub.artifact_digest(files.items())
        self.assertNotIn(artifact, {v["input"] for v in LEGACY.values()})
        legacy = synthetic("review")
        e = dict(legacy["execution"], github_run_id=50, artifact_name=legacy["execution"]["artifact_name"]
                 .replace(f"run-{legacy['execution']['github_run_id']}_", "run-50_"), trigger_event="workflow_run",
                 input_commit_sha=COMMIT, scanned_commit_sha=COMMIT, terraform_artifact_sha256=artifact,
                 signal_run_id=7)
        raw_config = json.dumps(e["business_context"]).encode()
        provenance = bc.provenance("automatic_push", CONTROL, config_sha=digest(raw_config),
                                   expected_head=COMMIT, source_branch=BRANCH)
        e["context_provenance"] = provenance
        g = dict(legacy["result"], context_provenance=provenance, business_context=e["business_context"])
        export = site.canonical(g)
        e["gate_result_sha256"] = digest(export)
        execution = site.canonical(e)
        package = {"gate-result.json":export, "execution.json":execution,
                   "report.html":b"unsafe markup", "report.md":b"unsafe text"}
        for name, blob in [("gate-result.json",export), ("execution.json",execution)]:
            package[name+".sha256"] = f"{digest(blob)}  {name}\n".encode()
        package["checksums.sha256"] = "".join(f"{digest(blob)}  {name}\n" for name, blob in package.items()).encode()
        dst = io.BytesIO()
        with ZipFile(dst,"w") as z:
            for name,blob in package.items(): z.writestr(name,blob)
        archive = dst.getvalue()
        path = "actions/runs/50"
        run = dict(id=50, run_attempt=1, run_number=e["github_run_number"], workflow_id=5, path=pub.GATE,
                   status="completed", event="workflow_run", head_branch="main", head_sha=CONTROL,
                   repository=REPO, head_repository=REPO)
        upload = dict(id=6, name=e["artifact_name"], created_at=e["finished_utc"], expired=False,
                      digest="sha256:"+digest(archive), workflow_run=dict(id=50, head_sha=CONTROL,
                      repository_id=REPO["id"], head_repository_id=REPO["id"]))
        job = dict(run_attempt=1, started_at=e["started_utc"], completed_at=e["finished_utc"],
                   steps=[dict(name="Upload the run record for PASS, REVIEW or ERROR", conclusion="success")])
        endpoints = {**pr_tree(COMMIT,files), path+"/attempts/1":run, "actions/workflows/security-gate.yml":{"id":5},
                     f"compare/{CONTROL}...{CONTROL}":{"status":"identical"},
                     path+"/artifacts?per_page=100":{"total_count":1,"artifacts":[upload]},
                     path+"/attempts/1/jobs":{"jobs":[job]}, "actions/artifacts/6/zip":archive,
                     "actions/runs/7":SIGNAL, "actions/workflows/security-gate-push.yml":{"id":4},
                     f"contents/{bc.CONFIG}?ref={CONTROL}":{**git_blob(raw_config),"type":"file"}}
        with patch.object(pub,"api",side_effect=lambda path, **_: endpoints[path]), patch.object(pub,"outputs") as out, \
             patch.dict(os.environ,GITHUB_SHA=CONTROL):
            pub.ingest(50,1)
            self.assertEqual(out.call_args.kwargs["pr"],"")
            result = parse(pub.base64.b64decode(out.call_args.kwargs["payload"]))
            self.assertEqual(result["scope"],PUBLIC_SCOPE)
            self.assertIsNone(result["execution"]["pr_number"])
            self.assertEqual(result["execution"]["context_provenance"]["source_branch"],BRANCH)
            self.assertNotIn("unsafe",json.dumps(result))
            with self.assertRaisesRegex(ValueError,"Push signal identity"):
                pub.resolve_input_digest(dict(e, input_commit_sha="e"*40),run)
            feedback = Mock()
            pub.feedback(result,True,feedback)
            feedback.assert_not_called()
            with tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp)
                reports={}
                key=site.insert(reports,legacy)
                site.insert(reports,result)
                previous_html=b"HTML already published"
                site.build(reports,root,{key:previous_html})
                self.assertEqual((root/key).read_bytes(),site.canonical(legacy))
                self.assertEqual((root/key).with_name("report.html").read_bytes(),previous_html)
                rows=parse((root/"history.json").read_bytes())["records"]
                self.assertEqual(len(rows),2)
                first=next(row for row in rows if row["github_run_id"]==50)
                self.assertEqual(first["terraform_artifact_sha256"],artifact)
            endpoints[path+"/artifacts?per_page=100"]={"total_count":0,"artifacts":[]}
            run["conclusion"]="success"
            job["steps"]=[dict(name="Skip push covered by the official PR lane",conclusion="success")]
            with patch.object(pub,"skip_notice") as notice:
                pub.ingest(50,1)
                notice.assert_called_once()
            self.assertEqual(out.call_count,1)


if __name__ == "__main__":
    unittest.main()
