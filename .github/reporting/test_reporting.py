"""CI-4 tests. CI4_ACCEPTANCE_ROOT and CI4_HOSTED_PARENT enable local evidence tests."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import generate_report as report
from render import html_report

ARCHIVE = "975ae49a69a61af6e06d64c081368d31ed0308856677f2e7a64fadb97d76d434"
RUNTIME = "bfb442e830511c657520d1477931593564459e29"
HOSTED = {
    45356485816: ("PASS", 0, "b7e76fe71538faacfcb17adfe459a93bdb290d7d178cdbc523943242d7ee4a9b"),
    45357318830: ("REVIEW", 10, "bf03ac1fc2f8b2d525ded78eebc73f08fbcc8a9ff0793361bc5d484a5a14eba2"),
    45357333044: ("ERROR", 20, "277951bf0b4faba7e6fefceef104e1b91ca78fa04b5f279095b5d3cf89e439e3"),
}


class HistoryTests(unittest.TestCase):
    def test_names(self):
        row = dict(started_utc="2026-11-24T08:29:05Z", github_run_id=1, github_run_attempt=1)
        name = report.history_name(row)
        self.assertEqual(name, "security-gate-20261124T082905Z_run-1_attempt-1")
        self.assertNotEqual(name, report.history_name(dict(row, github_run_id=2)))
        self.assertNotEqual(name, report.history_name(dict(row, github_run_attempt=2)))

    def test_escape_and_offline(self):
        attack = '<img src=x onerror="alert(1)">'
        html = html_report(dict(wrapper_status="ERROR", wrapper_exit_code=20, failure_stage=attack), None, None, None)
        self.assertNotIn(attack, html)
        self.assertIn("&lt;img", html)
        self.assertIn("default-src 'none'", html)
        self.assertNotIn("<script", html)
        self.assertNotIn('src="https:', html)

    @unittest.skipUnless(os.getenv("CI4_HOSTED_PARENT"), "requires the original CI-3B3 metadata")
    def test_three_historical_executions_without_invented_details(self):
        found = set()
        for path in Path(os.environ["CI4_HOSTED_PARENT"]).glob("ci3b3-verified-*/execution.json"):
            data = path.read_bytes()
            record = json.loads(data)
            run = record["github_run_id"]
            if run not in HOSTED:
                continue
            state, exit_code, digest = HOSTED[run]
            self.assertEqual(hashlib.sha256(data).hexdigest(), digest)
            self.assertEqual(path.with_suffix(".json.sha256").read_text(), digest + "  execution.json\n")
            self.assertEqual((record["gate_status"], record["wrapper_exit_code"]), (state, exit_code))
            self.assertEqual(record["model_sha256"], report.gate.MODEL_SHA)
            self.assertEqual(record["trusted_runtime_commit_sha"], RUNTIME)
            html = html_report(record, None, digest, None)
            self.assertIn(state, html)
            self.assertIn("Không có chi tiết đã xác minh", html)
            self.assertNotIn("0.009356", html)
            found.add(run)
        self.assertEqual(found, set(HOSTED))

    def test_context_profiles_are_dispatch_only(self):
        choose = lambda env: report.gate.trusted_context(env)[:2]
        self.assertEqual(choose({}), ("CTX01", ("dev", "low", "low")))
        values = {"FIXTURE": "ci5", "CI_CONTEXT_PROFILE": "CTX08"}
        self.assertEqual(choose(dict(values, GITHUB_EVENT_NAME="workflow_run")),
                         ("CTX01", ("dev", "low", "low")))
        self.assertEqual(choose(dict(values, GITHUB_EVENT_NAME="workflow_dispatch")),
                         ("CTX08", ("prod", "high", "high")))
        for fixture, profile in (("review", "CTX08"), ("ci5", "invalid")):
            with self.assertRaises(ValueError):
                choose(dict(GITHUB_EVENT_NAME="workflow_dispatch", FIXTURE=fixture,
                            CI_CONTEXT_PROFILE=profile))

    def test_pr_signal_uses_matching_head_sha(self):
        from contextlib import redirect_stdout
        from io import StringIO
        head = {"sha": "1" * 40, "repo": {"id": 5}}
        base = {"ref": "main", "repo": {"id": 5}}
        pr = {"number": 42, "head": head, "base": base}
        run = {"event": "pull_request", "conclusion": "success",
               "path": ".github/workflows/security-gate-pr.yml", "head_repository": {"id": 5},
               "head_sha": head["sha"], "pull_requests": [pr]}
        event = {"workflow_run": run, "repository": {"id": 5, "default_branch": "main"}}
        with tempfile.TemporaryDirectory() as folder:
            payload = Path(folder) / "event.json"
            with patch.dict(os.environ, GITHUB_EVENT_PATH=str(payload)), redirect_stdout(StringIO()) as out:
                payload.write_text(json.dumps(event))
                report.gate.resolve_pr()
                self.assertEqual(out.getvalue(), f"sha={head['sha']}\nnumber=42\n")
                # A new signal must carry a matching new head after synchronize.
                head["sha"] = "2" * 40
                payload.write_text(json.dumps(event))
                with self.assertRaises(ValueError):
                    report.gate.resolve_pr()
                run["head_sha"] = head["sha"]
                payload.write_text(json.dumps(event))
                report.gate.resolve_pr()
                self.assertTrue(out.getvalue().endswith(f"sha={head['sha']}\nnumber=42\n"))
                head["repo"]["id"] = 6
                payload.write_text(json.dumps(event))
                with self.assertRaises(ValueError):
                    report.gate.resolve_pr()

    def test_final_wrapper_step(self):
        import yaml
        workflow = yaml.safe_load((HERE.parent / "workflows/security-gate.yml").read_text())
        job = workflow["jobs"]["advisory"]["steps"]
        final = job[-1]["run"]
        with tempfile.TemporaryDirectory() as tmp:
            for outcome, gate_exit, final_exit in (("success","0",0), ("success","10",10),
                                                   ("success","20",20), ("failure","0",20), ("skipped","10",20)):
                env = dict(os.environ, UPLOAD_OUTCOME=outcome, ADVISORY_EXIT=gate_exit,
                           GITHUB_STEP_SUMMARY=str(Path(tmp) / "summary"))
                self.assertEqual(subprocess.run(["bash","-eu","-c",final],env=env).returncode, final_exit)
        upload = next(step for step in job if step.get("id") == "upload")
        self.assertEqual(upload["with"]["retention-days"], 30)
        self.assertFalse(upload["with"]["overwrite"])
        self.assertNotIn("RAW_DIR", upload["with"]["path"])


@unittest.skipUnless(os.getenv("CI4_ACCEPTANCE_ROOT"), "requires verified local Gate fixture outputs and venv")
class GateReportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = Path(os.environ["CI4_ACCEPTANCE_ROOT"])

    def generate(self, name="review", raw=None, code=None, event="workflow_dispatch"):
        dest = self.base / "artifact"
        env = dict(os.environ, BUNDLE_DIR=str(self.root/"bundle"), RAW_DIR=str(raw or self.root/(name+"-output")),
                   GATE_EXIT={"pass":"0","review":"10","error":"20"}.get(name,"") if code is None else code,
                   STARTED_UTC="2026-11-24T08:29:05Z", RUNTIME_SHA=RUNTIME, RUNTIME_ARCHIVE_SHA=ARCHIVE,
                   GITHUB_EVENT_NAME=event, GITHUB_REF="refs/heads/main", GITHUB_SHA=RUNTIME, PR_SHA=RUNTIME,
                   FIXTURE=name, ARCHIVE_OUTCOME="success", GITHUB_RUN_ID="7", GITHUB_RUN_ATTEMPT="2",
                   GITHUB_RUN_NUMBER="5")
        proc = subprocess.run([str(self.root/"bundle/runtime/.venv/bin/python"),"-I","-B",str(HERE/"generate_report.py"),
                               "--output",str(dest)],env=env,check=True,capture_output=True,text=True)
        record = json.loads((dest/"execution.json").read_bytes())
        self.assertEqual(str(record["wrapper_exit_code"]), proc.stdout.strip())
        subprocess.run(["sha256sum","--strict","--check","checksums.sha256"],cwd=dest,check=True,capture_output=True)
        safe = dest / "gate-result.json"
        if not safe.exists():
            self.assertFalse(safe.with_suffix(".json.sha256").exists())
            return record, None
        self.assertEqual(report.gate.sha(safe.read_bytes()), record["gate_result_sha256"])
        self.assertNotEqual(record["gate_result_sha256"],record["gate_json_sha256"])
        return record,json.loads(safe.read_bytes())

    def change(self, edit=None, bad_checksum=False, raw_edit=None):
        source = json.loads((self.root/"review-output/gate.json").read_bytes())
        if edit:
            edit(source)
        data = json.dumps(source).encode()
        if raw_edit:
            data = raw_edit(data)
        (self.base/"gate.json").write_bytes(data)
        digest = "0"*64 if bad_checksum else report.gate.sha(data)
        (self.base/"gate.json.sha256").write_text(digest+"  gate.json\n")
        return self.base

    def rejected(self, raw, code=None):
        rec, result = self.generate(raw=raw,code=code)
        self.assertIsNone(result)
        self.assertIsNone(rec["gate_status"])
        self.assertEqual((rec["wrapper_exit_code"],rec["failure_stage"]), (20,"GATE_OUTPUT_VERIFICATION"))

    def test_pass(self):
        rec,result = self.generate("pass")
        self.assertTrue(rec["scan_complete"])
        self.assertEqual((rec["wrapper_status"],result["counts"]["failed_findings_total"]),("PASS",0))
        self.assertIn("quét đã hoàn tất",(self.base/"artifact/report.html").read_text())

    def test_review_scores_ranks_unsupported(self):
        rec,result = self.generate()
        self.assertEqual(rec["wrapper_exit_code"],10)
        original = json.loads((self.root/"review-output/gate.json").read_bytes())
        row = result["ranked_supported_findings"][0]
        for key in ("finding_id","priority_score","priority_rank_expected","priority_tie_group_size","context_features"):
            self.assertEqual(row[key],original["ranked_supported_findings"][0][key])
        self.assertIn(str(row["priority_score"]),(self.base/"artifact/report.html").read_text())
        self.assertIsNone(result["unsupported_findings"][0]["priority_score"])
        self.assertEqual(result["unsupported_findings"][0]["unsupported_reason"],"UNSUPPORTED_RULE")

    def test_error(self):
        rec,result = self.generate("error")
        self.assertFalse(rec["scan_complete"])
        self.assertEqual((rec["gate_status"],rec["wrapper_exit_code"]),("ERROR",20))
        self.assertEqual(result["execution_status"]["terraform_validate"],"error")
        self.assertEqual(rec["model_trust_status"],"not_verified")

    def test_bootstrap(self):
        rec,result = self.generate("error",code="")
        self.assertIsNone(result)
        self.assertEqual(rec["failure_stage"],"TRUST_OR_PR_RESOLUTION")
        self.assertIsNone(rec["gate_exit_code"])

    def test_missing_json(self):
        self.rejected(self.base)

    def test_checksum(self):
        self.rejected(self.change(bad_checksum=True))

    def test_duplicate_key(self):
        self.rejected(self.change(raw_edit=lambda b:b.replace(b'{"schema_version"',b'{"exit_code":10,"schema_version"',1)))

    def test_non_finite_score(self):
        self.rejected(self.change(lambda d:d["ranked_supported_findings"][0].update(priority_score=float("nan"))))

    def test_overflow_in_unpublished_field(self):
        self.rejected(self.change(raw_edit=lambda b:b.replace(b'{"schema_version"',b'{"unused":1e999,"schema_version"',1)))

    def test_malformed_json(self):
        self.rejected(self.change(raw_edit=lambda b:b[:-2]))

    def test_bad_model(self):
        self.rejected(self.change(lambda d:d["model_provenance"].update(deployment_model_id="other")))

    def test_status_process_mismatch(self):
        self.rejected(self.change(),code="0")

    def test_bad_context_profile(self):
        self.rejected(self.change(lambda d: d["business_context"].update(context_profile_id="CTX08")))

    def test_bad_counts(self):
        self.rejected(self.change(lambda d:d["counts"].update(failed_findings_total=99)))

    def test_fabricated_unsupported_score(self):
        self.rejected(self.change(lambda d:d["unsupported_findings"][0].update(priority_score=0)))

    def test_ties_and_order(self):
        def tied(d):
            first = d["ranked_supported_findings"][0]
            first.update(priority_rank_expected=1.5,priority_tie_group_size=2)
            other = dict(first, finding_id="0"*64)
            third = dict(first, finding_id="1"*64, priority_score=0, priority_rank_expected=3,priority_tie_group_size=1)
            d["ranked_supported_findings"] = [third,first,other]
            d["counts"].update(supported_findings=3,failed_findings_total=4)
        _,result = self.generate(raw=self.change(tied))
        self.assertEqual([r["priority_rank_expected"] for r in result["ranked_supported_findings"]],[1.5,1.5,3])
        self.assertEqual(result["ranked_supported_findings"][0]["finding_id"],"0"*64)

    def test_sensitive_fields_and_optional_location(self):
        secret = "TEST_SECRET_123456789012"
        def inject(d):
            row = d["ranked_supported_findings"][0]
            row.update(resource=secret,source_path="/home/test/"+secret, check_name="<img onerror="+secret+">")
            d["input"]["terraform_files"].append(row["source_path"])
            d["execution_status"]["checkov_scan"]["stderr"] = secret
            d["unsupported_findings"][0]["unsupported_detail"] = secret
            d["warnings"].append({"environment":secret})
        _, result = self.generate(raw=self.change(inject),event="workflow_run")
        row = result["ranked_supported_findings"][0]
        self.assertTrue(all(row[k] is None for k in ("resource","source_path","check_name","line_start","line_end")))
        for p in (self.base/"artifact").iterdir():
            self.assertNotIn(secret.encode(),p.read_bytes())

    def test_renderer_failure_preserves_verified_gate(self):
        rec,result = self.generate()
        doc=json.loads((self.root/"review-output/gate.json").read_bytes())
        from types import SimpleNamespace
        args=SimpleNamespace(output=self.base/"diagnostic",bundle=self.root/"bundle")
        with patch.object(report,"prepare",return_value=(rec,doc)), patch.object(report,"html_report",side_effect=ValueError("fixture")):
            observed=report.generate(args,{})
        self.assertEqual((observed["gate_status"],observed["wrapper_exit_code"],observed["failure_stage"]),
                         ("REVIEW",20,"REPORT_GENERATION"))
        self.assertFalse((args.output/"gate-result.json").exists())
        self.assertTrue((args.output/"checksums.sha256").exists())


if __name__ == "__main__":
    unittest.main()
