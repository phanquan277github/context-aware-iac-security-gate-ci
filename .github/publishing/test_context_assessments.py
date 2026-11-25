"""Regression tests for CI-5C trust boundaries and compatibility."""
import base64
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE.parent), str(HERE.parent / "reporting")]
import build_dashboard as site
import business_context as bc
import ci_gate as gate
import generate_report as report
import publisher as pub
from records import PUBLIC_SCOPE, digest, parse, public_projection, record
from test_publishing import pr_tree, synthetic


class ContextTests(unittest.TestCase):
    def test_context_config_strict_and_ignores_pr_dispatch_values(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(gate, "CONTROL", Path(tmp)/".github"):
            path = Path(tmp) / bc.CONFIG
            path.parent.mkdir()
            env = dict(GITHUB_EVENT_NAME="workflow_run", GITHUB_SHA="a"*40, CI_ASSESSMENT_MODE="on_demand_pr",
                       CI_CONTEXT_PROFILE="CTX08", CI_INPUT_ENVIRONMENT="prod")
            with self.assertRaises(OSError):
                gate.trusted_context(env)
            for content in ('{"environment":"dev"}', 'null',
                            '{"environment":"dev","environment":"prod","asset_criticality":"low","data_sensitivity":"low"}',
                            '{"environment":"development","asset_criticality":"low","data_sensitivity":"low"}'):
                path.write_text(content)
                with self.subTest(content=content), self.assertRaises(ValueError):
                    gate.trusted_context(env)
            for case in [("dev","low","low"), ("prod","high","high"), ("dev","high","low")]:
                value = dict(zip(bc.KEYS, case))
                path.write_text(json.dumps(value))
                self.assertEqual(gate.trusted_context(env), (bc.PROFILES[case], case, bc.provenance(
                    "automatic_pr", "a"*40, config_sha=digest(path.read_bytes()))))

    def test_invalid_configuration_builds_error_diagnostic(self):
        args = SimpleNamespace(commit="c"*40, start="2026-01-01T00:00:00Z", runtime_sha="", exit=-1)
        env = dict(GITHUB_EVENT_NAME="workflow_run", GITHUB_SHA="a"*40, GITHUB_RUN_ID="10", GITHUB_RUN_ATTEMPT="1",
                   CI_PR_NUMBER="2", PINS_OUTCOME="failure")
        with tempfile.TemporaryDirectory() as tmp, patch.object(gate, "CONTROL", Path(tmp)/".github"):
            e, document = report.prepare(args, env)
        self.assertIsNone(document)
        self.assertEqual((e["wrapper_status"], e["wrapper_exit_code"], e["failure_stage"]), ("ERROR",20,"BUSINESS_CONTEXT"))
        self.assertIsNone(e["business_context"])
        self.assertNotIn("context_provenance",e)

    def test_manual_pr_requires_pin_and_trusted_main(self):
        with tempfile.TemporaryDirectory() as tmp:
            payload = Path(tmp) / "event.json"
            payload.write_text(json.dumps({"repository": {"full_name":"org/project", "id":5, "default_branch":"main"}}))
            env = dict(GITHUB_REF="refs/heads/main",GITHUB_EVENT_NAME="workflow_dispatch",GITHUB_EVENT_PATH=str(payload),
                       GITHUB_REPOSITORY="org/project",CI_INPUT_PR="2",CI_EXPECTED_HEAD="c"*40,
                       CI_ASSESSMENT_MODE="on_demand_pr",CI_INPUT_ENVIRONMENT="prod",
                       CI_INPUT_ASSET_CRITICALITY="low",CI_INPUT_DATA_SENSITIVITY="high")
            valid = {"number":2,"state":"open","head":{"repo":{"id":5},"sha":"c"*40},
                     "base":{"ref":"main","repo":{"id":5}}}
            fetch = Mock(return_value=valid)
            self.assertEqual(gate.resolve_manual_pr(env, fetch), ("c"*40, 2))
            fetch.assert_called_once_with("pulls/2")
            self.assertEqual(gate.trusted_context(env)[:2], ("CTX06",("prod","low","high")))
            for path,value in [(("number",),3),(("state",),"closed"),(("head","repo"),{"id":6}),
                               (("head","sha"),"b"*40),(("base","ref"),"demo")]:
                mutant = copy.deepcopy(valid)
                target = mutant if len(path)==1 else mutant[path[0]]
                target[path[-1]]=value
                with self.subTest(path=path), self.assertRaises(ValueError):
                    gate.resolve_manual_pr(env, Mock(return_value=mutant))
            with self.assertRaises(ValueError):
                gate.resolve_manual_pr(dict(env,GITHUB_REF="refs/heads/demo"),fetch)
            with self.assertRaises(ValueError):
                gate.trusted_context(dict(env,CI_INPUT_DATA_SENSITIVITY="medium"))

    def review(self, kind):
        r = synthetic("review")
        e,g = r["execution"],r["result"]
        revision, selected = "b"*40, "a"*40
        arguments = dict(expected_head=selected) if kind=="on_demand_pr" else dict(config_sha=digest(b"{}"))
        e.update(pr_number=2, trigger_event="workflow_dispatch" if kind=="on_demand_pr" else "workflow_run",
                 context_provenance=bc.provenance(kind, revision, **arguments))
        g.update(context_provenance=e["context_provenance"], business_context=e["business_context"])
        return r

    def test_same_repo_manual_provenance_does_not_write_feedback(self):
        r = self.review("on_demand_pr")
        e = r["execution"]
        run = {"event":"workflow_dispatch","head_sha":"b"*40,"repository":{"id":5}}
        pub.validate_context_origin(e,run)
        expected_pr = {"number":2,"base":{"ref":"main","repo":{"id":5}},"head":{"repo":{"id":5},"sha":"c"*40}}
        files = {"network.tf": b"terraform {}"}
        paths = {"pulls/2": expected_pr, **pr_tree("a"*40, files)}
        with patch.object(pub,"api",side_effect=paths.__getitem__):
            self.assertEqual(pub.resolve_input_digest(e,run), pub.artifact_digest(files.items()))
            expected_pr["head"]["repo"]["id"] = 6
            with self.assertRaises(ValueError):
                pub.resolve_input_digest(e,run)
        with self.assertRaises(ValueError):
            pub.validate_context_origin(e,{**run,"head_sha":"d"*40})
        record(e, public_projection(r["result"]), PUBLIC_SCOPE, r["execution_digest"], r["export_digest"])
        api = Mock()
        pub.feedback(r,True,call=api)
        api.assert_not_called()

    def test_automatic_provenance_is_bound_to_git_blob(self):
        r = self.review("automatic_pr")
        e = r["execution"]
        run = {"event":"workflow_run","head_sha":"b"*40}
        raw = json.dumps(e["business_context"]).encode()
        e["context_provenance"]["configuration_sha256"] = digest(raw)
        blob = dict(type="file", encoding="base64", size=len(raw), content=base64.b64encode(raw).decode())
        with patch.object(pub,"api",return_value=blob) as api:
            pub.validate_context_origin(e,run)
            api.assert_called_once_with("contents/config/business-context.json?ref="+"b"*40)
            e["context_provenance"]["configuration_sha256"] = "0"*64
            with self.assertRaises(ValueError):
                pub.validate_context_origin(e,run)
        e["context_provenance"]["configuration_sha256"] = digest(raw)
        self.assertTrue(pub.official_pr(e))
        g = copy.deepcopy(r["result"])
        g["business_context"]["asset_criticality"] = "high"
        with self.assertRaises(ValueError):
            record(e,g,"review",r["execution_digest"],r["export_digest"])

    def test_new_fixture_provenance_with_all_gate_outcomes(self):
        for scope in ("pass", "review", "error"):
            with self.subTest(scope=scope):
                r = synthetic(scope)
                e, g = r["execution"], r["result"]
                info = bc.provenance("fixture", e["input_commit_sha"])
                e["context_provenance"] = info
                g.update(context_provenance=info, business_context=e["business_context"])
                pub.validate_context_origin(e, {"event": "workflow_dispatch", "head_sha": e["input_commit_sha"]})
                e["publication_fixture"] = scope
                published = record(e, public_projection(g), PUBLIC_SCOPE, r["execution_digest"], r["export_digest"])
                self.assertEqual(published["execution"]["gate_status"], scope.upper())
                self.assertFalse(pub.official_pr(e))

    def test_legacy_history_immutable_and_asset_paths_versioned(self):
        r = synthetic("pass")
        records = {}
        key = site.insert(records,r)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            legacy = b"HTML previously published by CI-4E"
            assets = {"assets/app.js": b"old script"}
            site.build(records,root,{key:legacy},historical_assets=assets)
            first = (root/"history.json").read_bytes()
            site.build(records,root,{key:legacy},parse(first),assets)
            self.assertEqual(first,(root/"history.json").read_bytes())
            self.assertEqual((root/key).with_name("report.html").read_bytes(),legacy)
            self.assertEqual((root/"assets/app.js").read_bytes(),assets["assets/app.js"])
            index = (root/"index.html").read_text()
            for path in (root/"assets").glob("*.*.*"):
                self.assertIn(path.name,index)
                self.assertIn(digest(path.read_bytes()),path.name)
            self.assertEqual(len(list((root/"assets").glob("*.*.*"))),3)


if __name__ == "__main__":
    unittest.main()
