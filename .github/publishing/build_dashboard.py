"""Build from verified records; read historical blobs with Git plumbing, never checkout gh-pages."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

sys.path.insert(0,str(Path(__file__).resolve().parent))
from records import HERE, LEGACY, PUBLIC_SCOPE, REPO, digest, html_report, need, parse, public_projection, record
from publisher import unpack_env

KEY=re.compile(r"reports/([1-9][0-9]{0,19})/attempt-([1-9][0-9]{0,19})/record.json")
ASSETS=HERE.parent.parent/"dashboard"
STATIC_ASSET = re.compile(r"assets/(style(?:\.[a-f0-9]{64})?\.css|(?:app|comparison)(?:\.[a-f0-9]{64})?\.js)")


def canonical(obj):
    return (json.dumps(obj,sort_keys=True,ensure_ascii=False,allow_nan=False,separators=(",",":"))+"\n").encode()


def insert(records,r):
    e=r["execution"]
    for key in ["execution_digest","export_digest"]:
        need((key=="export_digest" and r[key] is None) or re.fullmatch("[0-9a-f]{64}",r[key]),"Invalid stored digest")
    verified=record(e,r["result"],r["scope"],r["execution_digest"],r["export_digest"])
    need(canonical(r)==canonical(verified) and r["repository"]==REPO and
         r["export_digest"]==e["gate_result_sha256"],"Unexpected stored content")
    path=f"reports/{e['github_run_id']}/attempt-{e['github_run_attempt']}/record.json"
    if path in records and canonical(records[path]) != canonical(r):
        previous = records[path]
        if previous["scope"] in LEGACY and r["scope"] == PUBLIC_SCOPE:
            previous_execution = dict(previous["execution"])
            if "publication_fixture" in e:
                previous_execution["publication_fixture"] = e["publication_fixture"]
            projection = record(previous_execution, public_projection(previous["result"]), PUBLIC_SCOPE,
                                previous["execution_digest"], previous["export_digest"])
            if canonical(projection) == canonical(r):
                return path  # Same artifact replayed under the new policy. Keep historical bytes.
        raise ValueError("Conflict for existing run/attempt")
    records[path]=r
    return path


def build(records, site, historical_html=None, previous_index=None, historical_assets=None):
    site.mkdir(exist_ok=True)
    historical_html = historical_html or {}
    asset_dir = site / "assets"
    asset_dir.mkdir(exist_ok=True)
    for name, data in (historical_assets or {}).items():
        (site / name).write_bytes(data)
    assets = {}
    index = (ASSETS / "index.html").read_text(encoding="utf-8")
    for name in ("assets/style.css", "assets/comparison.js", "assets/app.js"):
        data = (ASSETS / name).read_bytes()
        assets[name] = digest(data)
        stem, extension = name.rsplit(".", 1)
        versioned_name = f"{stem}.{assets[name]}.{extension}"
        index = index.replace(f'"{name}"', f'"{versioned_name}"')
        (site / versioned_name).write_bytes(data)
    (site / "index.html").write_text(index, encoding="utf-8")
    history = []
    for key, r in sorted(records.items()):
        e = r["execution"]
        dst = site / key
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(canonical(r))
        html = historical_html.get(key)
        if html is None:
            html = html_report(e, r["result"], r["execution_digest"], r["export_digest"]).encode()
        dst.with_name("report.html").write_bytes(html)
        history.append({**e, "report_url": key.replace("record.json", "report.html"),
                        "actions_url": f"https://github.com/{REPO}/actions/runs/{e['github_run_id']}/attempts/{e['github_run_attempt']}"})
    history.sort(key=lambda e: (e["started_utc"], e["github_run_id"], e["github_run_attempt"]), reverse=True)
    fingerprint = digest(canonical({"history": history, "assets": assets, "index": digest(index.encode())}))
    if isinstance(previous_index, dict) and previous_index.get("content_sha256") == fingerprint:
        generated = previous_index["generated_utc"]
    else:
        generated = datetime.now(timezone.utc).isoformat()
    (site / "history.json").write_bytes(canonical(dict(schema_version="ci5c-history-v1",
        generated_utc=generated, content_sha256=fingerprint, records=history)))


def git(*args,env=None,data=None):
    return subprocess.check_output(["git",*args],env=env,input=data)


def snapshot(ref):
    stored={}
    original={}
    if ref:
        for entry in git("ls-tree","-rz",ref).split(b"\0"):
            if not entry: continue
            meta,path=entry.split(b"\t",1);path=path.decode()
            mode,kind,oid=meta.split()
            need(mode==b"100644" and kind==b"blob","Unsafe storage tree")
            original[path]=oid
            if KEY.fullmatch(path):
                need(insert(stored,parse(git("cat-file","blob",oid)))==path,"Wrong historical path")
    return stored,original


def publish(site,new):
    for _ in range(3):
        heads=git("ls-remote","--heads","origin","refs/heads/gh-pages").split()
        ref=None
        if heads:
            git("fetch","--quiet","origin","refs/heads/gh-pages")
            ref=git("rev-parse","FETCH_HEAD").decode().strip()
        records,original=snapshot(ref)
        historical_html = {}
        for key in records:
            html_path = key.replace("record.json", "report.html")
            need(html_path in original or not ref, "Missing historical report")
            if html_path in original:
                historical_html[key] = git("cat-file", "blob", original[html_path])
        previous_index = parse(git("cat-file", "blob", original["history.json"])) if "history.json" in original else None
        historical_assets = {path: git("cat-file", "blob", oid) for path, oid in original.items()
                             if STATIC_ASSET.fullmatch(path)}
        if new is not None:
            insert(records, new)
        build(records, site, historical_html, previous_index, historical_assets)
        for path,oid in original.items():
            need((site/path).is_file(),"Unrecognized storage path")
            if KEY.fullmatch(path) or path.endswith("/report.html") or STATIC_ASSET.fullmatch(path):
                need(git("hash-object",str(site/path)).strip()==oid,"Existing report would change")
        with tempfile.TemporaryDirectory() as tmp:
            gitdir=git("rev-parse","--absolute-git-dir").decode().strip()
            env=dict(os.environ,GIT_DIR=gitdir,GIT_WORK_TREE=str(site),GIT_INDEX_FILE=tmp+"/index",
                     GIT_AUTHOR_NAME="github-actions[bot]",GIT_AUTHOR_EMAIL="41898282+github-actions[bot]@users.noreply.github.com",
                     GIT_COMMITTER_NAME="github-actions[bot]",GIT_COMMITTER_EMAIL="41898282+github-actions[bot]@users.noreply.github.com")
            git("-C",str(site),"add","-f","--",".",env=env)
            tree=git("write-tree",env=env).decode().strip()
            if ref and git("rev-parse",ref+"^{tree}").decode().strip()==tree:return
            commit=git("commit-tree",tree,*(["-p",ref] if ref else []),"-m","Publish verified advisory history",env=env).decode().strip()
            if subprocess.run(["git","push","origin",commit+":refs/heads/gh-pages"]).returncode==0:return
    raise ValueError("Storage push conflict: recover the same run/attempt")


if __name__=="__main__":
    if os.environ.get("INITIALIZE") == "yes":
        need(not os.environ.get("RECORD"), "Unexpected initialization payload")
        incoming=None
    else:
        need(os.environ.get("RECORD"), "Validated publication record missing")
        incoming=unpack_env()
    publish(Path(os.environ["SITE_DIR"]).resolve(),incoming)
