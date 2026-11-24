"""Stage and validate the unsigned CI-3B advisory profile."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tarfile
from io import BytesIO
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parent))
import business_context as bc


RELEASE_ID = "ci-gate-v1"
MANIFEST_SHA = "e9c723e256dfbe31ea927ad74990686b94b2f8d7831bc7c665b55ba109a73fa2"
MODEL_SHA = "5ed8eb2bb44af178a748c1d6902917f5459a4361ba8171a5181960a06c6eb4c1"
VERIFIER_SHA = "1fbafd48ce5613a22360429a01deb410fd421f1f9dd08a6f9caebdfebae1f414"
TOOLCHAIN_SHA = "5f44a2f0f007d00747f388572ae475dbee9a907c4465993baada35cf2c0619e5"
MANIFEST = "release-manifest.json"
MODEL = "runtime/results/prototype/model_v1/deployment_model_v1.joblib"
POLICY = "results/main_benchmark/phase8_prototype_policy_v1.json"
VERIFIER = "runtime/scripts/prototype_v1/ci_release_verifier.py"
EXIT = {0: "PASS", 10: "REVIEW", 20: "ERROR"}
CONTROL = Path(__file__).resolve().parent
FIXTURES = {"pass": 0, "review": 10, "error": 20, "ci5": 10}
CONTEXT_KEYS = bc.KEYS
CONTEXT_PROFILES = {"CTX01": ("dev", "low", "low"), "CTX08": ("prod", "high", "high")}
SHA40 = re.compile("[0-9a-f]{40}")
SHA64 = re.compile("[0-9a-f]{64}")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def regular(path, limit=4 * 1024 * 1024):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= limit,
                "Expected a bounded regular file")
        data = stream.read(limit + 1)
    require(len(data) == info.st_size, "File changed during read")
    return data


def sha(data):
    return hashlib.sha256(data).hexdigest()


def unique_object(pairs):
    doc = {}
    for key, value in pairs:
        require(key not in doc, "Duplicate JSON key")
        doc[key] = value
    return doc


def invalid_constant(_value):
    raise ValueError("Invalid non-finite JSON constant")


def finite_float(token):
    value = float(token)
    require(math.isfinite(value), "Non-finite JSON number")
    return value


def strict_json(data):
    return json.loads(data.decode("utf-8"), object_pairs_hook=unique_object,
                      parse_constant=invalid_constant, parse_float=finite_float)


def inventory(manifest):
    require(sha(manifest) == MANIFEST_SHA, "Unexpected release manifest SHA-256")
    doc = strict_json(manifest)
    require(doc["release_id"] == RELEASE_ID and doc["authorization"] == "UNSIGNED_DEV_ONLY",
            "Unexpected advisory release identity")
    files = {entry["path"]: (entry["size_bytes"], entry["sha256"]) for entry in doc["files"]}
    require(len(files) == len(doc["files"]) == 23 and files[MODEL][1] == MODEL_SHA
            and files[VERIFIER][1] == VERIFIER_SHA, "Unexpected release contents")
    files[MANIFEST] = (len(manifest), MANIFEST_SHA)
    return files


def verify_bundle(root, *, overlay=False):
    files = inventory(regular(root / MANIFEST))
    if overlay:
        script = "import runpy,sys; p=sys.argv.pop(1); root=sys.argv.pop(1); " \
                 "runpy.run_path(p)['verify'](__import__('pathlib').Path(root), " \
                 "sys.argv[1], dev_only=True, allow_venv=True)"
    for path, (size, digest) in files.items():
        data = regular(root / path)
        require(len(data) == size and sha(data) == digest, "Release file differs from the pin")
    if overlay:
        command = [sys.executable, "-I", "-B", "-c", script, str(root / VERIFIER),
                   str(root), MANIFEST_SHA]
    else:
        command = [sys.executable, "-I", "-B", str(root / VERIFIER), "--release", str(root),
                   "--expected-manifest-sha256", MANIFEST_SHA, "--dev-only"]
    subprocess.run(command, check=True, stdout=subprocess.DEVNULL)
    return files


def pack(source, destination):
    files = verify_bundle(source)
    with destination.open("xb") as stream:
        with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name in sorted(files):
                data = regular(source / name)
                require((len(data), sha(data)) == files[name], "Source changed while packing")
                header = tarfile.TarInfo(name)
                header.mode = 0o644
                header.size = len(data)
                archive.addfile(header, BytesIO(data))
    print(sha(regular(destination)))


def unpack(archive_path, expected, destination):
    blob = regular(archive_path)
    require(SHA64.fullmatch(expected) and sha(blob) == expected, "Archive SHA-256 mismatch")
    with tarfile.open(fileobj=BytesIO(blob), mode="r:") as archive:
        members = archive.getmembers()
        names = [entry.name for entry in members]
        require(len(names) == len(set(names)) == 24, "Unexpected archive inventory")
        require(all(entry.type == tarfile.REGTYPE for entry in members), "Archive entry is not regular")
        files = inventory(archive.extractfile(MANIFEST).read())
        require(set(files) == set(names), "Archive path is outside the manifest")
        destination.mkdir()
        for entry in members:
            data = archive.extractfile(entry).read()
            require((len(data), sha(data)) == files[entry.name], "Archive member bytes differ")
            target = destination / entry.name
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as output:
                output.write(data)
    verify_bundle(destination)


def git(root, *args):
    return subprocess.check_output(["git", "--no-optional-locks", "-C", str(root), *args])


def prepare_input(source, commit, destination):
    require(SHA40.fullmatch(commit) and git(source, "rev-parse", "HEAD").decode().strip() == commit,
            "PR checkout SHA mismatch")
    directory = git(source, "ls-tree", "-z", commit, "--", "terraform").rstrip(b"\0")
    require(directory.startswith(b"040000 tree ") and directory.endswith(b"\tterraform"),
            "Expected the Terraform directory at terraform/")
    entries = git(source, "ls-tree", "-z", commit + ":terraform").split(b"\0")
    destination.mkdir()
    count = total = 0
    for entry in filter(None, entries):
        meta, raw_name = entry.split(b"\t", 1)
        mode, kind, blob = meta.split()
        name = raw_name.decode("utf-8")
        require(mode in {b"100644", b"100755"} and kind == b"blob",
                "Nested directories, symlinks and submodules are outside this MVP scope")
        require(not name.endswith((".tf.json", ".tfvars", ".tfvars.json")),
                "Unsupported Terraform input file form")
        if not name.endswith(".tf"):
            continue
        require(re.fullmatch(r"[A-Za-z0-9_.-]+\.tf", name) and name != ".tf",
                "Unsupported Terraform filename")
        object_id = blob.decode("ascii")
        size = int(git(source, "cat-file", "-s", object_id))
        count, total = count + 1, total + size
        require(count <= 64 and size <= 1024 * 1024 and total <= 2 * 1024 * 1024,
                "Terraform input exceeds the MVP static scan limits")
        with (destination / name).open("xb") as output:
            output.write(git(source, "cat-file", "blob", object_id))
    require(count > 0, "No Terraform files were supplied")


def fixture(name, destination):
    destination.mkdir()
    with (destination / "main.tf").open("xb") as output:
        output.write(regular(CONTROL / "ci_gate_fixtures" / name / "main.tf"))


def toolchain_steps(work):
    source = regular(CONTROL / "workflows" / "toolchain-smoke.yml")
    require(sha(source) == TOOLCHAIN_SHA, "Unexpected CI-3B0 toolchain workflow bytes")
    text = source.decode("utf-8")
    for step in ("dependencies", "terraform", "checkov", "provider"):
        spec = text.split(f"\n        id: {step}\n")[1].split("\n      - name:", 1)[0]
        lines = spec.split("\n        run: |\n", 1)[1].splitlines()
        require(all(not line or line.startswith(" " * 10) for line in lines),
                "Unexpected toolchain block indentation")
        body = "\n".join(line[10:] for line in lines).strip() + "\n"
        body = body.replace("$TOOLCHAIN_DIR/venv", "$BUNDLE_DIR/runtime/.venv")
        with (work / f"ci3b0-{step}.sh").open("x", encoding="utf-8") as output:
            output.write(body)


def resolve_pr():
    event = strict_json(regular(Path(os.environ["GITHUB_EVENT_PATH"])))
    run = event["workflow_run"]
    repo = event["repository"]
    prs = run["pull_requests"]
    require(run["event"] == "pull_request" and run["conclusion"] == "success"
            and run["path"] == ".github/workflows/security-gate-pr.yml"
            and run["head_repository"]["id"] == repo["id"]
            and len(prs) == 1, "Unsupported workflow run or missing same-repository PR")
    pr = prs[0]
    commit = pr["head"]["sha"]
    require(pr["head"]["repo"]["id"] == repo["id"] and pr["base"]["repo"]["id"] == repo["id"]
            and pr["base"]["ref"] == repo["default_branch"]
            and SHA40.fullmatch(commit) and commit == run["head_sha"]
            and type(pr["number"]) is int and pr["number"] > 0,
            "PR metadata does not match the triggering run")
    print(f"sha={commit}")
    print(f"number={pr['number']}")


def assessment_type(env):
    if env.get("GITHUB_EVENT_NAME") == "workflow_run":
        return "automatic_pr"
    if env.get("GITHUB_EVENT_NAME") == "workflow_dispatch":
        mode = env.get("CI_ASSESSMENT_MODE") or "fixture"
        require(mode in {"fixture", "on_demand_pr"}, "Unsupported assessment mode")
        return mode
    return None


def trusted_context(env):
    kind = assessment_type(env)
    revision = env.get("GITHUB_SHA", "")
    if kind == "automatic_pr":
        data = regular(CONTROL.parent / bc.CONFIG, 4096)
        context = bc.values(strict_json(data))
        info = bc.provenance(kind, revision, config_sha=sha(data))
    elif kind == "on_demand_pr":
        context = bc.values({k: env.get("CI_INPUT_" + k.upper()) for k in CONTEXT_KEYS})
        expected = env.get("CI_EXPECTED_HEAD", "")
        require(SHA40.fullmatch(expected), "Expected PR head must be a full lowercase SHA")
        info = bc.provenance(kind, revision, expected_head=expected)
    elif kind == "fixture":
        profile = env.get("CI_CONTEXT_PROFILE") or "CTX01"
        require(profile in CONTEXT_PROFILES and (profile == "CTX01" or env.get("FIXTURE") == "ci5"),
                "Context profile is not allowed for this fixture")
        context = CONTEXT_PROFILES[profile]
        info = bc.provenance(kind, revision)
    else:
        context = CONTEXT_PROFILES["CTX01"]
        info = None
    # Direct local regression invocations may omit GitHub metadata.
    return bc.PROFILES[context], context, info if SHA40.fullmatch(revision) else None


def pr_from_api(pr, repo, expected, number):
    require(pr.get("number") == number and pr.get("state") == "open"
            and type(repo.get("id")) is int
            and (pr["head"].get("repo") or {}).get("id") == repo["id"]
            and (pr["base"].get("repo") or {}).get("id") == repo["id"]
            and pr["base"].get("ref") == "main",
            "Expected an open same-repository PR targeting main")
    require(pr["head"].get("sha") == expected, "Pinned PR head no longer matches")
    return expected, number


def resolve_manual_pr(env, fetch=None):
    require(env.get("GITHUB_EVENT_NAME") == "workflow_dispatch" and env.get("GITHUB_REF") == "refs/heads/main",
            "On-demand PR assessments require main")
    number = env.get("CI_INPUT_PR", "")
    expected = env.get("CI_EXPECTED_HEAD", "")
    require(re.fullmatch(r"[1-9][0-9]{0,9}", number) and SHA40.fullmatch(expected),
            "Enter a valid PR number and full lower-case head SHA")
    event = strict_json(regular(Path(env["GITHUB_EVENT_PATH"])))
    repo = event["repository"]
    full_name = repo["full_name"]
    require(repo["default_branch"] == "main" and re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", full_name)
            and env.get("GITHUB_REPOSITORY") == full_name, "Unexpected PR repository")
    if fetch is None:
        def fetch(path):
            req = Request("https://api.github.com/repos/" + full_name + "/" + path,
                          headers={"Accept": "application/vnd.github+json"})
            req.add_unredirected_header("Authorization", "Bearer " + env["GH_TOKEN"])
            with urlopen(req, timeout=30) as response:
                data = response.read(1_000_001)
            require(len(data) <= 1_000_000, "Oversized GitHub PR response")
            return strict_json(data)
    return pr_from_api(fetch("pulls/" + number), repo, expected, int(number))


def manual_pr_outputs():
    commit, number = resolve_manual_pr(os.environ)
    print(f"sha={commit}")
    print(f"number={number}")


def context_outputs():
    _, context, _ = trusted_context(os.environ)
    for key, value in zip(CONTEXT_KEYS, context):
        print(f"{key}={value}")


def verified_document(root, raw, code, profile, expected_context):
    verify_bundle(root, overlay=True)
    data = regular(raw / "gate.json", 16 * 1024 * 1024)
    checksum = sha(data)
    require(regular(raw / "gate.json.sha256", 128) == f"{checksum}  gate.json\n".encode(),
            "Gate JSON checksum pair is missing or incorrect")
    document = strict_json(data)
    require(isinstance(document, dict) and code in EXIT
            and type(document.get("exit_code")) is int
            and document["exit_code"] == code and document.get("gate_status") == EXIT[code],
            "Gate status and process exit disagree")
    context = document["business_context"]
    reported_profile = context["context_profile_id"]
    # D-039 can return ERROR before deriving its profile from the trusted tuple.
    require(tuple(context.get(key) for key in CONTEXT_KEYS) == expected_context
            and (reported_profile == profile or (code == 20 and reported_profile is None)),
            "Gate business context differs from the trusted workflow")
    require(document["model_provenance"]["deployment_model_sha256"] == MODEL_SHA,
            "Gate JSON model SHA-256 differs from the pin")
    model = document["model_provenance"]
    require(model.get("deployment_model_id") == "rf_severity_context_deployment_v1"
            and model.get("trust_status") in {"verified", "not_verified"}, "Unexpected Gate model identity")
    runtime = root / "runtime"
    require(not any(name == "scripts" or name.startswith("scripts.") for name in sys.modules),
            "Unexpected validation module already imported")
    sys.path.insert(0, str(runtime))
    try:
        from scripts.prototype_v1.ranking_gate_schema import validate_output
        validate_output(document, strict_json(regular(runtime / POLICY)))
    finally:
        sys.path.pop(0)
    return checksum, document


def result_counts(document):
    counts = document["counts"]
    require(all(type(value) is int and value >= 0 for value in counts.values()),
            "Gate counts were not safe integers")
    public_counts = {key: counts[key] for key in (
        "failed_findings_total", "supported_findings", "unsupported_findings", "unscorable_findings")}
    scan = document["execution_status"]["checkov_scan"]
    return public_counts, isinstance(scan, dict) and scan.get("status") == "success"


def collect_record(args, env=None):
    env = os.environ if env is None else env
    context_error = False
    try:
        profile, context, provenance = trusted_context(env)
    except (OSError, ValueError, TypeError, KeyError):
        profile = context = provenance = None
        context_error = True
    document = None
    def numeric(name):
        value = env.get(name, "")
        return int(value) if re.fullmatch(r"\d{1,20}", value) else None

    input_commit = args.commit if SHA40.fullmatch(args.commit) else None
    result = {
        "schema_version": "ci3b-advisory-execution-v1",
        "enforcement": "ADVISORY_ONLY",
        "started_utc": args.start,
        "finished_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "github_run_id": numeric("GITHUB_RUN_ID"),
        "github_run_attempt": numeric("GITHUB_RUN_ATTEMPT"),
        "github_run_number": numeric("GITHUB_RUN_NUMBER"),
        "pr_number": numeric("CI_PR_NUMBER"),
        "input_commit_sha": input_commit,
        "scanned_commit_sha": None,
        "trusted_runtime_commit_sha": args.runtime_sha if SHA40.fullmatch(args.runtime_sha) else None,
        "release_id": RELEASE_ID,
        "manifest_sha256": MANIFEST_SHA,
        "model_sha256": MODEL_SHA,
        "business_context": dict(zip(CONTEXT_KEYS, context)) if context else None,
        "context_profile_id": profile,
        "gate_status": None,
        "gate_exit_code": None,
        "process_exit_code": args.exit,
        "wrapper_status": "ERROR",
        "wrapper_exit_code": 20,
        "failure_stage": None,
        "gate_json_sha256": None,
        "counts": None,
    }
    if provenance is not None and (provenance["assessment_type"] == "fixture" or result["pr_number"] is not None):
        result["context_provenance"] = provenance
    if context_error:
        result["failure_stage"] = "BUSINESS_CONTEXT"
        return result, None
    try:
        require(args.exit in EXIT, "Gate process did not return a supported exit code")
        if provenance and provenance["assessment_type"] == "on_demand_pr":
            require(provenance["expected_head_sha"] == input_commit and result["pr_number"] is not None,
                    "Evaluated commit differs from the on-demand PR pin")
        checksum, verified = verified_document(args.bundle, args.raw, args.exit, profile, context)
        counts, scan_complete = result_counts(verified)
        document = verified
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, ImportError,
            subprocess.SubprocessError, RecursionError, OverflowError, AttributeError):
        result["failure_stage"] = "GATE_OUTPUT_VERIFICATION" if args.exit in EXIT else "GATE_EXECUTION"
    else:
        result.update(gate_status=EXIT[args.exit], gate_exit_code=args.exit,
                      wrapper_status=EXIT[args.exit], wrapper_exit_code=args.exit,
                      failure_stage="GATE" if args.exit == 20 else None,
                      gate_json_sha256=checksum, counts=counts,
                      scanned_commit_sha=input_commit if scan_complete else None)
    return result, document


def collect(args):
    result, _ = collect_record(args)
    with args.report.open("x", encoding="utf-8") as output:
        json.dump(result, output, indent=2, sort_keys=True, allow_nan=False)
        output.write("\n")
    print(result["wrapper_exit_code"])


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    spec = {
        "pack": (("source", Path), ("destination", Path)),
        "unpack": (("archive", Path), ("expected", str), ("destination", Path)),
        "stage": (("source", Path), ("commit", str), ("destination", Path)),
        "fixture": (("name", str), ("destination", Path)),
        "provision": (("work", Path),),
        "collect": (("bundle", Path), ("raw", Path), ("exit", int), ("report", Path),
                    ("start", str), ("commit", str), ("runtime_sha", str)),
        "resolve-pr": (),
        "resolve-manual-pr": (),
        "context": (),
    }
    for name, arguments in spec.items():
        command = commands.add_parser(name)
        for argument, kind in arguments:
            command.add_argument(argument, type=kind, **({"choices": FIXTURES} if argument == "name" else {}))
    args = parser.parse_args()
    runners = {"pack": pack, "unpack": unpack, "stage": prepare_input, "fixture": fixture,
               "provision": toolchain_steps, "resolve-pr": resolve_pr,
               "resolve-manual-pr": manual_pr_outputs, "context": context_outputs}
    if args.command == "collect":
        collect(args)
        return
    runners[args.command](*(getattr(args, name) for name, _kind in spec[args.command]))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, tarfile.TarError) as exc:
        raise SystemExit(f"CI-3B: {type(exc).__name__}: {exc}") from None
