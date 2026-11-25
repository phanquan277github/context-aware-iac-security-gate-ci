"""Resolve trusted GitHub metadata for an automatic Terraform push assessment."""
import re
from urllib.parse import urlencode

SIGNAL_PATH = ".github/workflows/security-gate-push.yml"
SHA = re.compile(r"[0-9a-f]{40}")


def workload_branch(branch):
    return (isinstance(branch, str) and branch != "gh-pages"
            and re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9._/-]{0,199}", branch) is not None)


def source_identity(run, repository_id):
    branch, commit = run.get("head_branch"), run.get("head_sha")
    if (run.get("event") != "push" or run.get("path") != SIGNAL_PATH or run.get("conclusion") != "success"
            or type(repository_id) is not int or (run.get("head_repository") or {}).get("id") != repository_id
            or not workload_branch(branch) or not isinstance(commit, str) or not SHA.fullmatch(commit)
            or commit == "0" * 40):
        raise ValueError("Untrusted Terraform push signal")
    return branch, commit


def has_eligible_pr(fetch, repo, branch, commit):
    """Prefer the official PR lane only when it can assess this exact head."""
    if branch == "main":
        return False
    owner = repo["full_name"].split("/", 1)[0]
    query = urlencode({"state": "open", "base": "main", "head": f"{owner}:{branch}", "per_page": 100})
    for pr in fetch("pulls?" + query):
        number = pr["number"]
        head, base = pr["head"], pr["base"]
        if (type(number) is not int or number <= 0 or pr["state"] != "open"
                or head["ref"] != branch or head["sha"] != commit or base["ref"] != "main"
                or any((side.get("repo") or {}).get("id") != repo["id"] for side in (head, base))):
            continue
        # GitHub caps the PR files API. An inconclusive lookup leaves the push lane available.
        for page in range(1, 31):
            files = fetch(f"pulls/{number}/files?per_page=100&page={page}")
            if any(file["filename"].startswith("terraform/") for file in files):
                return True
            if len(files) < 100:
                break
    return False
