/* Compare complete scans by the frozen Gate finding_id, never by rule alone. */
const ContextComparison = (() => {
  const businessKeys = ["environment", "asset_criticality", "data_sensitivity"];
  const technicalKeys = ["internet_exposure", "reachability", "privilege_impact", "resource_role",
    "logging_missing", "public_access", "wildcard_action", "wildcard_resource", "encryption_missing"];
  const tolerance = 1e-12;
  const identityFields = ["trusted_runtime_commit_sha", "runtime_archive_sha256", "manifest_sha256",
    "deployment_model_id", "model_sha256"];

  function reason(a, b) {
    if (!a || !b) return "Chọn hai lượt đánh giá.";
    if (![a,b].every(row => row.scan_complete && ["PASS","REVIEW"].includes(row.gate_status)
        && row.model_trust_status === "verified")) return "Cần hai lượt quét và chấm điểm hoàn tất.";
    if (!a.terraform_artifact_sha256 || !b.terraform_artifact_sha256 || !a.gate_result_sha256 || !b.gate_result_sha256)
      return "Thiếu hash Terraform hoặc Gate export.";
    if (a.terraform_artifact_sha256 !== b.terraform_artifact_sha256)
      return "Hai lượt dùng Terraform artifact khác nhau.";
    if (!a.scanned_commit_sha || a.scanned_commit_sha !== b.scanned_commit_sha)
      return "Cần cùng commit đã quét.";
    if (identityFields.some(key => !a[key] || a[key] !== b[key])) return "Runtime hoặc model khác nhau hoặc thiếu định danh.";
    if (a.schema_version !== b.schema_version || a.schema_version !== "ci4-advisory-execution-v1")
      return "Schema execution không tương thích.";
    if (!a.business_context || !b.business_context) return "Thiếu business context.";
    if (!businessKeys.some(key => a.business_context[key] !== b.business_context[key]))
      return "Hai lượt có cùng business context.";
    return "";
  }

  function byFinding(result) {
    const rows = [...result.ranked_supported_findings, ...result.unsupported_findings];
    const found = new Map();
    for (const row of rows) {
      if (!/^[0-9a-f]{64}$/.test(row.finding_id) || found.has(row.finding_id))
        throw Error("Finding ID thiếu hoặc trùng. Không thể ghép một-một.");
      found.set(row.finding_id, row);
    }
    return found;
  }

  function comparable(x, y) {
    const fields = ["check_id", "classification", "severity_numeric", "unsupported_reason"];
    if (fields.some(key => x[key] !== y[key])) return false;
    // The stable ID binds source location and resource identity when public display fields are redacted.
    const locationFields = ["resource_type", "source_path", "line_start", "line_end"];
    if (locationFields.some(key => x[key] != null && y[key] != null && x[key] !== y[key])) return false;
    if (x.classification !== "scored") return x.context_features === null && y.context_features === null;
    const a = x.context_features;
    const b = y.context_features;
    return a && b && technicalKeys.every(key => Object.hasOwn(a, key) && a[key] === b[key]);
  }

  function compare(a, b) {
    const blocked = reason(a.execution, b.execution);
    if (blocked) return {error: blocked};
    const first = a.result;
    const next = b.result;
    if (!first || !next || first.schema_version !== "ci4-advisory-gate-result-v1" ||
        first.schema_version !== next.schema_version) return {error: "Thiếu Gate export tương thích."};
    if (![first,next].every(result => Object.values(result.execution_status ?? {}).length === 5
        && Object.values(result.execution_status).every(value => value === "success")))
      return {error: "Các bước Gate chưa hoàn tất."};
    const x = byFinding(first);
    const y = byFinding(next);
    const unmatchedA = [...x.keys()].filter(id => !y.has(id));
    const unmatchedB = [...y.keys()].filter(id => !x.has(id));
    const matched = [...x.keys()].filter(id => y.has(id));
    const mismatch = matched.filter(id => !comparable(x.get(id), y.get(id)));
    if (unmatchedA.length || unmatchedB.length || mismatch.length) {
      return {error: "Finding hoặc đặc trưng kỹ thuật khác nhau. Không thể cô lập ảnh hưởng của context.",
        matched: matched.length, unmatchedA, unmatchedB, mismatch};
    }
    const rows = matched.map(id => {
      const left = x.get(id), right = y.get(id);
      const scored = left.classification === "scored";
      if (scored && [left, right].some(row => !Number.isFinite(row.priority_score) ||
          row.priority_score < 0 || row.priority_score > 1 || !Number.isFinite(row.priority_rank_expected) ||
          !Number.isInteger(row.priority_tie_group_size))) throw Error("Điểm, hạng hoặc tie group không hợp lệ.");
      return {left, right, delta: scored ? right.priority_score - left.priority_score : null,
        rankChange: scored ? right.priority_rank_expected - left.priority_rank_expected : null};
    });
    return {rows, matched: matched.length, unmatchedA, unmatchedB,
      businessChanges: businessKeys.filter(key => a.execution.business_context[key] !== b.execution.business_context[key]),
      scoreChanges: rows.filter(row => Math.abs(row.delta) > tolerance).length,
      rankChanges: rows.filter(row => row.rankChange !== null && row.rankChange !== 0).length};
  }

  return {businessKeys, identityFields, reason, compare, tolerance};
})();

if (typeof module !== "undefined") module.exports = ContextComparison;
