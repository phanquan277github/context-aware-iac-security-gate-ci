/* The history index is mutable. Individual run/attempt reports are immutable. */
const el = id => document.getElementById(id);
const tag = (name, text) => {
  const node = document.createElement(name);
  node.textContent = text;
  return node;
};
const contextKeys = ContextComparison.businessKeys;
const domains = [["dev", "prod"], ["low", "high"], ["low", "high"]];
const iso = value => typeof value === "string" && /(?:Z|\+00:00)$/.test(value) && Number.isFinite(Date.parse(value));
const sha = (value, size) => typeof value === "string" && new RegExp("^[0-9a-f]{" + size + "}$").test(value);
const integer = n => Number.isSafeInteger(n) && n >= 0;
const countKeys = ["failed_findings_total", "supported_findings", "unsupported_findings", "unscorable_findings"];
const context = row => row.business_context ? contextKeys.map(key => row.business_context[key]).join(" / ") : "N/A";
const runKey = row => row.github_run_id + "/" + row.github_run_attempt;
const reportDir = row => "reports/" + row.github_run_id + "/attempt-" + row.github_run_attempt + "/";
const labels = {automatic_push: "Push Assessment", automatic_pr: "PR tự động", on_demand_pr: "PR giả định", fixture: "Fixture"};
const source = row => labels[row.context_provenance?.assessment_type] ||
  (row.trigger_event === "workflow_run" ? labels.automatic_pr : labels.fixture);
const sourceDetails = row => source(row) + (row.pr_number ? " #" + row.pr_number : "") +
  (row.context_provenance?.source_branch ? " · " + row.context_provenance.source_branch : "");
const status = row => row.gate_status || "Diagnostic";
const states = ["PASS", "REVIEW", "ERROR"];
let rows = [];
let currentIndex;
let checking = false;
let checkOnVisible = false;
let comparisonKey = "";
let comparisonRevision = 0;

function normalizedIndex(data) {
  const legacy = Array.isArray(data);
  const records = legacy ? data : data?.records;
  if (!Array.isArray(records) || (!legacy && (data.schema_version !== "ci5c-history-v1" ||
      !iso(data.generated_utc) || !sha(data.content_sha256, 64)))) throw Error("Cấu trúc history.json không hợp lệ.");
  const seen = new Set();
  for (const row of records) {
    if (!row || !integer(row.github_run_id) || !integer(row.github_run_attempt) ||
        row.github_run_id === 0 || row.github_run_attempt === 0 || !iso(row.started_utc) ||
        !states.includes(row.wrapper_status) || !(row.gate_status === null || states.includes(row.gate_status)) ||
        ![true, false, null].includes(row.scan_complete) || seen.has(runKey(row)) ||
        row.report_url !== reportDir(row) + "report.html" ||
        (row.pr_number != null && (!integer(row.pr_number) || row.pr_number === 0)) ||
        (row.counts != null && !countKeys.every(key => integer(row.counts[key]))) ||
        (row.scan_complete && !row.counts) ||
        (row.business_context != null && !contextKeys.every((key,i) => domains[i].includes(row.business_context[key]))) ||
        (row.context_provenance != null && (row.context_provenance.schema_version !== "ci5c-context-v1" ||
          !Object.hasOwn(labels, row.context_provenance.assessment_type)))) throw Error("Bản ghi history.json không hợp lệ.");
    for (const field of ["input_commit_sha", "scanned_commit_sha", "trusted_runtime_commit_sha"]) {
      if (row[field] != null && !sha(row[field], 40)) throw Error("Commit trong lịch sử không hợp lệ.");
    }
    for (const field of ["model_sha256", "manifest_sha256", "gate_result_sha256", "terraform_artifact_sha256", "runtime_archive_sha256"]) {
      if (row[field] != null && !sha(row[field], 64)) throw Error("Digest trong lịch sử không hợp lệ.");
    }
    seen.add(runKey(row));
  }
  return {records, generated: legacy ? null : data.generated_utc, digest: legacy ? null : data.content_sha256};
}

function options(select, entries) {
  const selected = select.value;
  const first = select.options[0];
  select.replaceChildren(first, ...entries.map(([value, label]) => new Option(label, value)));
  select.value = entries.some(([value]) => value === selected) ? selected : "";
}

function sortRows(records) {
  return [...records].sort((a,b) => Date.parse(b.started_utc) - Date.parse(a.started_utc) ||
    b.github_run_id - a.github_run_id || b.github_run_attempt - a.github_run_attempt);
}

function drawHistory() {
  const query = el("search").value.trim().toLowerCase();
  const visible = rows.filter(row =>
    [row.github_run_id, row.input_commit_sha, row.scanned_commit_sha,
      row.context_provenance?.source_branch, row.pr_number && "#" + row.pr_number]
      .some(value => value && String(value).toLowerCase().includes(query)) &&
    (!el("status").value || status(row) === el("status").value) &&
    (!el("trigger").value || source(row) === el("trigger").value) &&
    (!el("ctx").value || context(row) === el("ctx").value));
  if (el("sort").value === "old") visible.reverse();
  el("rows").replaceChildren();
  el("matches").textContent = visible.length + " kết quả";
  for (const row of visible) {
    const tr = tag("tr", "");
    const counts = row.counts ? countKeys.slice(0,3).map(key => row.counts[key]).join(" / ") : "N/A";
    const facts = [row.started_utc, status(row) + " / " + row.wrapper_status, runKey(row),
      sourceDetails(row), context(row), counts];
    tr.append(...facts.map(value => tag("td", value)));
    tr.children[1].className = status(row);
    const td = tag("td", "");
    const link = tag("a", "Mở HTML");
    link.href = reportDir(row) + "report.html";
    td.append(link);
    tr.append(td);
    el("rows").append(tr);
  }
}

function drawOverview() {
  el("stats").replaceChildren();
  for (const [name,count] of [["Tổng lượt",rows.length],
    ...[...states,"Diagnostic"].map(state => [state,rows.filter(row => status(row) === state).length])]) {
    const box = tag("div", name);
    box.append(tag("strong", count));
    el("stats").append(box);
  }
  const latest = rows[0];
  el("latest").textContent = latest ? status(latest) + " · " + latest.started_utc + " · Run " + runKey(latest) :
    "Chưa có báo cáo đã công bố.";
  const complete = rows.filter(row => row.scan_complete && ["PASS","REVIEW"].includes(row.gate_status));
  const sum = key => complete.reduce((n,row) => n + row.counts[key], 0);
  el("coverage").textContent = complete.length + " lượt hoàn tất · " +
    countKeys.map((key,i) => sum(key) + " " + ["failed","scored","unsupported","unscorable"][i]).join(" · ");
  const model = rows.find(row => row.deployment_model_id);
  el("model").textContent = model ? [model.deployment_model_id,"Model SHA-256 " + model.model_sha256,
    "Runtime " + model.trusted_runtime_commit_sha].join(" · ") : "Chưa có provenance của model.";
  for (const [id,fn] of [["status",status],["trigger",source],["ctx",context]]) {
    const values = new Set(rows.map(fn));
    options(el(id), [...values].map(value => [value,value]));
  }
  drawHistory();
}

const selection = id => rows.find(row => runKey(row) === el(id).value);

function updateSelectors() {
  const a = selection("run-a");
  const ordered = a ? [...rows].sort((x,y) =>
    Number(Boolean(a.terraform_artifact_sha256 && y.terraform_artifact_sha256 === a.terraform_artifact_sha256)) -
    Number(Boolean(a.terraform_artifact_sha256 && x.terraform_artifact_sha256 === a.terraform_artifact_sha256))) : rows;
  const choices = records => records.map(row => [runKey(row), runKey(row) + " · " + source(row) + " · " + context(row)]);
  options(el("run-a"), choices(rows));
  options(el("run-b"), choices(ordered));
}

function pairDetails(row, side) {
  const block = tag("div","");
  block.append(tag("h3", "Lượt " + side));
  const list = tag("dl","");
  const counts = row.counts;
  const details = [["Run / attempt",runKey(row)], ["PR",row.pr_number ? "#" + row.pr_number : null],
    ["Commit đã quét",row.scanned_commit_sha],["Terraform SHA-256",row.terraform_artifact_sha256],
    ["Loại đánh giá",sourceDetails(row)],["Business context",context(row)],["Model",row.deployment_model_id],
    ["Model SHA-256",row.model_sha256],["Runtime commit",row.trusted_runtime_commit_sha],
    ["Runtime SHA-256",row.runtime_archive_sha256],["Quét hoàn tất",String(row.scan_complete)],
    ["Failed / scored / unsupported / unscorable", counts && countKeys.map(key => counts[key]).join(" / ")]];
  for (const [name,value] of details) list.append(tag("dt",name), tag("dd",value ?? "N/A"));
  const report = tag("a","Mở báo cáo " + side);
  report.href = reportDir(row) + "report.html";
  block.append(list,report);
  return block;
}

function drawComparison(outcome) {
  const result = el("comparison-result");
  result.replaceChildren();
  const desc = el("comparison-status");
  const summary = outcome.matched === undefined ? "" :
    " · Ghép theo ID " + outcome.matched + " · Chỉ A " + outcome.unmatchedA.length + " · Chỉ B " + outcome.unmatchedB.length;
  if (outcome.error) {
    desc.textContent = outcome.error + summary + (outcome.mismatch?.length ? " · Khác kỹ thuật " + outcome.mismatch.length : "");
    return;
  }
  desc.textContent = "Đổi " + outcome.scoreChanges + " điểm, " + outcome.rankChanges + " hạng" + summary;
  result.append(tag("p", "Giá trị bối cảnh thay đổi — " + outcome.businessChanges.join(", ")));
  const scroll = tag("div","");
  scroll.className = "scroll";
  const table = tag("table","");
  const heads = ["Rule · Finding ID", "Điểm A / B", "Δ điểm B−A", "Hạng A / B", "Δ hạng B−A", "Tie A / B", "Phân loại"];
  const thead = tag("thead","");
  const th = tag("tr","");
  th.append(...heads.map(label => tag("th",label)));
  thead.append(th);
  const body = tag("tbody","");
  for (const {left,right,delta,rankChange} of outcome.rows) {
    const tr = tag("tr","");
    const name = tag("td",left.check_id + " · " + left.finding_id.slice(0,12));
    name.title = left.finding_id;
    const scores = tag("td","");
    if (delta === null) scores.textContent = "—";
    else for (const [label,value] of [["A",left.priority_score],["B",right.priority_score]]) {
      const item = tag("div",label + " " + value);
      const bar = tag("meter","");
      bar.min = 0;
      bar.max = 1;
      bar.value = value;
      bar.setAttribute("aria-label","Điểm ưu tiên " + label);
      item.append(bar);
      scores.append(item);
    }
    tr.append(name,scores,...[delta,delta === null ? null : left.priority_rank_expected + " / " + right.priority_rank_expected,
      rankChange,delta === null ? null : left.priority_tie_group_size + " / " + right.priority_tie_group_size,
      left.classification].map(value => tag("td",value ?? "—")));
    body.append(tr);
  }
  table.append(thead,body);
  scroll.append(table);
  result.append(scroll, tag("p", "Δ hạng âm là lên hạng. Đếm thay đổi điểm với |Δ| > 10⁻¹². Thanh biểu diễn điểm ưu tiên ML."));
}

async function getExecution(row) {
  const response = await fetch(reportDir(row) + "record.json", {signal: AbortSignal.timeout(15000)});
  if (!response.ok) throw Error("Chưa đọc được record của lượt " + runKey(row));
  const data = await response.json();
  const fields = ["github_run_id", "github_run_attempt", "pr_number", "scan_complete", "schema_version",
    "terraform_artifact_sha256", "scanned_commit_sha", "gate_result_sha256", ...ContextComparison.identityFields];
  if (!data.execution || fields.some(key => data.execution[key] !== row[key]) ||
      context(data.execution) !== context(row) || data.export_digest !== row.gate_result_sha256 ||
      !data.result || !Array.isArray(data.result.ranked_supported_findings) || !Array.isArray(data.result.unsupported_findings))
    throw Error("Gate export không khớp lịch sử.");
  return data;
}

async function compareSelection() {
  const a = selection("run-a"), b = selection("run-b");
  const key = JSON.stringify([a,b]);
  if (comparisonKey === key) return;
  comparisonKey = key;
  const revision = ++comparisonRevision;
  el("pair-details").replaceChildren(...([[a,"A"],[b,"B"]].filter(([row]) => row).map(([row,side]) => pairDetails(row,side))));
  const blocked = ContextComparison.reason(a,b);
  drawComparison({error: blocked || "Đang đọc hai Gate export…"});
  if (blocked) return;
  try {
    const [left,right] = await Promise.all([getExecution(a),getExecution(b)]);
    if (revision === comparisonRevision) drawComparison(ContextComparison.compare(left,right));
  } catch (error) {
    if (revision === comparisonRevision) {
      comparisonKey = "";
      drawComparison({error: error.message});
    }
  }
}

async function refresh() {
  if (checking) return;
  checking = true;
  el("refresh").disabled = true;
  const previousText = el("freshness").dataset.success ?? "";
  try {
    const response = await fetch("history.json?check=" + Date.now(), {cache:"no-store", signal:AbortSignal.timeout(20000)});
    if (!response.ok) throw Error("HTTP " + response.status);
    const next = normalizedIndex(await response.json());
    if (currentIndex?.generated && (!next.generated || Date.parse(next.generated) < Date.parse(currentIndex.generated) ||
        (next.generated === currentIndex.generated && next.digest !== currentIndex.digest))) {
      throw Error("Máy chủ trả bản lịch sử cũ hoặc không nhất quán");
    }
    currentIndex = next;
    rows = sortRows(next.records);
    drawOverview();
    updateSelectors();
    compareSelection();
    const summary = "Lần kiểm tra thành công " + new Date().toISOString() + " · Bản lịch sử sinh lúc " +
      (next.generated ?? "không có trong phiên bản lịch sử này");
    el("freshness").dataset.success = summary;
    el("freshness").textContent = summary;
  } catch (error) {
    el("freshness").textContent = (previousText ? previousText + " · " : "") + "Làm mới lỗi (" + error.message +
      "). Bấm Làm mới lịch sử để thử lại.";
  } finally {
    checking = false;
    el("refresh").disabled = false;
    if (checkOnVisible && !document.hidden) {
      checkOnVisible = false;
      refresh();
    }
  }
}

for (const id of ["search","status","trigger","ctx","sort"]) el(id).addEventListener("input",drawHistory);
for (const id of ["run-a","run-b"]) el(id).addEventListener("change",() => {
  updateSelectors();
  compareSelection();
});
el("refresh").addEventListener("click",refresh);
setInterval(() => { if (!document.hidden) refresh(); },60000);
document.addEventListener("visibilitychange",() => {
  if (document.hidden) return;
  if (checking) checkOnVisible = true;
  else refresh();
});
refresh();
