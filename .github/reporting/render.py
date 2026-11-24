"""Offline, dependency-free presentation of CI-4 disclosure-approved records."""
from html import escape


def display(value):
    return "N/A" if value is None else str(value)


def h(value):
    return escape(display(value), quote=True)


def facts(items):
    return "<dl>" + "".join(f"<dt>{h(key)}</dt><dd>{h(value)}</dd>" for key, value in items) + "</dl>"


def finding(item):
    location = item["source_path"]
    if location:
        location += f" · {item['line_start']}–{item['line_end']}"
    details = [
        ("Finding ID", item["finding_id"]), ("Loại tài nguyên", item["resource_type"]),
        ("Tài nguyên", item["resource"]), ("Vị trí", location),
        ("Mức nghiêm trọng D-022", item["severity_numeric"]),
    ]
    if item["classification"] == "scored":
        details.extend([("Điểm ưu tiên ML", item["priority_score"]),
                        ("Hạng kỳ vọng", item["priority_rank_expected"]),
                        ("Số finding đồng hạng", item["priority_tie_group_size"])])
    else:
        details.append(("Lý do", item["unsupported_reason"]))
    return (f"<article><h3>{h(item['check_id'])}</h3><p>{h(item['check_name'])}</p>"
            + facts(details) + "</article>")


STYLE = """
:root{font-family:system-ui,sans-serif;color:#172f3b;background:#f2f5f5}
*{box-sizing:border-box}body{margin:0}main{max-width:64rem;margin:auto;padding:1.5rem}
header{background:#153745;color:white;border-radius:.8rem;padding:2rem}
header p{margin:0;color:#c7e5ed}h1{font-size:clamp(1.6rem,4vw,2.8rem);margin:.35em 0}
h2{font-size:1.25rem;margin:0 0 .8rem}h3{font-size:1rem}section{background:white;
border:1px solid #ccd8dc;border-radius:.6rem;margin:1rem 0;padding:1.25rem}
dl{display:grid;grid-template-columns:minmax(10rem,36%) 1fr;gap:.5rem 1rem;margin:0}
dt{color:#405d69}dd{margin:0;font-variant-numeric:tabular-nums;overflow-wrap:anywhere}
article+article{border-top:1px solid #c8d4d8;margin-top:1rem}
meter{vertical-align:middle;width:min(50%,16rem)}.coverage{display:flex;align-items:center;gap:.8rem}
@media(max-width:34rem){main{padding:.6rem}dl{grid-template-columns:1fr;gap:.2rem}dd{margin-bottom:.6rem}}
@media print{main{max-width:100%}section,article{break-inside:avoid}}
"""


def conclusion(record):
    if record.get("gate_status") == "PASS" and record.get("scan_complete") is True:
        return "Lượt quét đã hoàn tất và không ghi nhận failed finding trong phạm vi đầu vào."
    if record.get("gate_status") == "REVIEW":
        return "Có finding cần rà soát. Điểm ưu tiên giúp xác định thứ tự xem xét trong lượt quét."
    if record.get("gate_status") == "ERROR":
        return "Gate gặp lỗi. Các số đếm hiện có không chứng minh đầu vào an toàn."
    return "Chưa xác minh được kết quả Gate. Xem bước lỗi của wrapper."


def html_report(record, result, execution_digest, export_digest):
    sections = []
    def section(title, content):
        sections.append(f"<section><h2>{h(title)}</h2>{content}</section>")

    section("Tóm tắt", f"<p>{h(conclusion(record))}</p>" + facts([
        ("Gate / exit", f"{display(record.get('gate_status'))} / {display(record.get('gate_exit_code'))}"),
        ("Wrapper / exit", f"{record['wrapper_status']} / {record['wrapper_exit_code']}"),
        ("Checkov quét hoàn tất", record.get("scan_complete"))]))
    section("Thông tin thực thi", facts((key, record.get(key)) for key in (
        "execution_origin", "github_run_id", "github_run_number", "github_run_attempt", "started_utc", "finished_utc",
        "duration_seconds", "trigger_event", "workflow_ref", "pr_number", "scanned_commit_sha",
        "artifact_name")))
    section("Bối cảnh triển khai", facts((key, (record.get("business_context") or {}).get(key))
                                        for key in ("environment", "asset_criticality", "data_sensitivity")))
    counts = record.get("counts")
    coverage = "<p>N/A</p>"
    if counts:
        total = counts["failed_findings_total"]
        coverage = f"<p>Tổng số failed finding: <strong>{h(total)}</strong></p>"
        for key, label in (("supported_findings", "Đã chấm điểm"), ("unsupported_findings", "Ngoài phạm vi"),
                           ("unscorable_findings", "Trong phạm vi, chưa chấm được")):
            n = counts[key]
            coverage += (f'<p class="coverage">{label} <meter aria-label="{label}" min="0" '
                         f'max="{h(max(1,total))}" value="{h(n)}"></meter> {h(n)}</p>')
    section("Phạm vi chấm điểm", coverage)
    empty = "<p>Không có finding trong nhóm này.</p>" if result else "<p>Không có chi tiết đã xác minh.</p>"
    scored = result["ranked_supported_findings"] if result else []
    others = result["unsupported_findings"] if result else []
    section("Finding đã xếp hạng", "".join(map(finding, scored)) or empty)
    section("Finding chưa có điểm ML", "<p>Các finding này vẫn cần được xem xét.</p>" +
            ("".join(map(finding, others)) or empty))
    section("Đặc trưng ngữ cảnh theo finding", "".join(
        f"<article><h3>{h(i['check_id'])} · {h(i['finding_id'])}</h3>{facts(i['context_features'].items())}</article>"
        for i in scored) or empty)
    section("Chẩn đoán", facts([("Bước lỗi wrapper", record.get("failure_stage")),
                                ("Exit của tiến trình", record.get("process_exit_code")),
                                ("Fixture expectation", record.get("fixture_expectation"))] +
                               list(result["execution_status"].items() if result else [])))
    section("Nguồn gốc runtime và model", facts((key, record.get(key)) for key in (
        "release_id", "trusted_runtime_commit_sha", "runtime_archive_sha256", "manifest_sha256",
        "deployment_model_id", "model_sha256", "model_trust_status")))
    section("Tính toàn vẹn", facts([("Gate JSON nguồn", record.get("gate_json_sha256")),
                                    ("gate-result.json đã lọc", export_digest),
                                    ("execution.json", execution_digest)]))
    section("Giới hạn", "<p>Điểm ML biểu thị mức ưu tiên tương đối. Việc đánh giá hiệu năng khoa học "
            "dùng kết quả OOF riêng. Mức severity hiển thị lấy từ bảng D-022. N/A biểu thị thông tin "
            "vắng mặt hoặc đã lược khỏi bản công bố. Trạng thái wrapper ở thời điểm tạo artifact; "
            "xem bước cuối của job để xác nhận upload.</p>")
    return ('<!doctype html><html lang="vi"><meta charset="utf-8"><meta name="viewport" '
            'content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" '
            'content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">'
            '<title>Báo cáo Security Gate</title><style>' + STYLE + '</style><main><header>'
            '<p>Security Gate · ADVISORY_ONLY</p><h1>Báo cáo kiểm tra Terraform</h1>'
            f'<strong>{h(record.get("gate_status"))}</strong></header>' + "".join(sections) + '</main></html>\n')


def markdown(record, result):
    # Only constrained IDs, enums, numbers and the generated artifact name enter the summary.
    counts = record.get("counts") or {}
    ctx = record.get("business_context") or {}
    lines = ["## Security Gate · ADVISORY_ONLY", conclusion(record), "",
             f"- Gate: {display(record.get('gate_status'))} / {display(record.get('gate_exit_code'))}",
             f"- Wrapper (trước upload): {record['wrapper_status']} / {record['wrapper_exit_code']}",
             f"- Bước lỗi: {display(record.get('failure_stage'))}",
             "- Finding (tổng / đã chấm / ngoài phạm vi / chưa chấm được): " + " / ".join(
                 display(counts.get(k)) for k in ("failed_findings_total", "supported_findings",
                                                  "unsupported_findings", "unscorable_findings")),
             "- Bối cảnh: " + " / ".join(display(ctx.get(k)) for k in ("environment", "asset_criticality", "data_sensitivity")),
             f"- Run / attempt: {record['github_run_id']} / {record['github_run_attempt']}",
             f"- Artifact: `{record['artifact_name']}`"]
    if record.get("fixture_expectation"):
        lines.append(f"- Fixture expectation: {record['fixture_expectation']}")
    if result and result["ranked_supported_findings"]:
        lines.extend(["", "| Quy tắc | Hạng | Điểm ưu tiên |", "|---|---:|---:|"])
        for item in result["ranked_supported_findings"][:5]:
            lines.append(f"| {item['check_id'] or 'N/A'} | {item['priority_rank_expected']} | {item['priority_score']} |")
    return "\n".join(lines) + "\n"
