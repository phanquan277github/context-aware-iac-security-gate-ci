"use strict";
const el = id => document.getElementById(id);
const tag = (name,text) => { const node=document.createElement(name); node.textContent=text; return node; };
const context = r => Object.values(r.business_context ? {env:r.business_context.environment,asset:r.business_context.asset_criticality,data:r.business_context.data_sensitivity} : {}).join(" / ") || "N/A";
const source = r => r.trigger_event === "workflow_run" ? "PR" : "Fixture";
const status = r => r.gate_status || "Diagnostic";
function draw(data) {
  const q=el("search").value.trim().toLowerCase();
  const rows=data.filter(r => [r.github_run_id,r.input_commit_sha,r.scanned_commit_sha,r.pr_number && "#"+r.pr_number].some(x=>x && String(x).toLowerCase().includes(q)) &&
    (!el("status").value || status(r)===el("status").value) && (!el("trigger").value || source(r)===el("trigger").value) && (!el("ctx").value || context(r)===el("ctx").value));
  rows.sort((a,b)=>(Date.parse(b.started_utc)-Date.parse(a.started_utc) || b.github_run_attempt-a.github_run_attempt)*(el("sort").value==="old"?-1:1));
  el("rows").replaceChildren(); el("matches").textContent=rows.length+" kết quả";
  for(const r of rows){
    const tr=tag("tr",""), c=r.counts;
    for(const v of [r.started_utc,status(r)+" / "+r.wrapper_status,r.github_run_id+" · "+r.github_run_attempt,source(r)+(r.pr_number?" #"+r.pr_number:""),context(r),c?[c.failed_findings_total,c.supported_findings,c.unsupported_findings].join(" / "):"N/A"]){tr.append(tag("td",v));}
    tr.children[1].className=status(r); const td=tag("td",""), link=tag("a","Mở HTML");link.href="reports/"+r.github_run_id+"/attempt-"+r.github_run_attempt+"/report.html";td.append(link);tr.append(td);el("rows").append(tr);
  }
}
async function load(){
  const response=await fetch("history.json");if(!response.ok)throw Error();
  const data=await response.json(),latest=data[0];
  for(const [name,count] of [["Tổng lượt",data.length],...["PASS","REVIEW","ERROR","Diagnostic"].map(s=>[s,data.filter(r=>status(r)===s).length])]){
    const d=tag("div",name);d.append(tag("strong",count));el("stats").append(d);
  }
  el("latest").textContent=latest?status(latest)+" · "+latest.started_utc+" · Run "+latest.github_run_id+" / "+latest.github_run_attempt:"Chưa có báo cáo đã công bố.";
  const complete=data.filter(r=>r.scan_complete && ["PASS","REVIEW"].includes(r.gate_status));
  const sum=k=>complete.reduce((n,r)=>n+r.counts[k],0);
  el("coverage").textContent=complete.length+" lượt hoàn tất · "+sum("failed_findings_total")+" failed · "+sum("supported_findings")+" scored · "+sum("unsupported_findings")+" unsupported · "+sum("unscorable_findings")+" unscorable";
  const model=data.find(r=>r.deployment_model_id);
  el("model").textContent=model?[model.deployment_model_id,"Model SHA-256 "+model.model_sha256,"Runtime "+model.trusted_runtime_commit_sha].join(" · "):"Chưa có provenance của model.";
  for(const [id,fn] of [["status",status],["trigger",source],["ctx",context]])for(const v of new Set(data.map(fn))){el(id).add(new Option(v,v));}
  for(const id of ["search","status","trigger","ctx","sort"]){el(id).addEventListener("input",()=>draw(data));}draw(data);
}
load().catch(()=>{el("latest").textContent="Không đọc được history.json.";});
