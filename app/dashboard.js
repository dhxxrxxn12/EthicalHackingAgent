(() => {
  const byId = (id) => document.getElementById(id);
  const text = (node, value) => { node.textContent = value == null ? "" : String(value); };
  const link = (label, href) => {
    const anchor = document.createElement("a");
    anchor.textContent = label;
    anchor.href = href;
    return anchor;
  };
  const cell = (value) => { const td = document.createElement("td"); text(td, value); return td; };
  const scanLabel = (scan) => `${scan.timestamp} — ${scan.target || "invalid target"}`;

  function renderFindings(findings) {
    const container = byId("findings"); container.replaceChildren();
    if (!findings || findings.length === 0) { const empty = document.createElement("p"); empty.className = "muted"; text(empty, "No potential findings observed."); container.appendChild(empty); return; }
    findings.forEach((finding) => {
      const article = document.createElement("article"); article.className = "card";
      const heading = document.createElement("h3"); text(heading, finding.title); article.appendChild(heading);
      const list = document.createElement("dl");
      [["Severity", finding.severity], ["Confidence", `${finding.confidence}%`], ["Affected URL", finding.affected_url], ["Evidence", finding.evidence], ["Explanation", finding.explanation], ["Remediation", finding.remediation]].forEach(([label, value]) => {
        const term = document.createElement("dt"); text(term, label); const description = document.createElement("dd"); text(description, value); list.appendChild(term); list.appendChild(description);
      });
      article.appendChild(list); container.appendChild(article);
    });
  }

  function render(data) {
    text(byId("scan-count"), data.scan_count);
    const severity = byId("severity-counts"); severity.replaceChildren();
    Object.entries(data.severity_counts || {}).forEach(([name, count]) => {
      const item = document.createElement("li"); text(item, `${name}: ${count}`); severity.appendChild(item);
    });
    const history = byId("history"); history.replaceChildren();
    if (!data.recent_scans || data.recent_scans.length === 0) {
      const empty = document.createElement("p"); empty.className = "muted"; text(empty, "No scans yet."); history.appendChild(empty); return;
    }
    const table = document.createElement("table");
    const head = document.createElement("tr"); ["Timestamp", "Target", "Status", "Findings", "Reports"].forEach((name) => { const th = document.createElement("th"); text(th, name); head.appendChild(th); });
    const thead = document.createElement("thead"); thead.appendChild(head); table.appendChild(thead);
    const body = document.createElement("tbody");
    data.recent_scans.forEach((scan) => {
      const row = document.createElement("tr");
      row.appendChild(cell(scan.timestamp)); row.appendChild(cell(scan.target)); row.appendChild(cell(scan.status_code)); row.appendChild(cell(scan.finding_count));
      const reports = document.createElement("td"); reports.appendChild(link("JSON", `/reports/${encodeURIComponent(scan.scan_id)}/json`)); reports.appendChild(document.createTextNode(" · ")); reports.appendChild(link("HTML", `/reports/${encodeURIComponent(scan.scan_id)}/html`)); reports.appendChild(document.createTextNode(" · ")); reports.appendChild(link("Summary", `/reports/${encodeURIComponent(scan.scan_id)}/summary.html`)); row.appendChild(reports); body.appendChild(row);
    });
    table.appendChild(body); history.appendChild(table);
  }

  function populateScanChoices(scans) {
    [byId("earlier-scan"), byId("later-scan")].forEach((select) => {
      select.replaceChildren();
      scans.filter((scan) => scan.completed).forEach((scan) => {
        const option = document.createElement("option"); option.value = scan.scan_id; text(option, scanLabel(scan)); select.appendChild(option);
      });
    });
  }

  function renderComparison(data) {
    const container = byId("comparison"); container.replaceChildren();
    [["New", data.new], ["Recurring", data.recurring], ["Resolved (observed)", data.resolved], ["Not assessed", data.not_assessed]].forEach(([label, findings]) => {
      const heading = document.createElement("h3"); text(heading, `${label}: ${findings.length}`); container.appendChild(heading);
      findings.forEach((finding) => { const item = document.createElement("p"); text(item, `${finding.finding_id}: ${finding.title || ""}${finding.reason ? ` — ${finding.reason}` : ""}`); container.appendChild(item); });
    });
    const note = document.createElement("p"); note.className = "muted"; text(note, "Resolved means the later completed scan performed the relevant check; absence after failure or incomplete scope is not treated as resolution."); container.appendChild(note);
  }

  async function loadHistory(url = "/api/overview") {
    const response = await fetch(url); if (!response.ok) throw new Error("Could not load scan history");
    const data = await response.json(); render(data.recent_scans ? data : { scan_count: data.scan_count, severity_counts: {}, recent_scans: data.scans }); populateScanChoices(data.recent_scans || data.scans || []);
  }

  async function load() { await loadHistory(); }
  byId("history-filter").addEventListener("submit", async (event) => {
    event.preventDefault(); const params = new URLSearchParams();
    if (byId("date-from").value) params.set("date_from", byId("date-from").value);
    if (byId("date-to").value) params.set("date_to", byId("date-to").value);
    if (byId("severity-filter").value) params.set("severity", byId("severity-filter").value);
    try { await loadHistory(`/api/history?${params}`); } catch (error) { text(byId("history"), error.message); }
  });
  byId("comparison-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const response = await fetch("/api/compare", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ earlier_scan_id: byId("earlier-scan").value, later_scan_id: byId("later-scan").value }) });
      const data = await response.json(); if (!response.ok) throw new Error(data.detail || "Comparison failed"); renderComparison(data);
    } catch (error) { text(byId("comparison"), error.message); }
  });
  byId("scan-form").addEventListener("submit", async (event) => {
    event.preventDefault(); const status = byId("scan-status"); text(status, "Scanning…"); status.className = "muted";
    try {
      const response = await fetch("/api/scans", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ target: byId("target").value }) });
      const data = await response.json(); if (!response.ok) throw new Error(data.detail || "Scan failed");
      text(status, `Scan complete: ${data.finding_count} finding(s)`); renderFindings(data.findings); await load();
    } catch (error) { text(status, error.message); status.className = "error"; }
  });
  load().catch((error) => { text(byId("history"), error.message); });
})();
