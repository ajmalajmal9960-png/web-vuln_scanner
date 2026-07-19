const form = document.getElementById("scan-form");
const urlInput = document.getElementById("url-input");
const scanBtn = document.getElementById("scan-btn");
const demoScanBtn = document.getElementById("demo-scan-btn");
const statusEl = document.getElementById("status");
const crawlInfoEl = document.getElementById("crawl-info");
const summaryEl = document.getElementById("summary");
const findingsEl = document.getElementById("findings");
const historyListEl = document.getElementById("history-list");

const API_BASE = "";

function setStatus(message, type) {
  statusEl.textContent = message;
  statusEl.className = `status ${type}`;
}

function clearStatus() {
  statusEl.className = "status hidden";
}

function renderCrawlInfo(summary, pagesScanned) {
  if (!pagesScanned || !pagesScanned.length) {
    crawlInfoEl.classList.add("hidden");
    return;
  }
  crawlInfoEl.innerHTML = `Crawled <strong>${summary.pages_crawled}</strong> page(s): ` +
    pagesScanned.map(escapeHtml).join(", ");
  crawlInfoEl.classList.remove("hidden");
}

function renderSummary(summary) {
  document.getElementById("count-critical").textContent = summary.Critical || 0;
  document.getElementById("count-high").textContent = summary.High || 0;
  document.getElementById("count-medium").textContent = summary.Medium || 0;
  document.getElementById("count-low").textContent = summary.Low || 0;
  document.getElementById("count-forms").textContent = summary.forms_tested || 0;
  summaryEl.classList.remove("hidden");
}

function renderFindings(findings) {
  findingsEl.innerHTML = "";

  if (findings.length === 0) {
    findingsEl.innerHTML = `<p class="muted">No issues detected with the current rule set. This does not guarantee the target is fully secure -- validate manually.</p>`;
    return;
  }

  findings.forEach((f) => {
    const card = document.createElement("div");
    card.className = `finding-card ${f.severity}`;
    card.innerHTML = `
      <div class="finding-head">
        <span class="finding-type">${escapeHtml(f.type)}</span>
        <span class="finding-sev ${f.severity}">${f.severity}</span>
      </div>
      <div class="finding-meta">${f.method} ${escapeHtml(f.location)}</div>
      <div class="finding-evidence">${escapeHtml(f.evidence)}</div>
      ${f.payload && f.payload !== "N/A" ? `<div class="finding-payload">Payload: <code>${escapeHtml(f.payload)}</code></div>` : ""}
    `;
    findingsEl.appendChild(card);
  });
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

async function runScan(url) {
  scanBtn.disabled = true;
  demoScanBtn.disabled = true;
  setStatus(`Scanning ${url} ... this may take a few seconds while pages are crawled.`, "info");
  summaryEl.classList.add("hidden");
  crawlInfoEl.classList.add("hidden");
  findingsEl.innerHTML = "";

  try {
    const res = await fetch(`${API_BASE}/api/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    const data = await res.json();

    if (!res.ok) {
      setStatus(data.error || "Scan failed.", "error");
      return;
    }

    clearStatus();
    renderCrawlInfo(data.results.summary, data.results.pages_scanned);
    renderSummary(data.results.summary);
    renderFindings(data.results.findings);
    loadHistory();
  } catch (err) {
    setStatus(`Could not reach the backend: ${err.message}`, "error");
  } finally {
    scanBtn.disabled = false;
    demoScanBtn.disabled = false;
  }
}

async function runDemoScan() {
  scanBtn.disabled = true;
  demoScanBtn.disabled = true;
  setStatus("Running offline demo scan against the built-in simulated dataset...", "info");
  summaryEl.classList.add("hidden");
  crawlInfoEl.classList.add("hidden");
  findingsEl.innerHTML = "";

  try {
    const res = await fetch(`${API_BASE}/api/demo-scan`, { method: "POST" });
    const data = await res.json();

    if (!res.ok) {
      setStatus(data.error || "Demo scan failed.", "error");
      return;
    }

    clearStatus();
    urlInput.value = data.url;
    renderCrawlInfo(data.results.summary, data.results.pages_scanned);
    renderSummary(data.results.summary);
    renderFindings(data.results.findings);
    loadHistory();
  } catch (err) {
    setStatus(`Could not reach the backend: ${err.message}`, "error");
  } finally {
    scanBtn.disabled = false;
    demoScanBtn.disabled = false;
  }
}

async function loadHistory() {
  try {
    const res = await fetch(`${API_BASE}/api/history`);
    const scans = await res.json();

    if (!scans.length) {
      historyListEl.innerHTML = `<p class="muted small">No scans yet.</p>`;
      return;
    }

    historyListEl.innerHTML = "";
    scans.forEach((scan) => {
      const item = document.createElement("div");
      item.className = "history-item";
      const modeTag = scan.mode === "demo" ? `<span class="mode-tag">DEMO</span>` : "";
      item.innerHTML = `
        <div class="history-url">${modeTag}${escapeHtml(scan.url)}</div>
        <div class="history-time">${new Date(scan.scanned_at).toLocaleString()}</div>
        <div class="history-counts">
          <span class="c">C:${scan.summary.Critical || 0}</span>
          &nbsp;<span class="h">H:${scan.summary.High || 0}</span>
          &nbsp;<span class="m">M:${scan.summary.Medium || 0}</span>
          &nbsp;<span class="l">L:${scan.summary.Low || 0}</span>
        </div>
      `;
      item.addEventListener("click", () => loadScanDetail(scan.id));
      historyListEl.appendChild(item);
    });
  } catch (err) {
    historyListEl.innerHTML = `<p class="muted small">Could not load history.</p>`;
  }
}

async function loadScanDetail(id) {
  const res = await fetch(`${API_BASE}/api/history/${id}`);
  const data = await res.json();
  if (!res.ok) return;

  urlInput.value = data.url;
  clearStatus();
  renderCrawlInfo(data.summary, null);
  renderSummary(data.summary);
  renderFindings(data.findings);
}

form.addEventListener("submit", (e) => {
  e.preventDefault();
  const url = urlInput.value.trim();
  if (url) runScan(url);
});

demoScanBtn.addEventListener("click", () => {
  runDemoScan();
});

loadHistory();
