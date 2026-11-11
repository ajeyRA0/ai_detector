/**
 * PhishGuard - Frontend Logic & Interactivity
 * Handles client-side URL analysis, bulk scanning, CSV export, history caching, and feedback reporting.
 */

document.addEventListener("DOMContentLoaded", () => {
  // Elements
  const scanForm = document.getElementById("scan-form");
  const urlInput = document.getElementById("url-input");
  const clearBtn = document.getElementById("clear-btn");
  const analyzeBtn = document.getElementById("analyze-btn");
  const btnSpinner = document.getElementById("btn-spinner");
  const errorBanner = document.getElementById("error-banner");
  const errorText = document.getElementById("error-text");

  const resultsSection = document.getElementById("results-section");
  const verdictBanner = document.getElementById("verdict-banner");
  const verdictIcon = document.getElementById("verdict-icon");
  const verdictTitle = document.getElementById("verdict-title");
  const verdictPill = document.getElementById("verdict-pill");
  const riskPill = document.getElementById("risk-pill");
  const confidencePill = document.getElementById("confidence-pill");
  const verdictUrl = document.getElementById("verdict-url");

  const meterPercentDisplay = document.getElementById("meter-percent-display");
  const meterFill = document.getElementById("meter-fill");
  const reasonsList = document.getElementById("reasons-list");
  const featuresTbody = document.getElementById("features-tbody");
  const importanceBarsContainer = document.getElementById("importance-bars-container");

  // Bulk Elements
  const bulkTextarea = document.getElementById("bulk-textarea");
  const bulkFileInput = document.getElementById("bulk-file-input");
  const bulkScanBtn = document.getElementById("bulk-scan-btn");
  const bulkClearBtn = document.getElementById("bulk-clear-btn");
  const bulkDownloadBtn = document.getElementById("bulk-download-btn");
  const bulkResultsWrapper = document.getElementById("bulk-results-wrapper");
  const bulkTbody = document.getElementById("bulk-tbody");

  // History Elements
  const historyEmpty = document.getElementById("history-empty");
  const historyTableWrapper = document.getElementById("history-table-wrapper");
  const historyTbody = document.getElementById("history-tbody");
  const clearHistoryBtn = document.getElementById("clear-history-btn");

  // Feedback Modal Elements
  const openReportBtn = document.getElementById("open-report-btn");
  const feedbackModal = document.getElementById("feedback-modal");
  const closeModalBtn = document.getElementById("close-modal-btn");
  const cancelModalBtn = document.getElementById("cancel-modal-btn");
  const feedbackForm = document.getElementById("feedback-form");
  const feedbackUrlInput = document.getElementById("feedback-url");
  const feedbackNotes = document.getElementById("feedback-notes");
  const feedbackStatus = document.getElementById("feedback-status");

  let currentBulkResults = [];

  // ==========================================
  // Helper: Feature Interpretations for Table
  // ==========================================
  const FEATURE_DESCRIPTIONS = {
    url_length: { desc: "Length of total URL string", safe: (v) => v <= 75 },
    domain_length: { desc: "Length of hostname/domain", safe: (v) => v <= 22 },
    num_dots: { desc: "Dot delimiter count", safe: (v) => v <= 3 },
    num_hyphens: { desc: "Hyphen count (brand impersonation indicator)", safe: (v) => v <= 1 },
    num_at_symbols: { desc: "@ credential spoofing symbol", safe: (v) => v === 0 },
    num_question_marks: { desc: "Query delimiter count", safe: (v) => v <= 1 },
    num_equal_signs: { desc: "URL parameter depth", safe: (v) => v <= 2 },
    num_underscores: { desc: "Underscore character count", safe: (v) => v <= 1 },
    num_digits: { desc: "Numeric digits in URL", safe: (v) => v <= 4 },
    num_subdomains: { desc: "Nested subdomain count", safe: (v) => v <= 1 },
    has_ip_address: { desc: "Direct IP address host usage", safe: (v) => v === 0 },
    has_https: { desc: "Encrypted HTTPS scheme indicator", safe: (v) => v === 1 },
    path_length: { desc: "URL directory path length", safe: (v) => v <= 45 },
    has_suspicious_word: { desc: "Phishing lure keywords (login, verify, etc.)", safe: (v) => v === 0 },
    num_slashes: { desc: "Path separator slash count", safe: (v) => v <= 4 },
  };

  // ==========================================
  // URL Scanner Logic
  // ==========================================
  clearBtn.addEventListener("click", () => {
    urlInput.value = "";
    urlInput.focus();
  });

  document.querySelectorAll(".pill-btn").forEach((pill) => {
    pill.addEventListener("click", () => {
      const sampleUrl = pill.getAttribute("data-url");
      if (sampleUrl) {
        urlInput.value = sampleUrl;
        triggerScan(sampleUrl);
      }
    });
  });

  scanForm.addEventListener("submit", (e) => {
    e.preventDefault();
    const url = urlInput.value.trim();
    if (!url) {
      showError("Please enter a valid URL to analyze.");
      return;
    }
    triggerScan(url);
  });

  async function triggerScan(url) {
    hideError();
    setScanningState(true);

    try {
      const response = await fetch("/api/predict", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Failed to analyze URL.");
      }

      displayResults(data);
      saveToHistory(data);
    } catch (err) {
      showError(err.message || "Network error. Could not reach PhishGuard API.");
    } finally {
      setScanningState(false);
    }
  }

  function setScanningState(isScanning) {
    analyzeBtn.disabled = isScanning;
    btnSpinner.hidden = !isScanning;
    const btnText = analyzeBtn.querySelector(".btn-text");
    if (btnText) btnText.textContent = isScanning ? "Analyzing..." : "Analyze URL";
  }

  function showError(msg) {
    errorText.textContent = msg;
    errorBanner.hidden = false;
  }

  function hideError() {
    errorBanner.hidden = true;
  }

  // ==========================================
  // Render Scan Results
  // ==========================================
  function displayResults(data) {
    const isPhishing = data.verdict === "Phishing";
    const prob = data.phishing_probability;

    // 1. Verdict Card
    verdictBanner.className = `verdict-card ${isPhishing ? "phish" : "safe"}`;
    verdictTitle.textContent = isPhishing ? "Phishing URL Detected" : "Legitimate URL (Safe)";
    verdictUrl.textContent = data.url;

    verdictPill.className = `badge ${isPhishing ? "badge-danger" : "badge-success"}`;
    verdictPill.textContent = data.verdict;

    riskPill.className = `badge ${
      data.risk_level === "Severe" || data.risk_level === "High"
        ? "badge-danger"
        : data.risk_level === "Moderate"
        ? "badge-warning"
        : "badge-success"
    }`;
    riskPill.textContent = `Risk: ${data.risk_level}`;

    confidencePill.textContent = `Confidence: ${data.confidence}`;

    // Verdict SVG Icon
    if (isPhishing) {
      verdictIcon.innerHTML = `
        <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
          <circle cx="12" cy="12" r="10"/>
          <line x1="12" y1="8" x2="12" y2="12"/>
          <line x1="12" y1="16" x2="12.01" y2="16"/>
        </svg>`;
    } else {
      verdictIcon.innerHTML = `
        <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          <polyline points="9 12 11 14 15 10"/>
        </svg>`;
    }

    // 2. Probability Meter
    const pct = (prob * 100).toFixed(1);
    meterPercentDisplay.textContent = `${pct}%`;
    meterFill.style.width = `${pct}%`;

    if (prob >= 0.5) {
      meterFill.style.backgroundColor = "var(--color-danger)";
      meterPercentDisplay.style.color = "var(--color-danger)";
    } else if (prob >= 0.25) {
      meterFill.style.backgroundColor = "var(--color-warning)";
      meterPercentDisplay.style.color = "var(--color-warning)";
    } else {
      meterFill.style.backgroundColor = "var(--color-safe)";
      meterPercentDisplay.style.color = "var(--color-safe)";
    }

    // 3. Reasons List
    reasonsList.innerHTML = "";
    (data.reasons || []).forEach((reason) => {
      const li = document.createElement("li");
      const isNegative =
        reason.includes("uses a raw IP") ||
        reason.includes("@") ||
        reason.includes("phishing lure") ||
        reason.includes("does not use HTTPS") ||
        reason.includes("subdomain") ||
        reason.includes("hyphen") ||
        reason.includes("long URL") ||
        reason.includes("digit");

      li.className = `reason-item ${isNegative ? (isPhishing ? "danger" : "warning") : "safe"}`;

      const iconSvg = isNegative
        ? `<svg class="reason-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`
        : `<svg class="reason-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>`;

      li.innerHTML = `${iconSvg}<span>${reason}</span>`;
      reasonsList.appendChild(li);
    });

    // 4. 15 Features Table
    featuresTbody.innerHTML = "";
    const feats = data.features || {};
    for (const [key, val] of Object.entries(feats)) {
      const meta = FEATURE_DESCRIPTIONS[key] || { desc: "Structural parameter", safe: () => true };
      const isSafe = meta.safe(val);

      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><code>${key}</code></td>
        <td class="mono font-bold">${val}</td>
        <td>${meta.desc}</td>
        <td>
          <span class="badge ${isSafe ? "badge-success" : isPhishing ? "badge-danger" : "badge-warning"}">
            ${isSafe ? "Normal" : "Anomalous"}
          </span>
        </td>
      `;
      featuresTbody.appendChild(tr);
    }

    // 5. Global Feature Importances Chart
    importanceBarsContainer.innerHTML = "";
    const importances = data.importances || {};
    const sorted = Object.entries(importances).sort((a, b) => b[1] - a[1]);

    sorted.slice(0, 8).forEach(([fName, score]) => {
      const pctVal = (score * 100).toFixed(1);
      const row = document.createElement("div");
      row.className = "importance-row";
      row.innerHTML = `
        <span class="importance-name" title="${fName}">${fName}</span>
        <div class="importance-track">
          <div class="importance-bar" style="width: ${pctVal}%"></div>
        </div>
        <span class="importance-val">${pctVal}%</span>
      `;
      importanceBarsContainer.appendChild(row);
    });

    resultsSection.hidden = false;
    resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  // ==========================================
  // Bulk Scan & CSV Export
  // ==========================================
  bulkClearBtn.addEventListener("click", () => {
    bulkTextarea.value = "";
    bulkResultsWrapper.hidden = true;
    bulkDownloadBtn.disabled = true;
    currentBulkResults = [];
  });

  bulkFileInput.addEventListener("change", (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      bulkTextarea.value = event.target.result;
    };
    reader.readAsText(file);
  });

  bulkScanBtn.addEventListener("click", async () => {
    const text = bulkTextarea.value.trim();
    if (!text) {
      alert("Please paste or upload URLs to scan.");
      return;
    }

    const urls = text
      .split("\n")
      .map((u) => u.trim())
      .filter((u) => u.length > 0 && !u.toLowerCase().startsWith("url"));

    if (urls.length === 0) {
      alert("No valid URLs found.");
      return;
    }

    bulkScanBtn.disabled = true;
    bulkScanBtn.textContent = "Scanning...";

    try {
      const resp = await fetch("/api/bulk-predict", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ urls: urls.slice(0, 100) }),
      });
      const data = await resp.json();

      if (!resp.ok) {
        throw new Error(data.error || "Bulk scan failed.");
      }

      currentBulkResults = data.results || [];
      renderBulkTable(currentBulkResults);
      bulkDownloadBtn.disabled = currentBulkResults.length === 0;
    } catch (err) {
      alert(`Bulk Error: ${err.message}`);
    } finally {
      bulkScanBtn.disabled = false;
      bulkScanBtn.textContent = "Scan Bulk URLs";
    }
  });

  function renderBulkTable(results) {
    bulkTbody.innerHTML = "";
    results.forEach((r, idx) => {
      const isPhish = r.verdict === "Phishing";
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${idx + 1}</td>
        <td class="mono font-bold" style="max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${r.url}">
          ${r.url}
        </td>
        <td>
          <span class="badge ${isPhish ? "badge-danger" : "badge-success"}">${r.verdict}</span>
        </td>
        <td><span class="badge ${r.risk_level === "Severe" || r.risk_level === "High" ? "badge-danger" : "badge-neutral"}">${r.risk_level}</span></td>
        <td class="mono font-bold">${(r.phishing_probability * 100).toFixed(1)}%</td>
        <td class="mono">${r.confidence}</td>
      `;
      bulkTbody.appendChild(tr);
    });
    bulkResultsWrapper.hidden = false;
  }

  bulkDownloadBtn.addEventListener("click", () => {
    if (!currentBulkResults.length) return;

    let csvContent = "data:text/csv;charset=utf-8,url,verdict,risk_level,phishing_probability,confidence\n";
    currentBulkResults.forEach((r) => {
      const cleanUrl = `"${r.url.replace(/"/g, '""')}"`;
      csvContent += `${cleanUrl},${r.verdict},${r.risk_level},${r.phishing_probability},${r.confidence}\n`;
    });

    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `phishguard_scan_results_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  });

  // ==========================================
  // LocalStorage Scan History
  // ==========================================
  const HISTORY_KEY = "phishguard_history";

  function getHistory() {
    try {
      return JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
    } catch {
      return [];
    }
  }

  function saveToHistory(item) {
    const list = getHistory();
    const entry = {
      url: item.url,
      verdict: item.verdict,
      risk_level: item.risk_level,
      prob: item.phishing_probability,
      timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
    };

    // Keep unique recent URLs, max 20
    const filtered = list.filter((x) => x.url !== entry.url);
    filtered.unshift(entry);
    const trimmed = filtered.slice(0, 20);

    localStorage.setItem(HISTORY_KEY, JSON.stringify(trimmed));
    renderHistory();
  }

  function renderHistory() {
    const list = getHistory();
    if (!list.length) {
      historyEmpty.hidden = false;
      historyTableWrapper.hidden = true;
      return;
    }

    historyEmpty.hidden = true;
    historyTableWrapper.hidden = false;
    historyTbody.innerHTML = "";

    list.forEach((item) => {
      const tr = document.createElement("tr");
      const isPhish = item.verdict === "Phishing";
      tr.innerHTML = `
        <td class="mono font-muted">${item.timestamp}</td>
        <td class="mono" style="max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${item.url}">
          ${item.url}
        </td>
        <td><span class="badge ${isPhish ? "badge-danger" : "badge-success"}">${item.verdict}</span></td>
        <td class="mono font-bold">${(item.prob * 100).toFixed(1)}%</td>
        <td>
          <button type="button" class="btn btn-ghost btn-sm recheck-btn" data-url="${item.url}">
            Re-scan
          </button>
        </td>
      `;
      historyTbody.appendChild(tr);
    });

    document.querySelectorAll(".recheck-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        const u = btn.getAttribute("data-url");
        if (u) {
          urlInput.value = u;
          triggerScan(u);
        }
      });
    });
  }

  clearHistoryBtn.addEventListener("click", () => {
    if (confirm("Are you sure you want to clear your local scan history?")) {
      localStorage.removeItem(HISTORY_KEY);
      renderHistory();
    }
  });

  // ==========================================
  // Report URL Feedback Modal
  // ==========================================
  openReportBtn.addEventListener("click", () => {
    feedbackUrlInput.value = verdictUrl.textContent || urlInput.value;
    feedbackNotes.value = "";
    feedbackStatus.hidden = true;
    feedbackModal.hidden = false;
  });

  function closeFeedbackModal() {
    feedbackModal.hidden = true;
  }

  closeModalBtn.addEventListener("click", closeFeedbackModal);
  cancelModalBtn.addEventListener("click", closeFeedbackModal);

  feedbackModal.addEventListener("click", (e) => {
    if (e.target === feedbackModal) closeFeedbackModal();
  });

  feedbackForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const url = feedbackUrlInput.value.trim();
    const suggestedLabel = feedbackForm.querySelector('input[name="suggested_label"]:checked').value;
    const notes = feedbackNotes.value.trim();

    try {
      const resp = await fetch("/api/feedback", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url, suggested_label: suggestedLabel, notes }),
      });
      const res = await resp.json();

      if (!resp.ok) {
        throw new Error(res.error || "Failed to submit feedback.");
      }

      feedbackStatus.textContent = res.message;
      feedbackStatus.hidden = false;
      setTimeout(() => {
        closeFeedbackModal();
      }, 1800);
    } catch (err) {
      alert(`Feedback Error: ${err.message}`);
    }
  });

  // Initial load
  renderHistory();
});
