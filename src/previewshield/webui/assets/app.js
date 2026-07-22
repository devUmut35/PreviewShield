"use strict";

import { filterItems, githubAction } from "./logic.mjs";

const csrfToken = document.body.dataset.csrfToken || "";
const privateTargetsEnabled = document.body.dataset.privateEnabled === "true";
const form = document.getElementById("scan-form");
const runButton = document.getElementById("run-button");
const formError = document.getElementById("form-error");
const results = document.getElementById("results");
const resultsTitle = document.getElementById("results-title");
const findingTemplate = document.getElementById("finding-template");
const metricTemplate = document.getElementById("metric-template");
const allowPrivate = document.getElementById("allow-private");
const authorizedPrivate = document.getElementById("authorized-private");
const authorizationRow = document.getElementById("authorization-row");
const privateLocked = document.getElementById("private-locked");
const privateControls = document.getElementById("private-controls");

const state = {
  mode: "diff",
  resultMode: null,
  busy: false,
  resultId: null,
  report: null,
  items: [],
  activeFilter: "all",
  lastRequest: null,
};

const extensions = {
  html: "html",
  json: "json",
  junit: "xml",
  markdown: "md",
  sarif: "sarif",
};

function element(id) {
  return document.getElementById(id);
}

function asText(value, fallback = "—") {
  if (value === null || value === undefined || value === "") {
    return fallback;
  }
  return String(value);
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function setMode(mode) {
  if (state.busy) {
    return;
  }
  state.mode = mode;
  const isDiff = mode === "diff";
  document.querySelectorAll("[data-mode]").forEach((button) => {
    const active = button.dataset.mode === mode;
    button.classList.toggle("is-active", active);
    button.setAttribute("aria-selected", String(active));
    button.tabIndex = active ? 0 : -1;
  });
  element("diff-fields").hidden = !isDiff;
  element("scan-fields").hidden = isDiff;
  element("baseline").required = isDiff;
  element("preview").required = isDiff;
  element("target").required = !isDiff;
  runButton.querySelector(".button-idle").textContent = isDiff
    ? "Compare security"
    : "Run security scan";
  clearError();
}

document.querySelectorAll("[data-mode]").forEach((button) => {
  button.addEventListener("click", () => setMode(button.dataset.mode));
  button.addEventListener("keydown", (event) => {
    if (!new Set(["ArrowLeft", "ArrowRight"]).has(event.key)) {
      return;
    }
    event.preventDefault();
    const nextMode = button.dataset.mode === "diff" ? "scan" : "diff";
    setMode(nextMode);
    document.querySelector(`[data-mode="${nextMode}"]`).focus();
  });
});

if (privateTargetsEnabled) {
  privateLocked.hidden = true;
  privateControls.hidden = false;
} else {
  privateLocked.hidden = false;
  privateControls.hidden = true;
}

allowPrivate.addEventListener("change", () => {
  authorizationRow.hidden = !allowPrivate.checked;
  authorizedPrivate.required = allowPrivate.checked;
  if (!allowPrivate.checked) {
    authorizedPrivate.checked = false;
  }
});

function clearError() {
  formError.hidden = true;
  formError.textContent = "";
}

function showError(message) {
  formError.textContent = message;
  formError.hidden = false;
  formError.focus?.();
}

function setBusy(busy) {
  state.busy = busy;
  runButton.disabled = busy;
  runButton.classList.toggle("is-busy", busy);
  form.setAttribute("aria-busy", String(busy));
  document.querySelectorAll("[data-mode]").forEach((button) => {
    button.disabled = busy;
  });
}

function requestPayload(mode) {
  const routeLines = element("paths").value
    .split(/\r?\n/u)
    .map((route) => route.trim())
    .filter(Boolean);
  const profile = form.querySelector('input[name="profile"]:checked').value;
  const payload = {
    profile,
    paths: routeLines,
    fail_on: element("fail-on").value,
    allow_private: privateTargetsEnabled && allowPrivate.checked,
    authorized_private:
      privateTargetsEnabled && allowPrivate.checked && authorizedPrivate.checked,
  };
  if (mode === "diff") {
    payload.baseline = element("baseline").value.trim();
    payload.preview = element("preview").value.trim();
  } else {
    payload.target = element("target").value.trim();
  }
  return payload;
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearError();
  if (!form.checkValidity()) {
    form.reportValidity();
    return;
  }
  const requestMode = state.mode;
  const payload = requestPayload(requestMode);
  if (payload.paths.length === 0) {
    showError("Add at least one route, such as /.");
    return;
  }
  if (payload.paths.length > 20) {
    showError("The browser interface accepts at most 20 routes.");
    return;
  }

  setBusy(true);
  try {
    const response = await fetch(`/api/v1/${requestMode}`, {
      method: "POST",
      credentials: "same-origin",
      cache: "no-store",
      headers: {
        "Content-Type": "application/json",
        "X-PreviewShield-CSRF": csrfToken,
      },
      body: JSON.stringify(payload),
    });
    const data = await response.json();
    if (!response.ok || data.ok !== true) {
      throw new Error(asText(data.error, "The scan could not be completed."));
    }
    renderResult(data);
    state.lastRequest = { mode: requestMode, payload };
  } catch (error) {
    showError(error instanceof Error ? error.message : "The scan could not be completed.");
  } finally {
    setBusy(false);
  }
});

function renderResult(data) {
  state.resultId = asText(data.result_id, "");
  state.report = data.report || {};
  const isDiff = data.kind === "diff";
  state.resultMode = isDiff ? "diff" : "scan";
  const report = state.report;
  const passed = report.passed === true;
  const threshold = asText(report.fail_on, "configured");

  element("verdict").textContent = passed ? "PASS" : "BLOCK";
  element("verdict-panel").dataset.state = passed ? "pass" : "block";
  element("verdict-copy").textContent = isDiff
    ? passed
      ? `No new ${threshold}-or-higher regressions were detected.`
      : `The preview introduced a ${threshold}-or-higher security regression.`
    : passed
      ? `No ${threshold}-or-higher findings crossed the configured policy.`
      : `This deployment has ${threshold}-or-higher findings that need attention.`;
  element("policy-name").textContent = asText(report.policy_name, "Built-in policy");
  element("generated-at").textContent = formatDate(report.generated_at);

  if (isDiff) {
    renderDiffScores(report);
    state.items = asArray(report.deltas).map((delta) => ({
      kind: asText(delta.kind, "changed"),
      finding: delta.preview || delta.baseline || {},
    }));
    renderMetrics([
      metric("Regressions", countKind("regression"), "New or more severe"),
      metric("Resolved", countKind("resolved"), "Removed in preview"),
      metric("Changed", countKind("changed"), "Content changed"),
      metric("Unchanged", countKind("unchanged"), "Existing debt"),
    ]);
    element("findings-title").textContent = "What changed?";
    state.activeFilter = countKind("regression") > 0 ? "regression" : "all";
    renderFilters(["all", "regression", "resolved", "changed", "unchanged"]);
  } else {
    renderScanScore(report);
    state.items = asArray(report.routes).flatMap((route) =>
      asArray(route.findings).map((finding) => ({ kind: "finding", finding })),
    );
    renderMetrics([
      metric("Critical", countSeverity("critical"), "Immediate action"),
      metric("High", countSeverity("high"), "Release concern"),
      metric("Medium", countSeverity("medium"), "Hardening gap"),
      metric("Total", state.items.length, "Across all routes"),
    ]);
    element("findings-title").textContent = "What to fix?";
    state.activeFilter = "all";
    renderFilters(["all", "critical", "high", "medium", "low", "info"]);
  }

  renderFindings();
  results.hidden = false;
  results.scrollIntoView({ behavior: "smooth", block: "start" });
  resultsTitle.focus({ preventScroll: true });
}

function renderDiffScores(report) {
  const baseline = report.baseline || {};
  const preview = report.preview || {};
  const seam = element("security-seam");
  seam.classList.remove("is-single");
  element("preview-score-side").hidden = false;
  seam.querySelector(".seam-spine").hidden = false;
  element("left-label").textContent = "Production";
  element("left-grade").textContent = asText(baseline.grade);
  element("left-score").textContent = `${asText(baseline.score)}/100`;
  element("left-target").textContent = asText(baseline.target);
  element("right-grade").textContent = asText(preview.grade);
  element("right-score").textContent = `${asText(preview.score)}/100`;
  element("right-target").textContent = asText(preview.target);
  const baselineScore = Number(baseline.score);
  const previewScore = Number(preview.score);
  const delta = Number.isFinite(baselineScore) && Number.isFinite(previewScore)
    ? previewScore - baselineScore
    : null;
  element("score-delta").textContent = delta === null ? "—" : `${delta > 0 ? "+" : ""}${delta}`;
}

function renderScanScore(report) {
  const seam = element("security-seam");
  seam.classList.add("is-single");
  element("preview-score-side").hidden = true;
  seam.querySelector(".seam-spine").hidden = true;
  element("left-label").textContent = "Deployment";
  element("left-grade").textContent = asText(report.grade);
  element("left-score").textContent = `${asText(report.score)}/100`;
  element("left-target").textContent = asText(report.target);
}

function metric(label, value, detail) {
  return { label, value, detail };
}

function renderMetrics(metrics) {
  const container = element("metrics");
  container.replaceChildren();
  metrics.forEach((item) => {
    const card = metricTemplate.content.firstElementChild.cloneNode(true);
    card.querySelector(".metric-label").textContent = item.label;
    card.querySelector(".metric-value").textContent = String(item.value);
    card.querySelector(".metric-detail").textContent = item.detail;
    container.append(card);
  });
}

function countKind(kind) {
  return state.items.filter((item) => item.kind === kind).length;
}

function countSeverity(severity) {
  return state.items.filter((item) => item.finding?.severity === severity).length;
}

function renderFilters(filters) {
  const row = element("filter-row");
  row.replaceChildren();
  filters.forEach((filter) => {
    const count = filter === "all"
      ? state.items.length
      : state.resultMode === "diff"
        ? countKind(filter)
        : countSeverity(filter);
    if (filter !== "all" && count === 0) {
      return;
    }
    const button = document.createElement("button");
    button.type = "button";
    button.dataset.filter = filter;
    button.setAttribute("aria-pressed", String(filter === state.activeFilter));
    button.textContent = `${labelFor(filter)} · ${count}`;
    button.addEventListener("click", () => {
      state.activeFilter = filter;
      row.querySelectorAll("button").forEach((item) => {
        item.setAttribute("aria-pressed", String(item.dataset.filter === filter));
      });
      renderFindings();
    });
    row.append(button);
  });
}

function filteredItems() {
  return filterItems(state.items, state.activeFilter, state.resultMode);
}

function renderFindings() {
  const list = element("finding-list");
  const items = filteredItems();
  list.replaceChildren();
  items.forEach((item) => list.append(findingCard(item)));
  element("finding-total").textContent = `${items.length} ${items.length === 1 ? "finding" : "findings"}`;
  element("empty-findings").hidden = items.length !== 0;
}

function findingCard(item) {
  const card = findingTemplate.content.firstElementChild.cloneNode(true);
  const finding = item.finding || {};
  card.dataset.kind = item.kind;
  card.querySelector(".finding-kind").textContent = labelFor(item.kind);
  card.querySelector(".finding-severity").textContent = asText(finding.severity, "unknown");
  card.querySelector(".finding-rule").textContent = asText(finding.rule_id, "RULE");
  card.querySelector(".finding-title").textContent = asText(finding.title, "Security finding");
  card.querySelector(".finding-target").textContent = asText(finding.target, "Target unavailable");
  card.querySelector(".finding-message").textContent = asText(finding.message, "No detail provided.");
  card.querySelector(".finding-remediation").textContent = asText(
    finding.remediation,
    "Review the affected security control.",
  );
  const evidence = card.querySelector(".finding-evidence");
  if (finding.evidence) {
    evidence.textContent = `Evidence: ${finding.evidence}`;
    evidence.hidden = false;
  }
  return card;
}

function labelFor(value) {
  const labels = {
    all: "All",
    regression: "Regression",
    resolved: "Resolved",
    changed: "Changed",
    unchanged: "Unchanged",
    finding: "Finding",
    critical: "Critical",
    high: "High",
    medium: "Medium",
    low: "Low",
    info: "Info",
  };
  return labels[value] || asText(value);
}

function formatDate(value) {
  if (typeof value !== "string") {
    return "Generated now";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

element("download-report").addEventListener("click", async () => {
  if (!state.resultId) {
    setExportStatus("Run a scan before downloading a report.", true);
    return;
  }
  const format = element("export-format").value;
  try {
    const response = await fetch(`/api/v1/reports/${state.resultId}/${format}`, {
      credentials: "same-origin",
      cache: "no-store",
      headers: { "X-PreviewShield-CSRF": csrfToken },
    });
    if (!response.ok) {
      throw new Error("The report download failed.");
    }
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `previewshield-report.${extensions[format] || "txt"}`;
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
    setExportStatus(`${labelFor(format)} report downloaded.`);
  } catch (error) {
    setExportStatus(error instanceof Error ? error.message : "The report download failed.", true);
  }
});

element("copy-action").addEventListener("click", async () => {
  if (!state.lastRequest) {
    setExportStatus("Run a scan before copying an Action example.", true);
    return;
  }
  try {
    await copyText(githubAction(state.lastRequest.mode, state.lastRequest.payload));
    setExportStatus("GitHub Action YAML copied to the clipboard.");
  } catch {
    setExportStatus("Clipboard access was unavailable.", true);
  }
});

async function copyText(value) {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(value);
    return;
  }
  const textarea = document.createElement("textarea");
  textarea.value = value;
  textarea.className = "visually-hidden";
  document.body.append(textarea);
  textarea.select();
  const copied = document.execCommand("copy");
  textarea.remove();
  if (!copied) {
    throw new Error("Copy failed");
  }
}

function setExportStatus(message, isError = false) {
  const status = element("export-status");
  status.textContent = message;
  status.dataset.state = isError ? "error" : "ok";
}

setMode("diff");
