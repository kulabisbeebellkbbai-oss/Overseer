"""Static operator console served by the loopback API."""

from __future__ import annotations


OPERATOR_CONSOLE_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Overseer</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f6f7f9;
      --panel: #ffffff;
      --panel-2: #eef2f5;
      --line: #ccd4dd;
      --text: #17202a;
      --muted: #5f6f7f;
      --good: #176d3b;
      --warn: #9a5b00;
      --bad: #a3262a;
      --focus: #0f6b8f;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-width: 320px;
      background: var(--bg);
      color: var(--text);
      font: 14px/1.45 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    button, input, select {
      font: inherit;
    }
    .shell {
      min-height: 100vh;
      display: grid;
      grid-template-columns: 260px minmax(0, 1fr);
    }
    aside {
      background: #202832;
      color: #f8fafc;
      padding: 18px 14px;
      border-right: 1px solid #111820;
    }
    main {
      min-width: 0;
      padding: 18px;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 18px;
    }
    .mark {
      width: 34px;
      height: 34px;
      border-radius: 6px;
      background: #d8aa3a;
      color: #111820;
      display: grid;
      place-items: center;
      font-weight: 800;
    }
    h1, h2, h3, p { margin: 0; }
    h1 { font-size: 20px; font-weight: 760; letter-spacing: 0; }
    h2 { font-size: 17px; font-weight: 720; }
    h3 { font-size: 14px; font-weight: 700; color: var(--muted); }
    .nav {
      display: grid;
      gap: 5px;
    }
    .nav button {
      width: 100%;
      border: 0;
      border-radius: 6px;
      padding: 9px 10px;
      background: transparent;
      color: #dce5ed;
      text-align: left;
      cursor: pointer;
    }
    .nav button[aria-selected="true"] {
      background: #344252;
      color: #ffffff;
    }
    .topbar {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 12px;
      align-items: center;
      margin-bottom: 16px;
    }
    .status-line {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
      color: var(--muted);
    }
    .token {
      display: flex;
      gap: 8px;
      align-items: center;
    }
    .token input {
      width: 230px;
      min-width: 0;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 8px 10px;
      background: #fff;
      color: var(--text);
    }
    .icon-btn, .action-btn {
      border: 1px solid var(--line);
      border-radius: 6px;
      min-height: 36px;
      background: #fff;
      color: var(--text);
      cursor: pointer;
    }
    .icon-btn {
      width: 38px;
      display: grid;
      place-items: center;
    }
    .action-btn {
      padding: 7px 12px;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(12, minmax(0, 1fr));
      gap: 12px;
    }
    .panel {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 14px;
      min-width: 0;
    }
    .span-3 { grid-column: span 3; }
    .span-4 { grid-column: span 4; }
    .span-6 { grid-column: span 6; }
    .span-8 { grid-column: span 8; }
    .span-12 { grid-column: span 12; }
    .metric {
      display: grid;
      gap: 6px;
      min-height: 92px;
    }
    .metric .value {
      font-size: 30px;
      line-height: 1;
      font-weight: 780;
    }
    .muted { color: var(--muted); }
    .pill {
      display: inline-flex;
      align-items: center;
      min-height: 24px;
      padding: 2px 8px;
      border-radius: 999px;
      border: 1px solid var(--line);
      background: var(--panel-2);
      color: var(--text);
      font-size: 12px;
      white-space: nowrap;
    }
    .pill.good { color: var(--good); border-color: #9cc9ad; background: #eef8f1; }
    .pill.warn { color: var(--warn); border-color: #dfc17d; background: #fff7df; }
    .pill.bad { color: var(--bad); border-color: #dda0a2; background: #fff0f0; }
    table {
      width: 100%;
      border-collapse: collapse;
      table-layout: fixed;
    }
    .table-scroll {
      width: 100%;
      max-width: 100%;
      overflow-x: auto;
    }
    th, td {
      border-bottom: 1px solid var(--line);
      padding: 8px 6px;
      text-align: left;
      vertical-align: top;
      overflow-wrap: anywhere;
    }
    th {
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
    }
    tr:last-child td { border-bottom: 0; }
    .section {
      display: none;
    }
    .section.active {
      display: block;
    }
    .stack {
      display: grid;
      gap: 12px;
    }
    .toolbar {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 10px;
    }
    .actions {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
    }
    .form-grid {
      display: grid;
      grid-template-columns: repeat(6, minmax(0, 1fr));
      gap: 10px;
      align-items: end;
    }
    .field {
      display: grid;
      gap: 4px;
      min-width: 0;
    }
    .field.span-2 { grid-column: span 2; }
    .field.span-3 { grid-column: span 3; }
    .field.span-6 { grid-column: span 6; }
    label {
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
    }
    .field input, .field select {
      width: 100%;
      min-height: 36px;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 7px 9px;
      background: #fff;
      color: var(--text);
      min-width: 0;
    }
    .action-status {
      margin-bottom: 12px;
    }
    .section-head {
      grid-column: span 12;
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
      justify-content: space-between;
      padding: 2px 0;
    }
    .list {
      display: grid;
      gap: 8px;
    }
    .row {
      display: grid;
      grid-template-columns: minmax(0, 1fr) minmax(0, 45%);
      gap: 10px;
      align-items: center;
      padding: 9px 0;
      border-bottom: 1px solid var(--line);
    }
    .row span, .row strong {
      min-width: 0;
      overflow-wrap: anywhere;
    }
    .row strong {
      text-align: right;
    }
    .row:last-child { border-bottom: 0; }
    .error {
      border-color: #dda0a2;
      background: #fff0f0;
      color: var(--bad);
    }
    @media (max-width: 900px) {
      .shell { grid-template-columns: 1fr; }
      aside {
        position: sticky;
        top: 0;
        z-index: 2;
        border-right: 0;
        border-bottom: 1px solid #111820;
      }
      .nav {
        grid-template-columns: repeat(4, minmax(0, 1fr));
      }
      .nav button {
        text-align: center;
      }
      .topbar {
        grid-template-columns: 1fr;
      }
      .token {
        width: 100%;
      }
      .token input {
        flex: 1;
      }
      .span-3, .span-4, .span-6, .span-8 { grid-column: span 12; }
      .field.span-2, .field.span-3 { grid-column: span 6; }
    }
    @media (max-width: 520px) {
      main { padding: 12px; }
      aside { padding: 12px; }
      .nav { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .grid { gap: 8px; }
      .panel { padding: 11px; }
      .token { flex-wrap: wrap; }
      .token input { width: 100%; flex-basis: 100%; }
      .field.span-2, .field.span-3, .field.span-6 { grid-column: span 6; }
    }
  </style>
</head>
<body>
  <div class="shell">
    <aside>
      <div class="brand">
        <div class="mark">O</div>
        <div>
          <h1>Overseer</h1>
          <p class="muted">Local command crew</p>
        </div>
      </div>
      <nav class="nav" aria-label="Views">
        <button data-view="overview" aria-selected="true">Overview</button>
        <button data-view="admin">Admin</button>
        <button data-view="assets">Assets</button>
        <button data-view="claims">Claims</button>
        <button data-view="security">Security</button>
        <button data-view="health">Health</button>
        <button data-view="usage">Usage</button>
        <button data-view="audit">Audit</button>
      </nav>
    </aside>
    <main>
      <div class="topbar">
        <div>
          <h2 id="view-title">Overview</h2>
          <div class="status-line">
            <span id="overall" class="pill">loading</span>
            <span id="updated" class="muted">not refreshed</span>
          </div>
        </div>
        <div class="token">
          <input id="token" type="password" autocomplete="off" placeholder="Bearer token">
          <button id="save-token" class="action-btn">Save</button>
          <button id="refresh" class="icon-btn" title="Refresh" aria-label="Refresh">R</button>
        </div>
      </div>
      <div id="error" class="panel error" hidden></div>
      <div id="action-status" class="panel action-status" hidden></div>
      <section id="overview" class="section active"></section>
      <section id="admin" class="section"></section>
      <section id="assets" class="section"></section>
      <section id="claims" class="section"></section>
      <section id="security" class="section"></section>
      <section id="health" class="section"></section>
      <section id="usage" class="section"></section>
      <section id="audit" class="section"></section>
    </main>
  </div>
  <script>
    const endpoints = {
      dashboard: "/operator-dashboard",
      authorizations: "/admin/authorizations-required",
      readiness: "/admin/execution-readiness",
      adapters: "/admin/adapter-capabilities",
      activePolicy: "/admin/active-policy-profile",
      packageStatus: "/maintenance/package-status",
      physical: "/physical-summary",
      virtual: "/virtual-summary",
      security: "/security-summary",
      health: "/health-efficiency",
      healthSummary: "/health-summary",
      usage: "/usage-summary",
      audit: "/audit-summary",
      approvals: "/approvals-summary",
      claims: "/claims/review",
      claimCleanup: "/claims/cleanup-plan"
    };
    const state = {
      data: {},
      view: "overview",
      token: localStorage.getItem("overseerToken") || "",
      lastAction: null
    };
    const tokenInput = document.getElementById("token");
    tokenInput.value = state.token;
    document.getElementById("save-token").addEventListener("click", () => {
      state.token = tokenInput.value.trim();
      if (state.token) localStorage.setItem("overseerToken", state.token);
      else localStorage.removeItem("overseerToken");
      refresh();
    });
    document.getElementById("refresh").addEventListener("click", refresh);
    document.querySelectorAll(".nav button").forEach((button) => {
      button.addEventListener("click", () => selectView(button.dataset.view));
    });
    document.addEventListener("click", async (event) => {
      const button = event.target.closest("[data-action]");
      if (!button) return;
      event.preventDefault();
      await runAction(button.dataset.action);
    });
    function selectView(view) {
      state.view = view;
      document.querySelectorAll(".nav button").forEach((button) => {
        button.setAttribute("aria-selected", String(button.dataset.view === view));
      });
      document.querySelectorAll(".section").forEach((section) => {
        section.classList.toggle("active", section.id === view);
      });
      document.getElementById("view-title").textContent = title(view);
      render();
    }
    async function refresh() {
      const error = document.getElementById("error");
      error.hidden = true;
      try {
        const entries = await Promise.all(Object.entries(endpoints).map(async ([key, path]) => [key, await getJson(path)]));
        state.data = Object.fromEntries(entries);
        document.getElementById("updated").textContent = new Date().toLocaleString();
        render();
      } catch (err) {
        error.textContent = err.message;
        error.hidden = false;
      }
    }
    async function getJson(path) {
      const headers = {};
      const token = tokenInput.value.trim() || state.token;
      if (token) headers.authorization = `Bearer ${token}`;
      const response = await fetch(path, {headers});
      if (!response.ok) throw new Error(`${path}: ${response.status}`);
      return await response.json();
    }
    async function postJson(path, payload = {}) {
      const headers = {"content-type": "application/json"};
      const token = tokenInput.value.trim() || state.token;
      if (token) headers.authorization = `Bearer ${token}`;
      const response = await fetch(path, {method: "POST", headers, body: JSON.stringify(payload)});
      if (!response.ok) throw new Error(`${path}: ${response.status}`);
      return await response.json();
    }
    async function runAction(action) {
      const status = document.getElementById("action-status");
      status.hidden = false;
      status.textContent = "Running action...";
      try {
        const result = await actionRequest(action);
        state.lastAction = {action, result, at: new Date().toLocaleString()};
        await refresh();
      } catch (err) {
        status.textContent = err.message;
        status.className = "panel action-status error";
      }
    }
    async function actionRequest(action) {
      if (action === "discover-physical") return await postJson("/physical/discover", {});
      if (action === "discover-storage") return await postJson("/physical/discover-storage", {});
      if (action === "discover-listeners") return await postJson("/virtual/discover-listeners", {});
      if (action === "register-resource") return await registerResource();
      if (action === "request-claim") return await requestClaim();
      if (action === "approve-claim") return await approveClaim();
      if (action === "activate-claim") return await activateClaim();
      if (action === "release-claim") return await releaseClaim();
      if (action === "request-claim-cleanup") return await requestClaimCleanup();
      if (action === "approve-claim-cleanup") return await approveClaimCleanup();
      if (action === "execute-claim-cleanup") return await executeClaimCleanup();
      if (action === "discover-user-services") return await postJson("/services/discover-user", {});
      if (action === "discover-codex-threads") return await postJson("/codex-projects/discover-threads", {});
      if (action === "plan-package-updates") return await postJson("/maintenance/package-update-plans", {});
      if (action === "run-health-probes") return await postJson("/health/probes/run", {retention_per_target: 5});
      if (action === "register-health-target") return await registerHealthTarget();
      throw new Error(`unsupported action: ${action}`);
    }
    async function registerResource() {
      const resourceId = document.getElementById("resource-id").value.trim();
      const name = document.getElementById("resource-name").value.trim();
      const resourceType = document.getElementById("resource-type").value;
      const ownerDomain = document.getElementById("resource-owner").value;
      const riskLevel = document.getElementById("resource-risk").value;
      const identifiersText = document.getElementById("resource-identifiers").value.trim();
      const payload = {resource_id: resourceId, name, resource_type: resourceType, owner_domain: ownerDomain, risk_level: riskLevel};
      if (identifiersText) payload.identifiers = JSON.parse(identifiersText);
      return await postJson("/resources", payload);
    }
    async function requestClaim() {
      const payload = {
        claim_id: value("claim-id"),
        resource_id: value("claim-resource-id"),
        claim_type: value("claim-type"),
        owner_thread: value("claim-owner-thread"),
        owner_role: value("claim-owner-role"),
        intent: value("claim-intent"),
        requested_action: value("claim-action"),
        risk_level: value("claim-risk")
      };
      const port = value("claim-port");
      if (port) payload.ports = [Number(port)];
      const expiresAt = value("claim-expires-at");
      if (expiresAt) payload.expires_at = expiresAt;
      const releaseCondition = value("claim-release-condition");
      if (releaseCondition) payload.release_condition = releaseCondition;
      return await postJson("/claims/request", payload);
    }
    async function approveClaim() {
      return await postJson("/claims/approve", {
        approval_id: value("claim-approval-id"),
        decided_by: value("claim-decided-by")
      });
    }
    async function activateClaim() {
      const payload = {claim_id: value("claim-activate-id")};
      const approvalId = value("claim-activate-approval-id");
      if (approvalId) payload.approval_id = approvalId;
      return await postJson("/claims/activate", payload);
    }
    async function releaseClaim() {
      const payload = {claim_id: value("claim-release-id")};
      const releasedBy = value("claim-released-by");
      const reason = value("claim-release-reason");
      if (releasedBy) payload.released_by = releasedBy;
      if (reason) payload.reason = reason;
      return await postJson("/claims/release", payload);
    }
    async function requestClaimCleanup() {
      return await postJson("/claims/cleanup-requests", {
        claim_id: value("cleanup-claim-id"),
        requested_by: value("cleanup-requested-by")
      });
    }
    async function approveClaimCleanup() {
      return await postJson("/claims/cleanup-requests/approve", {
        approval_id: value("cleanup-approval-id"),
        approved_by: value("cleanup-approved-by")
      });
    }
    async function executeClaimCleanup() {
      return await postJson("/claims/cleanup-requests/execute", {
        approval_id: value("cleanup-execute-approval-id"),
        executed_by: value("cleanup-executed-by")
      });
    }
    async function registerHealthTarget() {
      const targetId = document.getElementById("health-target-id").value.trim();
      const resourceId = document.getElementById("health-resource-id").value.trim();
      const name = document.getElementById("health-name").value.trim();
      const probeType = document.getElementById("health-probe-type").value;
      const target = document.getElementById("health-target").value.trim();
      const expectedStatus = document.getElementById("health-expected-status").value.trim();
      const expectedContentType = document.getElementById("health-expected-content-type").value.trim();
      const payload = {target_id: targetId, resource_id: resourceId, name, probe_type: probeType, target};
      if (expectedStatus) payload.expected_status = Number(expectedStatus);
      if (expectedContentType) payload.expected_content_type = expectedContentType;
      return await postJson("/health-targets", payload);
    }
    function render() {
      const dashboard = state.data.dashboard || {};
      const overall = dashboard.overall_status || "loading";
      const overallEl = document.getElementById("overall");
      overallEl.textContent = overall.replaceAll("_", " ");
      overallEl.className = `pill ${overallClass(overall)}`;
      renderOverview();
      renderAdmin();
      renderAssets();
      renderClaims();
      renderSecurity();
      renderHealth();
      renderUsage();
      renderAudit();
      renderActionStatus();
    }
    function renderActionStatus() {
      const status = document.getElementById("action-status");
      if (!state.lastAction) return;
      status.className = "panel action-status";
      status.hidden = false;
      const result = state.lastAction.result || {};
      const detail = result.count ?? result.targets ?? result.resources ?? result.plans ?? result.status ?? "complete";
      status.innerHTML = `<div class="toolbar"><h3>${safe(labelize(state.lastAction.action))}</h3><span class="pill good">${safe(detail)}</span></div><p class="muted">${safe(state.lastAction.at)}</p>`;
    }
    function renderOverview() {
      const focus = (state.data.dashboard || {}).role_focus || {};
      const attention = (state.data.dashboard || {}).attention || {};
      document.getElementById("overview").innerHTML = `
        <div class="grid">
          ${metric("Sisko", attention.pending_authorizations, "pending authorizations", "span-3")}
          ${metric("Odo", attention.high_security_findings, "high findings", "span-3", attention.high_security_findings ? "bad" : "good")}
          ${metric("Julian", attention.unhealthy_health_targets, "unhealthy targets", "span-3", attention.unhealthy_health_targets ? "bad" : "good")}
          ${metric("O'Brien", focus.obrien?.executable_plans, "executable plans", "span-3")}
          <div class="section-head"><h3>Command Crew</h3><span class="pill">${safe((state.data.dashboard || {}).service_name)}</span></div>
          ${crew("Sisko", focus.sisko)}
          ${crew("Kira", focus.kira)}
          ${crew("O'Brien", focus.obrien)}
          ${crew("Odo", focus.odo)}
          ${crew("Quark", focus.quark)}
          ${crew("Dax", focus.dax)}
          ${crew("Julian", focus.julian)}
        </div>`;
    }
    function renderAdmin() {
      const adapters = state.data.adapters || {};
      const auth = state.data.authorizations || {};
      const readiness = state.data.readiness || {};
      const activePolicy = state.data.activePolicy || {};
      const packageStatus = state.data.packageStatus || {};
      const profile = activePolicy.profile || {};
      document.getElementById("admin").innerHTML = `
        <div class="grid">
          <div class="section-head"><h3>Admin Actions</h3><div class="actions"><button class="action-btn" data-action="discover-user-services">Discover Services</button><button class="action-btn" data-action="plan-package-updates">Plan Updates</button></div></div>
          ${metric("Adapters", adapters.enabled, "enabled", "span-3", adapters.disabled ? "warn" : "good")}
          ${metric("Authorizations", auth.pending_count, "pending", "span-3", auth.pending_count ? "warn" : "good")}
          ${metric("Ready", readiness.ready_for_overseer_execution, "executable now", "span-3")}
          ${metric("Failed", readiness.failed, "plans", "span-3", readiness.failed ? "bad" : "good")}
          <div class="panel span-4">${kv("Package Status", {
            status: packageStatus.status,
            upgradable: packageStatus.upgradable,
            captured_at: packageStatus.captured_at,
            stderr: packageStatus.stderr
          })}</div>
          <div class="panel span-8">${table("Upgradable Packages", packageStatus.items || [], ["name", "installed_version", "candidate_version", "repository"])}</div>
          <div class="panel span-12">${kv("Active Policy Profile", {
            name: profile.name,
            source: activePolicy.source,
            customized: activePolicy.customized,
            warnings_block_execution: profile.block_warnings_until_accepted,
            path: activePolicy.path,
            next_step: activePolicy.next_step
          })}</div>
          <div class="panel span-6">${table("Adapter Capabilities", adapters.items || [], ["kind", "status", "adapter_name"])}</div>
          <div class="panel span-6">${table("Execution Readiness", readiness.items || [], ["id", "kind", "readiness_state", "next_step"])}</div>
        </div>`;
    }
    function renderAssets() {
      const physical = state.data.physical || {};
      const virtual = state.data.virtual || {};
      document.getElementById("assets").innerHTML = `
        <div class="grid">
          <div class="section-head"><h3>Asset Actions</h3><div class="actions"><button class="action-btn" data-action="discover-physical">Discover Devices</button><button class="action-btn" data-action="discover-storage">Discover Storage</button><button class="action-btn" data-action="discover-listeners">Discover Listeners</button></div></div>
          ${metric("Physical", physical.assets, "assets", "span-3")}
          ${metric("Checkout Ready", physical.ready_for_checkout, "physical", "span-3")}
          ${metric("Virtual", virtual.assets, "assets", "span-3")}
          ${metric("Active Claims", virtual.active_claims, "virtual", "span-3")}
          <div class="panel span-12">
            <div class="toolbar"><h3>Register Resource</h3><button class="action-btn" data-action="register-resource">Record Resource</button></div>
            <div class="form-grid">
              <div class="field span-2"><label for="resource-id">Resource ID</label><input id="resource-id" value="svc.local.service"></div>
              <div class="field span-2"><label for="resource-name">Name</label><input id="resource-name" value="Local Service"></div>
              <div class="field span-2"><label for="resource-type">Type</label><select id="resource-type">${resourceTypeOptions()}</select></div>
              <div class="field span-2"><label for="resource-owner">Owner</label><select id="resource-owner">${ownerOptions()}</select></div>
              <div class="field span-2"><label for="resource-risk">Risk</label><select id="resource-risk">${riskOptions()}</select></div>
              <div class="field span-6"><label for="resource-identifiers">Identifiers</label><input id="resource-identifiers" value='{"kind":"service"}'></div>
            </div>
          </div>
          <div class="panel span-6">${table("Physical Assets", physical.items || [], ["id", "kind", "stable_id", "checkout_ready"])}</div>
          <div class="panel span-6">${table("Virtual Assets", virtual.items || [], ["id", "name", "state", "current_claim_id"])}</div>
        </div>`;
    }
    function renderClaims() {
      const claims = state.data.claims || {};
      const cleanup = state.data.claimCleanup || {};
      document.getElementById("claims").innerHTML = `
        <div class="grid">
          ${metric("Active", claims.active_like, "claims", "span-3")}
          ${metric("Queued", claims.queued, "claims", "span-3", claims.queued ? "warn" : "good")}
          ${metric("Review", claims.operator_review_required, "required", "span-3", claims.operator_review_required ? "bad" : "good")}
          ${metric("Cleanup", cleanup.cleanup_candidates, "candidates", "span-3", cleanup.cleanup_candidates ? "warn" : "good")}
          <div class="panel span-12">
            <div class="toolbar"><h3>Request Claim</h3><button class="action-btn" data-action="request-claim">Request Claim</button></div>
            <div class="form-grid">
              <div class="field span-2"><label for="claim-id">Claim ID</label><input id="claim-id" value="claim.local.resource"></div>
              <div class="field span-2"><label for="claim-resource-id">Resource ID</label><input id="claim-resource-id" value="svc.systemd-user.overseer-api"></div>
              <div class="field span-2"><label for="claim-type">Type</label><select id="claim-type">${claimTypeOptions()}</select></div>
              <div class="field span-2"><label for="claim-owner-thread">Thread</label><input id="claim-owner-thread" value="operator-console"></div>
              <div class="field span-2"><label for="claim-owner-role">Owner</label><select id="claim-owner-role">${ownerOptions()}</select></div>
              <div class="field span-2"><label for="claim-risk">Risk</label><select id="claim-risk">${riskOptions()}</select></div>
              <div class="field span-2"><label for="claim-port">Port</label><input id="claim-port" type="number" min="1" max="65535"></div>
              <div class="field span-2"><label for="claim-expires-at">Expires At</label><input id="claim-expires-at"></div>
              <div class="field span-2"><label for="claim-release-condition">Release Condition</label><input id="claim-release-condition"></div>
              <div class="field span-3"><label for="claim-intent">Intent</label><input id="claim-intent" value="operate local resource"></div>
              <div class="field span-3"><label for="claim-action">Action</label><input id="claim-action" value="observe health"></div>
            </div>
          </div>
          <div class="panel span-4">
            <div class="toolbar"><h3>Approve</h3><button class="action-btn" data-action="approve-claim">Approve</button></div>
            <div class="form-grid">
              <div class="field span-6"><label for="claim-approval-id">Approval ID</label><input id="claim-approval-id"></div>
              <div class="field span-6"><label for="claim-decided-by">Decided By</label><input id="claim-decided-by" value="sisko"></div>
            </div>
          </div>
          <div class="panel span-4">
            <div class="toolbar"><h3>Activate</h3><button class="action-btn" data-action="activate-claim">Activate</button></div>
            <div class="form-grid">
              <div class="field span-6"><label for="claim-activate-id">Claim ID</label><input id="claim-activate-id"></div>
              <div class="field span-6"><label for="claim-activate-approval-id">Approval ID</label><input id="claim-activate-approval-id"></div>
            </div>
          </div>
          <div class="panel span-4">
            <div class="toolbar"><h3>Release</h3><button class="action-btn" data-action="release-claim">Release</button></div>
            <div class="form-grid">
              <div class="field span-6"><label for="claim-release-id">Claim ID</label><input id="claim-release-id"></div>
              <div class="field span-3"><label for="claim-released-by">By</label><input id="claim-released-by" value="sisko"></div>
              <div class="field span-3"><label for="claim-release-reason">Reason</label><input id="claim-release-reason"></div>
            </div>
          </div>
          <div class="panel span-12">
            <div class="toolbar"><h3>Cleanup</h3><div class="actions"><button class="action-btn" data-action="request-claim-cleanup">Request</button><button class="action-btn" data-action="approve-claim-cleanup">Approve</button><button class="action-btn" data-action="execute-claim-cleanup">Execute</button></div></div>
            <div class="form-grid">
              <div class="field span-2"><label for="cleanup-claim-id">Claim ID</label><input id="cleanup-claim-id"></div>
              <div class="field span-2"><label for="cleanup-requested-by">Requested By</label><input id="cleanup-requested-by" value="sisko"></div>
              <div class="field span-2"><label for="cleanup-approval-id">Approval ID</label><input id="cleanup-approval-id"></div>
              <div class="field span-2"><label for="cleanup-approved-by">Approved By</label><input id="cleanup-approved-by" value="sisko"></div>
              <div class="field span-2"><label for="cleanup-execute-approval-id">Execute Approval</label><input id="cleanup-execute-approval-id"></div>
              <div class="field span-2"><label for="cleanup-executed-by">Executed By</label><input id="cleanup-executed-by" value="sisko"></div>
            </div>
          </div>
          <div class="panel span-12">${table("Claims", claims.items || [], ["id", "resource_id", "status", "claim_type", "next_step"])}</div>
          <div class="panel span-12">${table("Cleanup Candidates", cleanup.items || [], ["id", "cleanup_action", "approval_required", "cleanup_next_step"])}</div>
        </div>`;
    }
    function renderSecurity() {
      const security = state.data.security || {};
      const host = security.host_security || {};
      const plans = (security.protective_plans || {}).items || [];
      document.getElementById("security").innerHTML = `
        <div class="grid">
          ${metric("Alerts", security.alerts, "security", "span-3", security.alerts ? "bad" : "good")}
          ${metric("High", host.high_findings, "findings", "span-3", host.high_findings ? "bad" : "good")}
          ${metric("Warning", host.warning_findings, "findings", "span-3", host.warning_findings ? "warn" : "good")}
          ${metric("Plans", (security.protective_plans || {}).total, "protective", "span-3")}
          <div class="panel span-8">${table("Protective Plans", plans, ["id", "kind", "target", "approved", "canceled"])}</div>
          <div class="panel span-4">${kv("IDS Review", security.ids_review || {})}</div>
        </div>`;
    }
    function renderHealth() {
      const health = state.data.health || {};
      const healthSummary = state.data.healthSummary || {};
      document.getElementById("health").innerHTML = `
        <div class="grid">
          <div class="section-head"><h3>Health Actions</h3><div class="actions"><button class="action-btn" data-action="run-health-probes">Run Probes</button></div></div>
          ${metric("Targets", health.targets, "registered", "span-3")}
          ${metric("Unhealthy", health.unhealthy, "targets", "span-3", health.unhealthy ? "bad" : "good")}
          ${metric("Recovery", health.recovery_required, "required", "span-3", health.recovery_required ? "warn" : "good")}
          ${metric("Failures", health.latest_failures, "latest", "span-3", health.latest_failures ? "bad" : "good")}
          <div class="panel span-12">
            <div class="toolbar"><h3>Register Target</h3><button class="action-btn" data-action="register-health-target">Record Target</button></div>
            <div class="form-grid">
              <div class="field span-2"><label for="health-target-id">Target ID</label><input id="health-target-id" value="health.local.service"></div>
              <div class="field span-2"><label for="health-resource-id">Resource ID</label><input id="health-resource-id" value="svc.systemd-user.overseer-api"></div>
              <div class="field span-2"><label for="health-name">Name</label><input id="health-name" value="Local Service"></div>
              <div class="field span-2"><label for="health-probe-type">Probe</label><select id="health-probe-type">${probeTypeOptions()}</select></div>
              <div class="field span-2"><label for="health-expected-status">Expected HTTP</label><input id="health-expected-status" type="number" min="100" max="599"></div>
              <div class="field span-2"><label for="health-expected-content-type">Content Type</label><input id="health-expected-content-type"></div>
              <div class="field span-6"><label for="health-target">Target</label><input id="health-target" value="http://127.0.0.1:8766/health"></div>
            </div>
          </div>
          <div class="panel span-12">${table("Health Targets", healthSummary.summaries || [], ["resource_id", "name", "status", "recovery_required", "error"])}</div>
        </div>`;
    }
    function probeTypeOptions() {
      return ["json", "http", "https", "mcp", "html", "process", "command", "log", "manual"].map((value) => `<option value="${value}">${safe(value)}</option>`).join("");
    }
    function resourceTypeOptions() {
      return ["service", "virtual_asset", "physical_asset", "usage_limited_service", "maintenance_target", "security_surface", "composite"].map((value) => `<option value="${value}">${safe(value)}</option>`).join("");
    }
    function ownerOptions() {
      return ["julian", "dax", "kira", "obrien", "odo", "quark", "sisko", "ezri"].map((value) => `<option value="${value}">${safe(value)}</option>`).join("");
    }
    function riskOptions() {
      return ["low", "medium", "high", "critical"].map((value) => `<option value="${value}">${safe(value)}</option>`).join("");
    }
    function claimTypeOptions() {
      return ["observation", "checkout", "lock", "lease", "hold", "quarantine"].map((value) => `<option value="${value}">${safe(value)}</option>`).join("");
    }
    function value(id) {
      const element = document.getElementById(id);
      return element ? element.value.trim() : "";
    }
    function renderUsage() {
      const usage = state.data.usage || {};
      document.getElementById("usage").innerHTML = `
        <div class="grid">
          <div class="section-head"><h3>Usage Actions</h3><div class="actions"><button class="action-btn" data-action="discover-codex-threads">Discover Codex Threads</button></div></div>
          ${metric("Limits", usage.limits, "tracked", "span-3")}
          ${metric("Available", usage.available, "limits", "span-3", "good")}
          ${metric("Exhausted", usage.exhausted, "limits", "span-3", usage.exhausted ? "warn" : "good")}
          ${metric("Low Confidence", usage.low_confidence, "limits", "span-3", usage.low_confidence ? "warn" : "good")}
          <div class="panel span-12">${table("Usage Limits", usage.items || [], ["limit_id", "resource_id", "remaining", "capacity", "resets_at"])}</div>
        </div>`;
    }
    function renderAudit() {
      const audit = state.data.audit || {};
      const approvals = state.data.approvals || {};
      document.getElementById("audit").innerHTML = `
        <div class="grid">
          ${metric("Audit Events", audit.event_count, "stored", "span-3")}
          ${metric("Approvals", approvals.approval_count, "stored", "span-3")}
          <div class="panel span-6">${table("Recent Audit", audit.events || [], ["id", "event_type", "owner_domain", "summary"])}</div>
          <div class="panel span-6">${table("Approvals", approvals.items || [], ["id", "status", "owner_domain", "reason"])}</div>
        </div>`;
    }
    function metric(label, value, hint, span = "span-3", tone = "") {
      return `<div class="panel metric ${span}"><h3>${safe(label)}</h3><div class="value ${toneClass(tone)}">${safe(value ?? 0)}</div><p class="muted">${safe(hint)}</p></div>`;
    }
    function crew(name, data) {
      const rows = Object.entries(data || {}).slice(0, 5).map(([key, value]) => `<div class="row"><span>${safe(labelize(key))}</span><strong>${safe(value ?? 0)}</strong></div>`).join("");
      return `<div class="panel span-4"><h3>${safe(name)}</h3><div class="list">${rows || "<p class='muted'>No data</p>"}</div></div>`;
    }
    function table(titleText, rows, keys) {
      const body = (rows || []).slice(0, 12).map((row) => `<tr>${keys.map((key) => `<td>${format(row?.[key])}</td>`).join("")}</tr>`).join("");
      return `<div class="toolbar"><h3>${safe(titleText)}</h3><span class="pill">${(rows || []).length}</span></div><div class="table-scroll"><table><thead><tr>${keys.map((key) => `<th>${safe(labelize(key))}</th>`).join("")}</tr></thead><tbody>${body || `<tr><td colspan="${keys.length}" class="muted">No rows</td></tr>`}</tbody></table></div>`;
    }
    function kv(titleText, value) {
      const rows = Object.entries(value || {}).slice(0, 12).map(([key, val]) => `<div class="row"><span>${safe(labelize(key))}</span><strong>${format(val)}</strong></div>`).join("");
      return `<h3>${safe(titleText)}</h3><div class="list">${rows || "<p class='muted'>No data</p>"}</div>`;
    }
    function title(view) {
      return view.charAt(0).toUpperCase() + view.slice(1);
    }
    function labelize(key) {
      return String(key).replaceAll("_", " ");
    }
    function format(value) {
      if (value === null || value === undefined || value === "") return "<span class='muted'>none</span>";
      if (typeof value === "boolean") return value ? "<span class='pill good'>yes</span>" : "<span class='pill'>no</span>";
      if (Array.isArray(value)) return safe(value.join(", "));
      if (typeof value === "object") return safe(JSON.stringify(value));
      const text = String(value);
      const cls = text === "enabled" || text === "completed" || text === "pass" || text === "ok" ? "good" : text === "failed" || text === "blocked" || text === "critical" ? "bad" : text === "warning" || text === "pending" ? "warn" : "";
      return cls ? `<span class="pill ${cls}">${safe(text)}</span>` : safe(text);
    }
    function safe(value) {
      return String(value ?? "").replace(/[&<>"']/g, (char) => {
        if (char === "&") return "&amp;";
        if (char === "<") return "&lt;";
        if (char === ">") return "&gt;";
        if (char === '"') return "&quot;";
        return "&#39;";
      });
    }
    function overallClass(value) {
      if (value === "ok") return "good";
      if (value === "critical") return "bad";
      return "warn";
    }
    function toneClass(tone) {
      return tone === "bad" ? "bad-text" : tone === "warn" ? "warn-text" : tone === "good" ? "good-text" : "";
    }
    const style = document.createElement("style");
    style.textContent = ".good-text{color:var(--good)}.warn-text{color:var(--warn)}.bad-text{color:var(--bad)}";
    document.head.appendChild(style);
    render();
    if (state.token) {
      refresh();
    } else {
      document.getElementById("updated").textContent = "enter bearer token";
    }
  </script>
</body>
</html>
"""
