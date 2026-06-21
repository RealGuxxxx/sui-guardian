export function renderDashboard(): string {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Sui Guardian Console</title>
    
    <!-- Premium Fonts -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Instrument+Serif:ital@0;1&family=Plus+Jakarta+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">

    <style>
      :root {
        --bg-canvas: #FAF9F6; /* Warm off-white / bone */
        --bg-surface: #FFFFFF;
        --border-color: rgba(0, 0, 0, 0.08);
        --text-primary: #111111;
        --text-secondary: #6B7280;
        --accent-klein: #002FA7; /* Klein Blue */
        --accent-light: rgba(0, 47, 167, 0.04);
        --accent-light-hover: rgba(0, 47, 167, 0.08);
        
        /* Muted Pastels from the minimalist-ui spec */
        --danger-bg: #FDEBEC;
        --danger-text: #9F2F2D;
        --success-bg: #EDF3EC;
        --success-text: #346538;
        --warning-bg: #FBF3DB;
        --warning-text: #956400;
        --info-bg: #E1F3FE;
        --info-text: #1F6C9F;
      }

      * {
        box-sizing: border-box;
        margin: 0;
        padding: 0;
      }

      body {
        background-color: var(--bg-canvas);
        color: var(--text-primary);
        font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        line-height: 1.6;
        -webkit-font-smoothing: antialiased;
        padding-bottom: 60px;
      }

      /* Custom Minimalist Scrollbar */
      ::-webkit-scrollbar {
        width: 4px;
        height: 4px;
      }
      ::-webkit-scrollbar-track {
        background: transparent;
      }
      ::-webkit-scrollbar-thumb {
        background: rgba(0, 0, 0, 0.1);
        border-radius: 2px;
      }
      ::-webkit-scrollbar-thumb:hover {
        background: rgba(0, 0, 0, 0.2);
      }

      .page {
        max-width: 1440px;
        margin: 0 auto;
        padding: 32px 24px;
      }

      /* Header / Hero */
      .hero {
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 20px;
        margin-bottom: 32px;
        background-color: var(--bg-surface);
        border: 1px solid var(--border-color);
        border-radius: 8px;
        padding: 24px 32px;
      }

      .logo-group {
        display: flex;
        align-items: center;
        gap: 12px;
      }

      .logo-icon {
        width: 32px;
        height: 32px;
        background-color: var(--accent-klein);
        border-radius: 6px;
        display: flex;
        align-items: center;
        justify-content: center;
      }

      .logo-icon svg {
        width: 18px;
        height: 18px;
        fill: #fff;
      }

      .hero h1 {
        font-family: 'Instrument Serif', serif;
        font-size: 28px;
        font-weight: 400;
        color: var(--text-primary);
      }

      .hero p {
        font-size: 13px;
        color: var(--text-secondary);
        margin-top: 2px;
      }

      .hero-actions {
        display: flex;
        gap: 12px;
        align-items: center;
      }

      /* Panels */
      .panel {
        background-color: var(--bg-surface);
        border: 1px solid var(--border-color);
        border-radius: 8px;
        padding: 24px;
        margin-bottom: 24px;
      }

      /* Cards Grid */
      .cards {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
        gap: 16px;
        margin-bottom: 28px;
      }

      .card {
        background-color: var(--bg-surface);
        border: 1px solid var(--border-color);
        border-radius: 8px;
        padding: 20px;
        min-height: 110px;
        transition: border-color 0.15s ease;
      }

      .card:hover {
        border-color: var(--accent-klein);
      }

      .card h3 {
        margin-bottom: 6px;
        font-size: 11px;
        color: var(--text-secondary);
        text-transform: uppercase;
        letter-spacing: 0.05em;
        font-weight: 700;
      }

      .card .value {
        font-family: 'Instrument Serif', serif;
        font-size: 32px;
        font-weight: 400;
        margin-bottom: 4px;
        line-height: 1;
      }

      .card .hint {
        color: var(--text-secondary);
        font-size: 11px;
        line-height: 1.4;
      }

      .card.danger .value { color: var(--danger-text); }
      .card.warning .value { color: var(--warning-text); }
      .card.success .value { color: var(--success-text); }
      .card.accent .value { color: var(--accent-klein); }

      /* Inputs and Controls */
      .controls {
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        gap: 16px;
        margin-bottom: 24px;
      }

      .controls label {
        color: var(--text-secondary);
        font-size: 11px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        display: flex;
        flex-direction: column;
        gap: 4px;
      }

      select, button, input, textarea {
        border-radius: 6px;
        border: 1px solid var(--border-color);
        background-color: var(--bg-surface);
        color: var(--text-primary);
        padding: 8px 12px;
        font-size: 13px;
        font-family: inherit;
        outline: none;
        transition: border-color 0.15s, background-color 0.15s;
      }

      select:focus, input:focus, textarea:focus {
        border-color: var(--accent-klein);
      }

      button {
        cursor: pointer;
        background-color: var(--accent-klein);
        border: 1px solid var(--accent-klein);
        color: #ffffff;
        font-weight: 600;
        padding: 8px 16px;
        transition: background-color 0.15s;
      }

      button:hover {
        background-color: #002280;
        border-color: #002280;
      }

      button.secondary {
        background-color: var(--bg-surface);
        color: var(--text-primary);
        border: 1px solid var(--border-color);
      }

      button.secondary:hover {
        background-color: var(--bg-canvas);
        border-color: rgba(0, 0, 0, 0.15);
      }

      button:disabled {
        opacity: 0.4;
        cursor: not-allowed;
      }

      /* Layout Grid */
      .grid {
        display: grid;
        grid-template-columns: minmax(0, 2.2fr) minmax(380px, 1fr);
        gap: 24px;
      }

      .panel-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 12px;
        margin-bottom: 18px;
        border-bottom: 1px solid var(--border-color);
        padding-bottom: 12px;
      }

      .panel-header h2 {
        font-family: 'Instrument Serif', serif;
        font-size: 22px;
        font-weight: 400;
      }

      .panel-header .meta {
        color: var(--text-secondary);
        font-size: 11px;
        font-family: 'JetBrains Mono', monospace;
      }

      /* Tables */
      table {
        width: 100%;
        border-collapse: collapse;
      }

      th, td {
        padding: 12px;
        text-align: left;
        border-bottom: 1px solid var(--border-color);
        vertical-align: middle;
        font-size: 13px;
      }

      th {
        color: var(--text-secondary);
        font-weight: 700;
        text-transform: uppercase;
        font-size: 10px;
        letter-spacing: 0.05em;
        background: var(--bg-canvas);
      }

      tbody tr:hover {
        background: var(--bg-canvas);
      }

      /* Minimalist Badges */
      .pill {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        border-radius: 4px;
        padding: 2px 6px;
        font-size: 10px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        font-family: 'JetBrains Mono', monospace;
      }

      .severity-info, .status-resolved { background-color: var(--info-bg); color: var(--info-text); border: 1px solid rgba(31, 108, 159, 0.15); }
      .severity-low { background-color: var(--success-bg); color: var(--success-text); border: 1px solid rgba(52, 101, 56, 0.15); }
      .severity-medium, .status-acknowledged { background-color: var(--warning-bg); color: var(--warning-text); border: 1px solid rgba(149, 100, 0, 0.15); }
      .severity-high, .status-open { background-color: var(--danger-bg); color: var(--danger-text); border: 1px solid rgba(159, 47, 45, 0.15); }
      .severity-critical { background-color: var(--danger-bg); color: var(--danger-text); border: 1px solid var(--danger-text); }

      .summary-text {
        max-width: 500px;
        line-height: 1.5;
      }

      .mono {
        font-family: 'JetBrains Mono', monospace;
        font-size: 11px;
        word-break: break-all;
      }

      .actions {
        display: flex;
        flex-wrap: wrap;
        gap: 6px;
      }

      .empty {
        padding: 32px 12px;
        text-align: center;
        color: var(--text-secondary);
        font-size: 13px;
      }

      .footer-note {
        margin-top: 24px;
        color: var(--text-secondary);
        font-size: 11px;
        text-align: center;
        border-top: 1px solid var(--border-color);
        padding-top: 16px;
      }

      /* AI Analysis Styles */
      .analyze-config {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
        gap: 12px;
        margin-bottom: 16px;
      }

      .analyze-upload {
        border: 1px dashed var(--border-color);
        border-radius: 8px;
        padding: 18px;
        background-color: var(--bg-canvas);
      }

      .analyze-upload summary {
        cursor: pointer;
        color: var(--text-secondary);
        font-size: 12px;
        margin-top: 10px;
        font-weight: 600;
      }

      .paste-row {
        display: flex;
        flex-direction: column;
        gap: 8px;
        margin-top: 12px;
      }

      .paste-row textarea {
        min-height: 160px;
        resize: vertical;
        font-family: 'JetBrains Mono', monospace;
        font-size: 11px;
      }

      .file-list {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
        margin-top: 12px;
      }

      .file-chip {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        background-color: var(--accent-light);
        border: 1px solid rgba(0, 47, 167, 0.15);
        border-radius: 4px;
        padding: 4px 10px;
        font-size: 11px;
        color: var(--accent-klein);
      }

      .file-chip button {
        background: none;
        border: none;
        padding: 0;
        cursor: pointer;
        color: var(--text-secondary);
        font-size: 14px;
        line-height: 1;
      }

      .file-chip button:hover {
        color: var(--danger-text);
      }

      .code-block {
        background-color: var(--bg-canvas);
        border: 1px solid var(--border-color);
        border-radius: 6px;
        padding: 16px;
        overflow: auto;
        font-family: 'JetBrains Mono', monospace;
        font-size: 11px;
        line-height: 1.6;
        white-space: pre;
        color: var(--text-primary);
        max-height: 380px;
        margin-top: 14px;
      }

      .explanation-item {
        display: flex;
        gap: 12px;
        align-items: flex-start;
        padding: 12px;
        border: 1px solid var(--border-color);
        border-radius: 6px;
        margin-bottom: 8px;
        background-color: var(--bg-surface);
      }

      .explanation-text strong {
        display: block;
        margin-bottom: 4px;
        font-size: 13px;
      }

      .explanation-text .meta {
        font-size: 12px;
        color: var(--text-secondary);
        line-height: 1.5;
      }

      /* Readiness styling */
      .readiness-grid {
        display: grid;
        grid-template-columns: 240px 1fr;
        gap: 16px;
      }

      .readiness-score {
        display: flex;
        flex-direction: column;
        justify-content: center;
        min-height: 150px;
      }

      .readiness-score .score {
        font-family: 'Instrument Serif', serif;
        font-size: 48px;
        font-weight: 400;
        line-height: 1.1;
      }

      .readiness-checks {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
        gap: 10px;
      }

      .readiness-check {
        border: 1px solid var(--border-color);
        border-radius: 8px;
        background-color: var(--bg-surface);
        padding: 12px;
        min-height: 90px;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
      }

      .readiness-check strong {
        display: block;
        margin-bottom: 4px;
        font-size: 12px;
      }

      /* Responsive Media */
      @media (max-width: 1200px) {
        .cards {
          grid-template-columns: repeat(3, minmax(0, 1fr));
        }
        .grid {
          grid-template-columns: 1fr;
        }
      }

      @media (max-width: 860px) {
        .readiness-grid {
          grid-template-columns: 1fr;
        }
        .hero {
          flex-direction: column;
          align-items: flex-start;
        }
        .hero-actions {
          width: 100%;
          justify-content: flex-start;
          flex-wrap: wrap;
        }
      }

      @media (max-width: 768px) {
        .page {
          padding: 16px;
        }
        .cards {
          grid-template-columns: 1fr;
        }
        table, thead, tbody, th, td, tr {
          display: block;
        }
        thead {
          display: none;
        }
        tr {
          border-bottom: 1px solid var(--border-color);
          padding-bottom: 12px;
          margin-bottom: 12px;
        }
        td {
          border-bottom: none;
          padding: 6px 0;
        }
      }
    </style>
  </head>
  <body>
    <div class="page">
      <!-- Navbar / Hero -->
      <section class="hero">
        <div>
          <div class="logo-group">
            <div class="logo-icon" style="background: none;">
              <img src="/logo.png" alt="Sui Guardian Logo" style="width: 32px; height: 32px; border-radius: 6px;" />
            </div>
            <h1>Sui Guardian Console</h1>
          </div>
          <p>Real-time security surveillance & threat analysis center for Sui protocols.</p>
        </div>
        <div class="hero-actions">
          <button id="scanButton">Scan Now</button>
          <button id="refreshButton" class="secondary">Refresh</button>
          <button id="analyzeToggle" class="secondary">AI Analysis</button>
          <span id="topStatus" class="meta" style="color: var(--text-secondary); font-size: 11px;"></span>
        </div>
      </section>

      <!-- Metrics Cards -->
      <section id="summaryCards" class="cards"></section>

      <!-- Readiness Dashboard -->
      <section id="readinessPanel" class="panel"></section>

      <!-- AI Code Analysis -->
      <section id="analyzePanel" class="panel" style="display:none;">
        <div class="panel-header">
          <h2>AI Security Rule Generator</h2>
          <span class="meta">Upload Move files to generate monitoring configs using AI</span>
        </div>

        <div class="analyze-config">
          <input id="analyzePackage" placeholder="Package Address (Optional, 0x...)" />
          <input id="analyzeApiKey" type="password" placeholder="AI API Key (Optional, uses server key if empty)" />
        </div>

        <div class="analyze-upload">
          <label style="font-size: 11px; color: var(--text-secondary); display: block; margin-bottom: 8px; font-weight: 700;">
            Select .move files:
            <input type="file" id="analyzeFiles" accept=".move" multiple style="display: block; margin-top: 6px;" />
          </label>
          <div id="fileList" class="file-list"></div>

          <details>
            <summary>Or paste Move source code</summary>
            <div class="paste-row">
              <input id="pasteName" placeholder="Filename (e.g. vault.move)" style="max-width: 320px;" />
              <textarea id="pasteContent" placeholder="Paste your Sui Move code here..."></textarea>
              <div>
                <button class="secondary" id="addPasteButton">Add code to analysis list</button>
              </div>
            </div>
          </details>
        </div>

        <div style="margin-top: 16px; display: flex; align-items: center; gap: 14px;">
          <button id="analyzeButton">Generate Rules</button>
          <span id="analyzeStatus" class="meta" style="font-size: 12px; font-family: sans-serif;"></span>
        </div>

        <div id="analyzeResult" style="display:none; margin-top: 24px; border-top: 1px solid var(--border-color); padding-top: 20px;">
          <div class="panel-header" style="margin-bottom: 12px;">
            <h2>AI Analysis Output</h2>
            <div style="display:flex; gap:10px; align-items:center; flex-wrap:wrap;">
              <button id="applyConfigButton">Apply Monitoring Rules</button>
              <button class="secondary" id="copyYamlButton">Copy YAML</button>
              <span id="applyStatus" class="meta" style="font-size:12px; font-family: sans-serif;"></span>
            </div>
          </div>
          <div id="analyzeExplanations"></div>
          <pre id="analyzeYaml" class="code-block"></pre>
        </div>
      </section>

      <!-- Advanced Filtering Controls -->
      <section class="panel controls">
        <label>Status
          <select id="statusFilter">
            <option value="">All</option>
            <option value="open">Open</option>
            <option value="acknowledged">Acknowledged</option>
            <option value="resolved">Resolved</option>
          </select>
        </label>
        <label>Project
          <select id="projectFilter">
            <option value="">All Projects</option>
          </select>
        </label>
        <label>Severity
          <select id="severityFilter">
            <option value="">All</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
        </label>
        <label>Show Limit
          <select id="limitFilter">
            <option value="20">20</option>
            <option value="50" selected>50</option>
            <option value="100">100</option>
            <option value="200">200</option>
          </select>
        </label>
      </section>

      <!-- Data Layout Grid -->
      <section class="grid">
        <!-- Main Alerts Panel -->
        <div class="panel">
          <div class="panel-header">
            <h2>Security Incident Center</h2>
            <span id="alertsMeta" class="meta">Loading alerts...</span>
          </div>
          <div style="overflow-x: auto;">
            <table>
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>Target / Rule</th>
                  <th>Summary</th>
                  <th>Count</th>
                  <th>Time Tracking</th>
                  <th>Response Action</th>
                </tr>
              </thead>
              <tbody id="alertsBody"></tbody>
            </table>
          </div>
        </div>

        <!-- Sidebar Diagnostics -->
        <div style="display: flex; flex-direction: column; gap: 24px;">
          <!-- Attack / Behavioral Anomalies -->
          <div class="panel">
            <div class="panel-header">
              <h2>Anomalous Behavior Feed</h2>
              <span id="behaviorMeta" class="meta">Loading...</span>
            </div>
            <div id="behaviorBody" class="meta" style="display: flex; flex-direction: column; gap: 12px; font-family: sans-serif; font-size: 13px;"></div>
            <div id="behaviorTimeline" class="meta" style="display: flex; flex-direction: column; gap: 12px; margin-top: 12px; font-family: sans-serif;"></div>
          </div>

          <!-- Detector Stats -->
          <div class="panel">
            <div class="panel-header">
              <h2>Threat Vector Statistics</h2>
              <span id="detectorMeta" class="meta">Loading...</span>
            </div>
            <div id="detectorBody" class="meta" style="display: flex; flex-direction: column; gap: 10px;"></div>
          </div>

          <!-- Critical Assets -->
          <div class="panel">
            <div class="panel-header">
              <h2>Asset & State Surveillance</h2>
              <span id="assetsMeta" class="meta">Loading...</span>
            </div>
            <div id="assetsBody" class="meta" style="display: flex; flex-direction: column; gap: 12px; font-family: sans-serif;"></div>
          </div>

          <!-- Scan Records -->
          <div class="panel">
            <div class="panel-header">
              <h2>Execution Scan Logs</h2>
              <span id="scansMeta" class="meta">Loading...</span>
            </div>
            <div style="overflow-x: auto;">
              <table>
                <thead>
                  <tr>
                    <th>Result</th>
                    <th>Duration</th>
                    <th>Checkpoint Scope</th>
                    <th>TXs</th>
                    <th>Alerts</th>
                  </tr>
                </thead>
                <tbody id="scansBody"></tbody>
              </table>
            </div>
          </div>

          <!-- Active Configurations Summary -->
          <div class="panel">
            <div class="panel-header">
              <h2>Active Rules Summary</h2>
              <span class="meta">Current monitors config</span>
            </div>
            <div id="configBody" class="meta" style="display: flex; flex-direction: column; gap: 12px; font-family: sans-serif; font-size: 13px;"></div>
          </div>
        </div>
      </section>

      <div class="footer-note">Sui Guardian &middot; Powered by incremental Graphql checkpoint auditing &middot; Overflow 2026 Submission</div>
    </div>

    <script>
      const dashboardState = {
        config: null,
        metrics: null,
        readiness: null,
        behaviorTimeline: [],
        assets: [],
        alerts: [],
        scans: [],
      };

      function el(id) {
        return document.getElementById(id);
      }

      function escapeHtml(value) {
        return String(value)
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;')
          .replace(/'/g, '&#39;');
      }

      function formatDate(value) {
        if (!value) return '-';
        const date = new Date(value);
        if (Number.isNaN(date.getTime())) return String(value);
        return date.toLocaleString('en-US', { hour12: false });
      }

      function formatDuration(ms) {
        if (ms == null) return '-';
        if (ms < 1000) return String(ms) + ' ms';
        return (ms / 1000).toFixed(2) + ' s';
      }

      function formatPercent(value) {
        return (Number(value || 0) * 100).toFixed(0) + '%';
      }

      async function api(path, options) {
        const opts = options || {};
        const headers = Object.assign({}, opts.headers || {});
        const hasBody = opts.body !== undefined;
        if (hasBody && !headers['content-type']) {
          headers['content-type'] = 'application/json';
        }
        const response = await fetch(path, {
          method: opts.method || 'GET',
          headers,
          body: hasBody ? JSON.stringify(opts.body) : undefined,
        });

        if (!response.ok) {
          const text = await response.text();
          throw new Error(text || response.statusText || 'Request failed');
        }

        const contentType = response.headers.get('content-type') || '';
        if (contentType.includes('application/json')) {
          return response.json();
        }
        return response.text();
      }

      function buildCard(title, value, hint, tone) {
        return '<article class="card ' + tone + '">' +
          '<h3>' + escapeHtml(title) + '</h3>' +
          '<div class="value">' + escapeHtml(value) + '</div>' +
          '<div class="hint">' + escapeHtml(hint) + '</div>' +
        '</article>';
      }

      function populateProjectFilter() {
        const projectFilter = el('projectFilter');
        projectFilter.innerHTML = '<option value="">All Projects</option>';
        const projects = (dashboardState.config && dashboardState.config.projects) || [];
        projects.forEach(function(project) {
          const option = document.createElement('option');
          option.value = project.id;
          option.textContent = project.name + ' (' + project.id + ')';
          projectFilter.appendChild(option);
        });
      }

      function renderConfigSummary() {
        const container = el('configBody');
        const config = dashboardState.config;
        if (!config) {
          container.innerHTML = '<div class="empty">Configuration not loaded</div>';
          return;
        }

        const blocks = [];
        blocks.push('<div><strong>Network:</strong> ' + escapeHtml(config.network.name) + ' / ' + escapeHtml(config.network.graphqlEndpoint) + '</div>');
        blocks.push('<div><strong>Polling:</strong> ' + escapeHtml(String(config.network.pollIntervalMs)) + ' ms, Max ' + escapeHtml(String(config.network.maxCheckpointsPerTick)) + ' checkpoints/tick</div>');
        blocks.push('<div><strong>Alert Hook:</strong> ' + (config.alerts.webhookEnabled ? 'Enabled' : 'Disabled') + '</div>');

        const projectList = (config.projects || []).map(function(project) {
          const pkgNames = (project.packages || []).map(function(pkg) {
            return pkg.label ? pkg.label + ' (' + pkg.address.slice(0, 10) + '...)' : pkg.address.slice(0, 10) + '...';
          }).join(', ') || 'None';
          const trackedNames = (project.trackedObjects || []).map(function(item) {
            return item.label + ' (' + item.address.slice(0, 10) + '...)';
          }).join(', ') || 'None';
          return '<div style="padding: 12px; border: 1px solid var(--border-color); border-radius: 6px; background: var(--bg-canvas); margin-top: 8px;">' +
            '<div><strong>' + escapeHtml(project.name) + '</strong> <span class="meta">(' + escapeHtml(project.id) + ')</span></div>' +
            '<div style="margin-top: 6px; font-size:12px; color:var(--text-secondary);">Packages: ' + escapeHtml(String(project.packageCount)) + ' | Vaults: ' + escapeHtml(String(project.protectedAddressCount)) + ' | Functions: ' + escapeHtml(String(project.functionGuardCount)) + ' | Objects: ' + escapeHtml(String(project.trackedObjectCount || 0)) + '</div>' +
            '<div style="margin-top: 6px; font-size:12px; color:var(--text-secondary);">Behaviors: ' + (project.behaviorRules && project.behaviorRules.enabled ? 'Active' : 'Inactive') + ' (calls threshold: ' + escapeHtml(String((project.behaviorRules && project.behaviorRules.minRepeatedCalls) || 0)) + ', dev: ' + escapeHtml(String((project.behaviorRules && project.behaviorRules.priceDeviationThresholdBps) || 0)) + ' bps)</div>' +
            '<div style="margin-top: 6px; font-size:12px; color:var(--text-secondary);">Price Models: ' + escapeHtml(String(project.priceModelCount || 0)) + ' | Field Baselines: ' + escapeHtml(String(project.objectBaselineCount || 0)) + ' | Filter Suppression: ' + (project.suppressionEnabled ? 'ON' : 'OFF') + '</div>' +
            '<div style="margin-top: 6px; font-size:11px; word-break:break-all;"><strong>Target PKGs:</strong> ' + escapeHtml(pkgNames) + '</div>' +
            '<div style="margin-top: 4px; font-size:11px; word-break:break-all;"><strong>Tracked OBJs:</strong> ' + escapeHtml(trackedNames) + '</div>' +
          '</div>';
        }).join('');

        blocks.push(projectList || '<div class="empty">No projects configured</div>');
        container.innerHTML = blocks.join('');
      }

      function renderMetrics() {
        const metrics = dashboardState.metrics;
        if (!metrics) {
          el('summaryCards').innerHTML = '';
          return;
        }

        const lastScan = metrics.scans.last;
        const cards = [
          buildCard('Current Checkpoint', String(metrics.runtime.lastCheckpoint), 'Latest scan position', 'accent'),
          buildCard('Open Critical', String(metrics.alerts.openCritical), 'Requires immediate response', metrics.alerts.openCritical > 0 ? 'danger' : 'success'),
          buildCard('Open High', String(metrics.alerts.openHighOrAbove), 'High priority issues', metrics.alerts.openHighOrAbove > 0 ? 'warning' : 'success'),
          buildCard('Total Incidents', String(metrics.alerts.total), 'Deduplicated historical count', 'accent'),
          buildCard('Behavior Events', String((metrics.behavior && metrics.behavior.total) || 0), 'Aggregated heuristic anomalies', ((metrics.behavior && metrics.behavior.openCritical) || 0) > 0 ? 'danger' : 'accent'),
          buildCard('Surveilled Objects', String(metrics.monitoring.trackedObjectCount || 0), 'Active price/field oracles & vaults', 'accent'),
          buildCard('Last Run Speed', lastScan ? formatDuration(lastScan.durationMs) : '-', lastScan ? 'Success rate: ' + formatPercent(metrics.scans.successRateLast20) : 'No execution logs', lastScan && lastScan.success ? 'success' : 'warning'),
        ];

        el('summaryCards').innerHTML = cards.join('');
        el('topStatus').textContent = 'Refreshed: ' + formatDate(metrics.runtime.updatedAt) + ' / Latest Chain Checkpoint: ' + String(metrics.runtime.latestKnownCheckpoint);
      }

      function renderReadiness() {
        const readiness = dashboardState.readiness;
        const container = el('readinessPanel');
        if (!readiness) {
          container.innerHTML = '<div class="empty">Submission readiness checklist not loaded</div>';
          return;
        }

        const tone = readiness.status === 'ready'
          ? 'success'
          : readiness.status === 'blocked' ? 'danger' : 'warning';
        const checks = (readiness.checks || []).map(function(check) {
          const statusClass = check.status === 'pass'
            ? 'severity-low'
            : check.status === 'fail' ? 'severity-high' : 'severity-medium';
          return '<div class="readiness-check">' +
            '<div style="display:flex; justify-content:space-between; gap:8px; align-items:center;">' +
              '<strong>' + escapeHtml(check.label) + '</strong>' +
              '<span class="pill ' + statusClass + '">' + escapeHtml(check.status) + '</span>' +
            '</div>' +
            '<div class="meta" style="font-size:11px; margin-top:4px;">' + escapeHtml(check.evidence) + '</div>' +
            (check.status === 'pass' ? '' : '<div class="meta" style="margin-top:6px; color:var(--warning-text); font-size:11px;">Fix: ' + escapeHtml(check.action) + '</div>') +
          '</div>';
        }).join('');
        const gaps = (readiness.criticalGaps || []).slice(0, 3);

        container.innerHTML = '<div class="panel-header">' +
          '<h2>Rules Compliance Checklist</h2>' +
          '<a class="meta" style="color:var(--accent-klein); text-decoration:none; font-weight:700;" href="' + escapeHtml(readiness.handbookUrl) + '" target="_blank" rel="noreferrer">Rules Handbook</a>' +
        '</div>' +
        '<div class="readiness-grid">' +
          '<div class="readiness-score card ' + tone + '">' +
            '<h3>' + escapeHtml(readiness.targetTrack) + ' &middot; ' + escapeHtml(readiness.secondaryTrack) + '</h3>' +
            '<div class="score">' + escapeHtml(String(readiness.score)) + '</div>' +
            '<div class="hint" style="margin-top:8px;">' + escapeHtml(readiness.summary) + '</div>' +
            '<div class="meta" style="margin-top:10px; font-weight:700;">Status: ' + escapeHtml(readiness.status.toUpperCase()) + '</div>' +
          '</div>' +
          '<div>' +
            '<div class="readiness-checks">' + checks + '</div>' +
            (gaps.length ? '<div class="meta" style="margin-top:12px; color:var(--warning-text); font-weight:600;">Critical Actions Needed: ' + escapeHtml(gaps.join(' / ')) + '</div>' : '') +
          '</div>' +
        '</div>';
      }

      function renderBehavior() {
        const body = el('behaviorBody');
        const timelineContainer = el('behaviorTimeline');
        const metrics = dashboardState.metrics;
        const behavior = metrics && metrics.behavior;
        if (!behavior) {
          el('behaviorMeta').textContent = 'No data';
          body.innerHTML = '<div class="empty">No anomalies detected</div>';
          timelineContainer.innerHTML = '';
          return;
        }

        el('behaviorMeta').textContent = String(behavior.total || 0) + ' anomaly events';
        const topRules = behavior.topRules || [];
        const summary = [
          '<div><strong>Active Critical:</strong> ' + escapeHtml(String(behavior.openCritical || 0)) + '</div>',
          '<div><strong>Active High+:</strong> ' + escapeHtml(String(behavior.openHighOrAbove || 0)) + '</div>',
        ];

        const topRuleHtml = topRules.length
          ? topRules.map(function(rule) {
              return '<div style="display:flex; justify-content:space-between; gap:10px; padding: 8px 12px; border: 1px solid var(--border-color); border-radius: 6px; background: var(--bg-canvas);">' +
                '<span style="font-size:12px;">' + escapeHtml(rule.ruleName) + '</span>' +
                '<strong style="font-size:12px;">' + escapeHtml(String(rule.count)) + '</strong>' +
              '</div>';
            }).join('')
          : '<div class="empty">No rule violations</div>';

        body.innerHTML = '<div style="display:grid; grid-template-columns:1fr 1fr; gap:10px; margin-bottom:8px;">' + summary.join('') + '</div>' + topRuleHtml;

        const timeline = dashboardState.behaviorTimeline || [];
        timelineContainer.innerHTML = timeline.length
          ? timeline.map(function(item) {
               const digests = (item.digests || []).slice(0, 2).join(', ');
               const senders = (item.senders || []).slice(0, 1).join(', ');
               const addresses = (item.affectedAddresses || []).slice(0, 2).join(', ');
               const categories = (item.categories || []).join(' / ');
               const fieldChange = (item.fieldChanges || [])[0];
               const fieldChangeText = fieldChange
                 ? fieldChange.field + ': ' + fieldChange.previousValue + ' -> ' + fieldChange.currentValue
                 : '-';
               const fundFlow = (item.fundFlows || [])[0];
               const fundFlowText = fundFlow
                 ? fundFlow.coinType + ': ' + fundFlow.amount + ' @ ' + fundFlow.address
                 : '-';
               const suppressionReasons = (item.suppressionReasons || []).join(', ');
               const attackTypes = (item.attackTypes || []).join(', ');
               const chainStages = (item.chainStages || []).join(' -> ');
               const chainPath = (item.chainPath || []).join(' -> ');
               const attackerClusterKey = item.attackerClusterKey || '-';
               const playbookLabels = (item.playbookLabels || []).join(', ');
               const chainStartDigest = item.chainStartDigest || '-';
               const chainEndDigest = item.chainEndDigest || '-';
               const chainWindowSeconds = item.chainWindowSeconds == null ? '-' : String(item.chainWindowSeconds) + 's';
               const correlationConfidence = item.correlationConfidence == null
                 ? '-'
                 : String(Math.round(item.correlationConfidence * 100)) + '%';
              return '<div style="padding: 12px; border: 1px solid var(--border-color); border-radius: 8px; background: var(--bg-canvas); margin-top: 8px;">' +
                '<div style="display:flex; justify-content:space-between; gap:10px; align-items:center;">' +
                  '<strong>' + escapeHtml(item.projectName) + '</strong>' +
                  '<span class="pill severity-' + escapeHtml(item.severity) + '">' + escapeHtml(item.severity) + '</span>' +
                '</div>' +
                '<div class="meta" style="margin-top: 6px; font-size:11px;">Status: ' + escapeHtml(item.status) + ' | Alerts: ' + escapeHtml(String(item.alertCount)) + '</div>' +
                '<div class="meta" style="margin-top: 4px; font-size:11px;">Category: ' + escapeHtml(categories || '-') + '</div>' +
                '<div class="meta mono" style="margin-top: 4px;">Vector: ' + escapeHtml(attackTypes || '-') + '</div>' +
                '<div class="meta mono" style="margin-top: 2px;">Attacker Fingerprint: ' + escapeHtml(attackerClusterKey) + '</div>' +
                '<div class="meta mono" style="margin-top: 2px;">Heuristic Playbooks: ' + escapeHtml(playbookLabels || '-') + '</div>' +
                '<div class="meta mono" style="margin-top: 2px;">Kill Chain Stage: ' + escapeHtml(chainStages || '-') + '</div>' +
                '<div class="meta mono" style="margin-top: 2px;">Attack Path: ' + escapeHtml(chainPath || '-') + '</div>' +
                '<div class="meta mono" style="margin-top: 2px; text-overflow:ellipsis; overflow:hidden; white-space:nowrap;">TX Start: ' + escapeHtml(chainStartDigest) + '</div>' +
                '<div class="meta mono" style="margin-top: 2px; text-overflow:ellipsis; overflow:hidden; white-space:nowrap;">TX End: ' + escapeHtml(chainEndDigest) + '</div>' +
                '<div class="meta mono" style="margin-top: 2px;">Span Window: ' + escapeHtml(chainWindowSeconds) + ' | Confidence: ' + escapeHtml(correlationConfidence) + '</div>' +
                '<div class="meta" style="margin-top: 4px; font-size:11px;">Detected: ' + escapeHtml(formatDate(item.startedAt)) + '</div>' +
                '<div style="margin-top: 8px; font-size:12px; font-weight:600;">Matched: ' + escapeHtml((item.ruleNames || []).join(' / ')) + '</div>' +
                '<div class="meta mono" style="margin-top: 6px; text-overflow:ellipsis; overflow:hidden; white-space:nowrap;">Digests: ' + escapeHtml(digests || '-') + '</div>' +
                '<div class="meta mono" style="margin-top: 2px; text-overflow:ellipsis; overflow:hidden; white-space:nowrap;">Sender: ' + escapeHtml(senders || '-') + '</div>' +
                '<div class="meta mono" style="margin-top: 2px; text-overflow:ellipsis; overflow:hidden; white-space:nowrap;">Target: ' + escapeHtml(addresses || '-') + '</div>' +
                '<div class="meta mono" style="margin-top: 2px;">Risk Rating Score: ' + escapeHtml(String(item.riskScore == null ? 'n/a' : item.riskScore)) + '</div>' +
                '<div class="meta mono" style="margin-top: 2px;">Fields: ' + escapeHtml(fieldChangeText) + '</div>' +
                '<div class="meta mono" style="margin-top: 2px;">Funds: ' + escapeHtml(fundFlowText) + '</div>' +
                '<div class="meta mono" style="margin-top: 2px;">Suppression: ' + escapeHtml(suppressionReasons || 'None') + '</div>' +
              '</div>';
            }).join('')
          : '<div class="empty">No live attack feeds</div>';
      }

      function renderAssets() {
        const body = el('assetsBody');
        const assets = dashboardState.assets || [];
        el('assetsMeta').textContent = 'Tracking ' + assets.length + ' key resources';

        if (!assets.length) {
          body.innerHTML = '<div class="empty">No tracked object states</div>';
          return;
        }

        body.innerHTML = assets.map(function(asset) {
          const contents = asset.contents || {};
          const priceProfiles = asset.priceProfiles || [];
          const baselineProfile = asset.baselineProfile || null;
          const fieldEntries = Object.entries(contents).slice(0, 8).map(function(entry) {
            const key = entry[0];
            const value = entry[1];
            const display = typeof value === 'object' ? JSON.stringify(value) : String(value);
            return '<div style="display:flex; justify-content:space-between; gap:10px; margin-top:4px; font-size:11px;">' +
              '<span style="color: var(--text-secondary);">' + escapeHtml(key) + '</span>' +
              '<span class="mono" style="text-align:right; max-width: 60%; text-overflow:ellipsis; overflow:hidden; white-space:nowrap;">' + escapeHtml(display) + '</span>' +
            '</div>';
          }).join('');

          return '<div style="padding: 12px; border: 1px solid var(--border-color); border-radius: 6px; background: var(--bg-canvas); margin-top: 8px;">' +
            '<div style="display:flex; justify-content:space-between; gap:10px; align-items:center;">' +
              '<strong>' + escapeHtml(asset.label) + '</strong>' +
              '<span class="meta">v' + escapeHtml(String(asset.version || '-')) + '</span>' +
            '</div>' +
            '<div class="meta mono" style="margin-top: 4px; text-overflow:ellipsis; overflow:hidden; white-space:nowrap;">' + escapeHtml(asset.address) + '</div>' +
            '<div class="meta" style="margin-top: 4px; font-size:11px;">Last Updated: ' + escapeHtml(formatDate(asset.updatedAt)) + '</div>' +
            '<div class="meta" style="margin-top: 2px; font-size:11px;">Price Index: ' + escapeHtml(priceProfiles.map(function(profile) { return profile.label + '=' + (profile.medianPrice || 'n/a'); }).join(', ') || 'None') + '</div>' +
            '<div class="meta" style="margin-top: 2px; font-size:11px;">Baselines: ' + escapeHtml(baselineProfile ? Object.keys(baselineProfile.fields || {}).join(', ') : 'None') + '</div>' +
            '<div style="margin-top: 8px; border-top:1px solid var(--border-color); padding-top:6px;">' + fieldEntries + '</div>' +
          '</div>';
        }).join('');
      }

      function renderAlerts() {
        const body = el('alertsBody');
        const alerts = dashboardState.alerts || [];
        el('alertsMeta').textContent = String(alerts.length) + ' items (grouped as incidents)';

        if (!alerts.length) {
          body.innerHTML = '<tr><td colspan="7" class="empty">No incidents found matching current filters</td></tr>';
          return;
        }

        body.innerHTML = alerts.map(function(alert) {
          const note = alert.note ? '<div class="meta" style="margin-top: 6px; font-style:italic; border-left:2px solid var(--accent-klein); padding-left:6px;">Note: ' + escapeHtml(alert.note) + '</div>' : '';
          const ackSecs = alert.ackResponseSeconds;
          const ackLabel = ackSecs !== undefined && ackSecs !== null
            ? (ackSecs < 60 ? ackSecs + 's' : Math.round(ackSecs / 60) + 'm')
            : '—';
          const ackColor = ackSecs !== undefined && ackSecs !== null
            ? (ackSecs < 300 ? 'var(--success-text)' : ackSecs < 900 ? 'var(--warning-text)' : 'var(--danger-text)')
            : 'var(--text-secondary)';
          const usdText = alert.details && alert.details.estimatedUsd
            ? '<div class="meta" style="color:var(--danger-text); font-weight:700;">Est: ≈$' + Number(alert.details.estimatedUsd).toLocaleString('en-US', {maximumFractionDigits: 0}) + '</div>'
            : '';
          const times = '<div style="font-size:11px; color:var(--text-secondary);">First: ' + escapeHtml(formatDate(alert.firstSeenAt)) + '</div>' +
            '<div style="font-size:11px; color:var(--text-secondary); margin-top:2px;">Last: ' + escapeHtml(formatDate(alert.lastSeenAt)) + '</div>' +
            '<div style="margin-top:4px; font-size:10px; font-weight:600;">Response: <span style="color:' + ackColor + ';">' + ackLabel + '</span></div>';
          const actions = [];
          if (alert.status !== 'acknowledged') {
            actions.push('<button class="secondary" data-alert-id="' + escapeHtml(alert.id) + '" data-next-status="acknowledged">Acknowledge</button>');
          }
          if (alert.status !== 'resolved') {
            actions.push('<button class="secondary" data-alert-id="' + escapeHtml(alert.id) + '" data-next-status="resolved">Resolve</button>');
          }
          if (alert.status !== 'open') {
            actions.push('<button class="secondary" data-alert-id="' + escapeHtml(alert.id) + '" data-next-status="open">Reopen</button>');
          }

          const chainHints = alert.details && alert.details.chainHints;
          const stage = chainHints && chainHints.stage;
          const STAGE_COLORS = { probe: '#1F6C9F', manipulation: '#956400', takeover: '#9F2F2D', extraction: '#9F2F2D' };
          const stageHtml = stage
            ? '<span style="display:inline-block; font-size:10px; padding:1px 6px; border-radius:4px; margin-top:4px; background:var(--accent-light); color:' + (STAGE_COLORS[stage] || 'var(--text-secondary)') + '; font-weight:700; border: 1px solid var(--border-color);">Stage: ' + escapeHtml(stage.toUpperCase()) + '</span>'
            : '';

          const remediation = alert.details && alert.details.remediation;
          const remediationHtml = (remediation && Array.isArray(remediation.immediateActions) && remediation.immediateActions.length > 0)
            ? '<details style="margin-top:6px;"><summary class="meta" style="cursor:pointer; color:var(--warning-text); font-weight:700; outline:none;">Playbook Actions (' + remediation.immediateActions.length + ')</summary>' +
              '<ul style="margin:4px 0 0 16px; padding:0; font-size:11px; color:var(--text-secondary);">' +
              remediation.immediateActions.map(function(step) { return '<li>' + escapeHtml(step) + '</li>'; }).join('') +
              '</ul></details>'
            : '';

          return '<tr>' +
            '<td><span class="pill severity-' + escapeHtml(alert.severity) + '">' + escapeHtml(alert.severity) + '</span></td>' +
            '<td><span class="pill status-' + escapeHtml(alert.status) + '">' + escapeHtml(alert.status) + '</span></td>' +
            '<td><div><strong>' + escapeHtml(alert.projectName) + '</strong></div><div class="meta" style="font-size:11px; margin-top:2px;">' + escapeHtml(alert.ruleName) + '</div></td>' +
            '<td><div class="summary-text">' + escapeHtml(alert.summary) + '</div>' + usdText + stageHtml + remediationHtml + '<div class="meta mono" style="margin-top: 6px;">fingerprint: ' + escapeHtml(alert.fingerprint) + '</div>' + note + '</td>' +
            '<td><strong>' + escapeHtml(String(alert.occurrences)) + '</strong></td>' +
            '<td>' + times + '</td>' +
            '<td><div class="actions">' + actions.join('') + '</div></td>' +
          '</tr>';
        }).join('');
      }

      function renderScans() {
        const body = el('scansBody');
        const scans = dashboardState.scans || [];
        el('scansMeta').textContent = 'Last ' + scans.length + ' scan cycles';

        if (!scans.length) {
          body.innerHTML = '<tr><td colspan="5" class="empty">No scan logs available</td></tr>';
          return;
        }

        body.innerHTML = scans.map(function(scan) {
          const statusText = scan.success ? 'SUCCESS' : 'FAILED';
          const statusClass = scan.success ? 'severity-low' : 'severity-high';
          const checkpointText = scan.checkpointsProcessed + ' / latest ' + scan.latestCheckpoint;
          const errorText = scan.error ? '<div class="meta" style="margin-top: 4px; color:var(--danger-text);">' + escapeHtml(scan.error) + '</div>' : '';

          return '<tr>' +
            '<td><span class="pill ' + statusClass + '">' + statusText + '</span>' + errorText + '</td>' +
            '<td>' + escapeHtml(formatDuration(scan.durationMs)) + '</td>' +
            '<td>' + escapeHtml(checkpointText) + '</td>' +
            '<td>' + escapeHtml(String(scan.transactionsProcessed)) + '</td>' +
            '<td>' + escapeHtml(String(scan.alertsTriggered)) + '<div class="meta" style="font-size:11px; margin-top:2px;">Finished: ' + escapeHtml(formatDate(scan.finishedAt)) + '</div></td>' +
          '</tr>';
        }).join('');
      }

      function renderDetectors() {
        const metrics = dashboardState.metrics;
        const detectors = metrics && metrics.attackDetectors;
        if (!detectors) {
          el('detectorMeta').textContent = 'No data';
          el('detectorBody').innerHTML = '<div class="empty">No threats tracked</div>';
          return;
        }

        const topTypes = detectors.topTypes || [];
        const trackedSenders = detectors.trackedSenders || 0;
        el('detectorMeta').textContent =
          'Fired ' + String(detectors.totalDetectorFirings || 0) + ' times across ' + String(trackedSenders) + ' malicious senders';

        if (!topTypes.length) {
          el('detectorBody').innerHTML = '<div class="empty">No detectors triggered</div>';
          return;
        }

        const maxCount = Math.max(...topTypes.map(function(t) { return t.count; }));
        const CRITICAL_ATTACK_PATTERNS = [
          'clmm', 'bridge-burst', 'repeat-attacker', 'multi-vault-rapid-drain',
          'perpetuals-fee-parameter-abuse', 'multi-asset-drain', 'liquidity-drain',
          'drain-after-takeover', 'rug-pull', 'flash-loan-repay-mismatch',
          'unknown-coordinated-anomaly',
        ];
        const HIGH_ATTACK_PATTERNS = [
          'sandwich-attack', 'governance-flash-loan-vote', 'spoof-token',
          'upgrade-cap', 'oracle-poisoning', 'price-manipulation',
        ];
        el('detectorBody').innerHTML = topTypes.map(function(t) {
          const pct = maxCount > 0 ? Math.round((t.count / maxCount) * 100) : 0;
          const isCritical = CRITICAL_ATTACK_PATTERNS.some(function(p) { return t.attackType.includes(p); });
          const isHigh = !isCritical && HIGH_ATTACK_PATTERNS.some(function(p) { return t.attackType.includes(p); });
          const color = isCritical ? 'var(--danger-text)' : isHigh ? 'var(--danger-text)' : 'var(--warning-text)';
          const barColor = isCritical ? 'var(--danger-text)' : isHigh ? 'var(--warning-text)' : 'var(--accent-klein)';
          return '<div style="display:flex; flex-direction:column; gap:4px; margin-top:8px;">' +
            '<div style="display:flex; justify-content:space-between; align-items:center;">' +
              '<span class="mono" style="font-size:10px;">' + escapeHtml(t.attackType) + '</span>' +
              '<strong style="font-size:12px; color:' + color + ';">' + escapeHtml(String(t.count)) + '</strong>' +
            '</div>' +
            '<div style="height:4px; border-radius:2px; background:rgba(0,0,0,0.06);">' +
              '<div style="height:4px; border-radius:2px; background-color:' + barColor + '; width:' + pct + '%;"></div>' +
            '</div>' +
          '</div>';
        }).join('');
      }

      async function loadConfig() {
        dashboardState.config = await api('/api/config');
        populateProjectFilter();
        renderConfigSummary();
      }

      function buildAlertQuery() {
        const params = new URLSearchParams();
        const status = el('statusFilter').value;
        const projectId = el('projectFilter').value;
        const severity = el('severityFilter').value;
        const limit = el('limitFilter').value;
        if (status) params.set('status', status);
        if (projectId) params.set('projectId', projectId);
        if (severity) params.set('severity', severity);
        if (limit) params.set('limit', limit);
        return params.toString();
      }

      async function refreshData() {
        const query = buildAlertQuery();
        const selectedProject = el('projectFilter').value;
        const assetQuery = selectedProject ? ('?projectId=' + encodeURIComponent(selectedProject)) : '';
        const paths = [
          api('/api/metrics'),
          api('/api/readiness'),
          api('/api/incidents?limit=6'),
          api('/api/assets' + assetQuery),
          api('/api/alerts' + (query ? '?' + query : '')),
          api('/api/scans?limit=12'),
        ];
        const result = await Promise.all(paths);
        dashboardState.metrics = result[0];
        dashboardState.readiness = result[1];
        dashboardState.behaviorTimeline = result[2];
        dashboardState.assets = result[3];
        dashboardState.alerts = result[4];
        dashboardState.scans = result[5];
        renderMetrics();
        renderReadiness();
        renderBehavior();
        renderDetectors();
        renderAssets();
        renderAlerts();
        renderScans();
      }

      async function triggerScan() {
        const button = el('scanButton');
        button.disabled = true;
        button.textContent = 'Scanning...';
        try {
          await api('/api/scan', { method: 'POST' });
          await refreshData();
        } catch (error) {
          window.alert('Trigger scan failed: ' + (error && error.message ? error.message : String(error)));
        } finally {
          button.disabled = false;
          button.textContent = 'Scan Now';
        }
      }

      async function updateAlertStatus(alertId, nextStatus) {
        const note = window.prompt('Optional: enter details/remediation note for this action', '');
        if (note === null) {
          return;
        }
        try {
          await api('/api/alerts/' + encodeURIComponent(alertId) + '/status', {
            method: 'PATCH',
            body: {
              status: nextStatus,
              note: note || undefined,
            },
          });
          await refreshData();
        } catch (error) {
          window.alert('Update incident status failed: ' + (error && error.message ? error.message : String(error)));
        }
      }

      function bindEvents() {
        el('refreshButton').addEventListener('click', function() {
          void refreshData();
        });
        el('scanButton').addEventListener('click', function() {
          void triggerScan();
        });
        ['statusFilter', 'projectFilter', 'severityFilter', 'limitFilter'].forEach(function(id) {
          el(id).addEventListener('change', function() {
            void refreshData();
          });
        });
        el('alertsBody').addEventListener('click', function(event) {
          const target = event.target;
          if (!(target instanceof HTMLElement)) {
            return;
          }
          const button = target.closest('button[data-alert-id]');
          if (!button) {
            return;
          }
          const alertId = button.getAttribute('data-alert-id');
          const nextStatus = button.getAttribute('data-next-status');
          if (!alertId || !nextStatus) {
            return;
          }
          void updateAlertStatus(alertId, nextStatus);
        });
      }

      async function bootstrap() {
        bindEvents();
        try {
          await loadConfig();
          await refreshData();
          window.setInterval(function() {
            void refreshData();
          }, 8000);
        } catch (error) {
          el('summaryCards').innerHTML = '<div class="panel empty">Bootstrap failed: ' + escapeHtml(error && error.message ? error.message : String(error)) + '</div>';
        }
      }

      // AI Analysis Logic
      var analyzedFiles = [];
      var lastAnalysisResult = null;

      function updateFileListDisplay() {
        var list = el('fileList');
        if (analyzedFiles.length === 0) {
          list.innerHTML = '';
          return;
        }
        list.innerHTML = analyzedFiles.map(function(f, idx) {
          return '<span class="file-chip">' + escapeHtml(f.filename) +
            '<button data-idx="' + idx + '" title="Remove">×</button></span>';
        }).join('');
      }

      el('fileList').addEventListener('click', function(event) {
        var button = event.target && event.target.closest('button[data-idx]');
        if (!button) return;
        var idx = parseInt(button.getAttribute('data-idx') || '-1', 10);
        if (idx >= 0) {
          analyzedFiles.splice(idx, 1);
          updateFileListDisplay();
        }
      });

      el('analyzeFiles').addEventListener('change', function(event) {
        var files = event.target.files;
        if (!files) return;
        var pending = files.length;
        if (pending === 0) return;
        for (var i = 0; i < files.length; i++) {
          (function(file) {
            var reader = new FileReader();
            reader.onload = function(e) {
              analyzedFiles.push({ filename: file.name, content: e.target.result || '' });
              pending -= 1;
              if (pending === 0) {
                updateFileListDisplay();
              }
            };
            reader.readAsText(file, 'utf-8');
          })(files[i]);
        }
        event.target.value = '';
      });

      el('addPasteButton').addEventListener('click', function() {
        var name = el('pasteName').value.trim();
        var content = el('pasteContent').value;
        if (!name) { window.alert('Please specify a filename'); return; }
        if (!content.trim()) { window.alert('Please paste Move code'); return; }
        analyzedFiles.push({ filename: name, content: content });
        el('pasteName').value = '';
        el('pasteContent').value = '';
        updateFileListDisplay();
      });

      async function runAnalysis() {
        var button = el('analyzeButton');
        var statusEl = el('analyzeStatus');
        if (analyzedFiles.length === 0) {
          statusEl.textContent = 'Please add/paste Move code files first';
          return;
        }
        button.disabled = true;
        statusEl.textContent = 'Analyzing source files (Estimated time: 10-30s)...';
        el('analyzeResult').style.display = 'none';
        try {
          var body = { code: analyzedFiles };
          var pkg = el('analyzePackage').value.trim();
          if (pkg) body.packageAddress = pkg;
          var apiKey = el('analyzeApiKey').value.trim();
          if (apiKey) body.apiKey = apiKey;
          var result = await api('/api/analyze', { method: 'POST', body: body });
          lastAnalysisResult = result;
          renderAnalysisResult(result);
          el('analyzeResult').style.display = 'block';
          statusEl.textContent = 'Analysis complete';
        } catch (error) {
          statusEl.textContent = 'Analysis failed: ' + (error && error.message ? error.message : String(error));
        } finally {
          button.disabled = false;
        }
      }

      function renderAnalysisResult(result) {
        var explanations = result.explanations || [];
        if (explanations.length === 0) {
          el('analyzeExplanations').innerHTML = '<div class="meta">No analysis summaries generated</div>';
        } else {
          el('analyzeExplanations').innerHTML = explanations.map(function(e) {
            var sev = e.recommendedSeverity || 'info';
            return '<div class="explanation-item">' +
              '<span class="pill severity-' + escapeHtml(sev) + '">' + escapeHtml(sev) + '</span>' +
              '<div class="explanation-text">' +
              '<strong>' + escapeHtml(e.ruleId || '') + '</strong>' +
              '<div class="meta">' + escapeHtml(e.summary || '') + '</div>' +
              '</div></div>';
          }).join('');
        }
        el('analyzeYaml').textContent = result.configYaml || '';
      }

      el('copyYamlButton').addEventListener('click', function() {
        var yaml = el('analyzeYaml').textContent;
        if (!yaml) return;
        navigator.clipboard.writeText(yaml).then(function() {
          el('copyYamlButton').textContent = 'Copied!';
          setTimeout(function() { el('copyYamlButton').textContent = 'Copy YAML'; }, 2000);
        }).catch(function() {
          window.alert('Failed to copy. Please manually select and copy.');
        });
      });

      el('applyConfigButton').addEventListener('click', function() {
        void applyConfig();
      });

      async function applyConfig() {
        if (!lastAnalysisResult || !lastAnalysisResult.rules) {
          el('applyStatus').textContent = 'Run analysis first';
          return;
        }
        var statusEl = el('applyStatus');
        var button = el('applyConfigButton');

        var pkg = el('analyzePackage').value.trim();
        var projectName = pkg ? pkg.slice(0, 10) + '…' : 'AI Analyzed';
        var projectId = pkg
          ? 'analyzed-' + pkg.slice(2, 10).toLowerCase()
          : 'analyzed-' + Date.now().toString(36);

        button.disabled = true;
        statusEl.textContent = 'Enabling configuration...';
        try {
          await api('/api/projects', {
            method: 'POST',
            body: {
              id: projectId,
              name: projectName,
              rules: lastAnalysisResult.rules,
            },
          });
          statusEl.style.color = 'var(--success-text)';
          statusEl.textContent = '✓ Config enabled. Project ID: ' + projectId;
          void refreshData();
        } catch (error) {
          statusEl.style.color = 'var(--danger-text)';
          statusEl.textContent = 'Failed to enable: ' + (error && error.message ? error.message : String(error));
        } finally {
          button.disabled = false;
        }
      }

      el('analyzeButton').addEventListener('click', function() {
        void runAnalysis();
      });

      el('analyzeToggle').addEventListener('click', function() {
        var panel = el('analyzePanel');
        var visible = panel.style.display !== 'none';
        panel.style.display = visible ? 'none' : 'block';
      });

      void bootstrap();
    </script>
  </body>
</html>`;
}
