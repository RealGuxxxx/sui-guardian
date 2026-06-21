export function renderLandingPage(): string {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Sui Guardian | On-Chain Anomaly Monitoring & Incident Response</title>
    <meta name="description" content="Autonomous checkpoint-level anomaly scanning, package upgrade safeguards, and intelligence-driven incident response for Sui protocols." />
    
    <!-- Premium Editorial & Sans Fonts -->
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
        --critical-bg: #FDEBEC;
        --critical-text: #9F2F2D;
        --success-bg: #EDF3EC;
        --success-text: #346538;
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
      }

      /* Navbar */
      header {
        max-width: 1200px;
        margin: 0 auto;
        padding: 32px 24px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        border-bottom: 1px solid var(--border-color);
        background-color: var(--bg-surface);
      }

      .logo-container {
        display: flex;
        align-items: center;
        gap: 12px;
        text-decoration: none;
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

      .logo-text {
        font-weight: 700;
        font-size: 20px;
        letter-spacing: -0.02em;
        color: var(--text-primary);
      }

      .nav-links {
        display: flex;
        gap: 32px;
        align-items: center;
        list-style: none;
      }

      .nav-link a {
        color: var(--text-secondary);
        text-decoration: none;
        font-size: 13px;
        font-weight: 600;
        transition: color 0.15s ease;
      }

      .nav-link a:hover {
        color: var(--accent-klein);
      }

      /* Buttons (Crisp border-radius, flat styles) */
      .btn-primary {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        padding: 10px 20px;
        border-radius: 6px;
        background-color: var(--accent-klein);
        color: #ffffff;
        font-size: 13px;
        font-weight: 600;
        text-decoration: none;
        border: 1px solid var(--accent-klein);
        transition: background-color 0.15s ease, transform 0.15s ease;
      }

      .btn-primary:hover {
        background-color: #002280;
        border-color: #002280;
      }

      .btn-secondary {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        padding: 10px 20px;
        border-radius: 6px;
        background-color: var(--bg-surface);
        color: var(--text-primary);
        font-size: 13px;
        font-weight: 600;
        text-decoration: none;
        border: 1px solid var(--border-color);
        transition: background-color 0.15s ease, border-color 0.15s ease;
      }

      .btn-secondary:hover {
        background-color: var(--bg-canvas);
        border-color: rgba(0, 0, 0, 0.15);
      }

      /* Hero Section */
      .hero {
        max-width: 1200px;
        margin: 0 auto;
        padding: 96px 24px 64px 24px;
        text-align: center;
      }

      .badge-version {
        display: inline-flex;
        align-items: center;
        background-color: var(--accent-light);
        border: 1px solid rgba(0, 47, 167, 0.15);
        color: var(--accent-klein);
        padding: 5px 12px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: 700;
        margin-bottom: 24px;
        text-transform: uppercase;
        letter-spacing: 0.05em;
      }

      .hero h1 {
        font-family: 'Instrument Serif', serif;
        font-size: 64px;
        font-weight: 400;
        line-height: 1.1;
        letter-spacing: -0.03em;
        margin-bottom: 24px;
        color: var(--text-primary);
      }

      .hero p {
        max-width: 700px;
        margin: 0 auto 36px auto;
        font-size: 16px;
        color: var(--text-secondary);
        font-weight: 400;
        line-height: 1.6;
      }

      .hero-actions {
        display: flex;
        justify-content: center;
        gap: 16px;
        margin-bottom: 64px;
      }

      /* Mock Live Feed */
      .mock-feed-panel {
        max-width: 760px;
        margin: 0 auto;
        border-radius: 12px;
        border: 1px solid var(--border-color);
        background-color: var(--bg-surface);
        padding: 24px;
        text-align: left;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.02);
      }

      .mock-feed-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding-bottom: 12px;
        border-bottom: 1px solid var(--border-color);
        margin-bottom: 16px;
      }

      .mock-feed-title {
        display: flex;
        align-items: center;
        gap: 8px;
        font-size: 11px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: var(--text-secondary);
      }

      .pulse-dot {
        width: 8px;
        height: 8px;
        background-color: var(--accent-klein);
        border-radius: 50%;
      }

      .mock-feed-body {
        font-family: 'JetBrains Mono', monospace;
        font-size: 11px;
        display: flex;
        flex-direction: column;
        gap: 8px;
        color: var(--text-primary);
      }

      .feed-item {
        display: flex;
        justify-content: space-between;
        gap: 12px;
        padding: 6px 12px;
        border-radius: 4px;
        background: var(--bg-canvas);
        border-left: 3px solid var(--border-color);
      }

      .feed-item.alert {
        border-left-color: var(--critical-text);
        background-color: var(--critical-bg);
        color: var(--critical-text);
      }

      .feed-item.info {
        border-left-color: var(--accent-klein);
        background-color: var(--accent-light);
        color: var(--accent-klein);
      }

      .feed-item.success {
        border-left-color: var(--success-text);
        background-color: var(--success-bg);
        color: var(--success-text);
      }

      .feed-tag {
        font-weight: 700;
      }

      /* Features Bento Grid */
      .features-section {
        max-width: 1200px;
        margin: 0 auto;
        padding: 80px 24px;
        border-top: 1px solid var(--border-color);
      }

      .section-header {
        text-align: center;
        margin-bottom: 48px;
      }

      .section-header h2 {
        font-family: 'Instrument Serif', serif;
        font-size: 40px;
        font-weight: 400;
        margin-bottom: 12px;
      }

      .section-header p {
        color: var(--text-secondary);
        font-size: 15px;
        max-width: 500px;
        margin: 0 auto;
      }

      .features-grid {
        display: grid;
        grid-template-columns: repeat(3, minmax(0, 1fr));
        gap: 20px;
      }

      @media (max-width: 968px) {
        .features-grid {
          grid-template-columns: repeat(2, minmax(0, 1fr));
        }
      }
      @media (max-width: 640px) {
        .features-grid {
          grid-template-columns: 1fr;
        }
      }

      .feature-card {
        background-color: var(--bg-surface);
        border: 1px solid var(--border-color);
        border-radius: 8px;
        padding: 24px;
        transition: border-color 0.15s ease;
      }

      .feature-card:hover {
        border-color: var(--accent-klein);
      }

      .feature-icon {
        width: 40px;
        height: 40px;
        background: var(--accent-light);
        border-radius: 6px;
        display: flex;
        align-items: center;
        justify-content: center;
        margin-bottom: 16px;
        color: var(--accent-klein);
      }

      .feature-card h3 {
        font-size: 15px;
        font-weight: 700;
        margin-bottom: 8px;
        letter-spacing: -0.01em;
      }

      .feature-card p {
        color: var(--text-secondary);
        font-size: 13px;
        line-height: 1.5;
      }

      /* Pipeline Section */
      .architecture-section {
        max-width: 1000px;
        margin: 0 auto;
        padding: 48px 24px 80px 24px;
        text-align: center;
        border-top: 1px solid var(--border-color);
      }

      .diag-container {
        margin-top: 40px;
        background: var(--bg-surface);
        border: 1px solid var(--border-color);
        border-radius: 12px;
        padding: 32px;
        display: flex;
        flex-direction: column;
        gap: 20px;
        align-items: center;
      }

      .diag-row {
        display: flex;
        justify-content: center;
        align-items: center;
        gap: 24px;
        width: 100%;
        max-width: 800px;
        flex-wrap: wrap;
      }

      .diag-node {
        background-color: var(--bg-canvas);
        border: 1px solid var(--border-color);
        padding: 12px 20px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 13px;
        color: var(--text-primary);
        min-width: 180px;
        transition: border-color 0.15s ease;
      }

      .diag-node:hover {
        border-color: var(--accent-klein);
      }

      .diag-node.highlight {
        background-color: var(--accent-light);
        border-color: rgba(0, 47, 167, 0.3);
        color: var(--accent-klein);
      }

      .diag-arrow {
        font-size: 14px;
        color: var(--accent-klein);
      }

      /* Call to Action */
      .cta-section {
        max-width: 1200px;
        margin: 0 auto;
        padding: 40px 24px 80px 24px;
      }

      .cta-card {
        background-color: var(--bg-surface);
        border: 1px solid var(--border-color);
        border-radius: 12px;
        padding: 48px 32px;
        text-align: center;
      }

      .cta-card h2 {
        font-family: 'Instrument Serif', serif;
        font-size: 40px;
        font-weight: 400;
        margin-bottom: 12px;
      }

      .cta-card p {
        color: var(--text-secondary);
        max-width: 500px;
        margin: 0 auto 24px auto;
        font-size: 14px;
      }

      /* Footer */
      footer {
        border-top: 1px solid var(--border-color);
        background-color: var(--bg-surface);
        max-width: 1000px;
        margin: 0 auto;
        padding: 32px 24px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        color: var(--text-secondary);
        font-size: 12px;
        font-weight: 500;
      }

      .operational-status {
        display: flex;
        align-items: center;
        gap: 6px;
        color: var(--accent-klein);
        font-weight: 700;
      }

      @media (max-width: 640px) {
        header {
          flex-direction: column;
          gap: 16px;
        }
        .nav-links {
          gap: 20px;
        }
        footer {
          flex-direction: column;
          gap: 16px;
          text-align: center;
        }
      }
    </style>
  </head>
  <body>
    <header>
      <a href="/" class="logo-container" id="logoLink">
        <div class="logo-icon" style="background: none;">
          <img src="/logo.png" alt="Sui Guardian Logo" style="width: 32px; height: 32px; border-radius: 6px;" />
        </div>
        <span class="logo-text">Sui Guardian</span>
      </a>
      <nav>
        <ul class="nav-links">
          <li class="nav-link"><a href="#features">Features</a></li>
          <li class="nav-link"><a href="#pipeline">Pipeline</a></li>
          <li><a href="/dashboard" class="btn-primary" id="launchNavBtn">Dashboard Console</a></li>
        </ul>
      </nav>
    </header>

    <main>
      <section class="hero">
        <div class="badge-version">Sui Overflow 2026 Ready</div>
        <h1 id="heroTitle">On-chain security monitor, redefined.</h1>
        <p id="heroSubtitle">Continuous checkpoint-level anomaly scanning, package upgrade safeguards, and intelligence-driven incident response. Built with Nordic utilitarian simplicity for Sui protocol teams.</p>
        
        <div class="hero-actions">
          <a href="/dashboard" class="btn-primary" id="launchHeroBtn">
            Launch Console
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
              <line x1="5" y1="12" x2="19" y2="12"></line>
              <polyline points="12 5 19 12 12 19"></polyline>
            </svg>
          </a>
          <a href="#features" class="btn-secondary">Technical Features</a>
        </div>

        <!-- Live Simulated Feed Panel -->
        <div class="mock-feed-panel">
          <div class="mock-feed-header">
            <div class="mock-feed-title">
              <div class="pulse-dot"></div>
              Audit Scan Feed
            </div>
            <span style="font-size: 10px; color: var(--accent-klein); font-family: 'JetBrains Mono', monospace; font-weight: 700;">RPC Node: Connection Active</span>
          </div>
          <div class="mock-feed-body">
            <div class="feed-item success">
              <span>[18:51:30] [INFO] Target GraphQL RPC connection established successfully.</span>
              <span class="feed-tag success">OK</span>
            </div>
            <div class="feed-item info">
              <span>[18:51:31] [SYSTEM] Loaded active target configurations (DeepBook V3, Interest).</span>
              <span class="feed-tag info">ACTIVE</span>
            </div>
            <div class="feed-item success">
              <span>[18:51:33] [SCAN] Checkpoint increment audit complete. Audited 142 txs.</span>
              <span class="feed-tag success">PASS</span>
            </div>
            <div class="feed-item alert">
              <span>[18:51:35] [WARNING] Alert triggered: [DeepBook V3] Package upgrade cap transfer detected.</span>
              <span class="feed-tag alert">OPEN</span>
            </div>
          </div>
        </div>
      </section>

      <!-- Features Bento Section -->
      <section class="features-section" id="features">
        <div class="section-header">
          <h2>Utilitarian Capabilities</h2>
          <p>Deterministic, rule-based auditing to safeguard protocol parameters and verify deployments.</p>
        </div>

        <div class="features-grid">
          <!-- Feature 1 -->
          <article class="feature-card">
            <div class="feature-icon">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="10"></circle>
                <polyline points="12 6 12 12 16 14"></polyline>
              </svg>
            </div>
            <h3>Checkpoint Scanning</h3>
            <p>Monitors Sui transaction blocks increment by increment. Parses state transitions and balances in sync with network checkpoints to secure low latency.</p>
          </article>

          <!-- Feature 2 -->
          <article class="feature-card">
            <div class="feature-icon">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path>
                <polyline points="3.27 6.96 12 12.01 20.73 6.96"></polyline>
                <line x1="12" y1="22.08" x2="12" y2="12"></line>
              </svg>
            </div>
            <h3>Package Verification</h3>
            <p>Surveills contract upgrade operations. Raises immediate warnings if unauthorized accounts trigger modifications or release code updates outside schedule.</p>
          </article>

          <!-- Feature 3 -->
          <article class="feature-card">
            <div class="feature-icon">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <line x1="12" y1="1" x2="12" y2="23"></line>
                <path d="M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"></path>
              </svg>
            </div>
            <h3>Outflow Surveillance</h3>
            <p>Traces critical vault and treasury account addresses. Automatically alerts if asset outflow rates or transaction values exceed predefined safety limits.</p>
          </article>

          <!-- Feature 4 -->
          <article class="feature-card">
            <div class="feature-icon">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <polygon points="12 2 2 7 12 12 22 7 12 2z"></polygon>
                <polyline points="2 17 12 22 22 17"></polyline>
                <polyline points="2 12 12 17 22 12"></polyline>
              </svg>
            </div>
            <h3>Access Control Guards</h3>
            <p>Intercepts calls to admin and pause functions. Protects structural parameters by verifying that senders match custom authorization allowlists.</p>
          </article>

          <!-- Feature 5 -->
          <article class="feature-card">
            <div class="feature-icon">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z"></path>
              </svg>
            </div>
            <h3>Incident Aggregation</h3>
            <p>Intelligently bundles related event logs into high-level incidents. Saves response team time and mitigates notification fatigue during security threats.</p>
          </article>

          <!-- Feature 6 -->
          <article class="feature-card">
            <div class="feature-icon">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"></path>
                <path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"></path>
              </svg>
            </div>
            <h3>AI Configuration Helper</h3>
            <p>Speeds up setup times. Automatically analyzes Sui Move code and configures custom audit parameters to match code structure using AI model rules.</p>
          </article>
        </div>
      </section>

      <!-- Pipeline Section -->
      <section class="architecture-section" id="pipeline">
        <div class="section-header">
          <h2>Data Pipeline</h2>
          <p>Restrained, sequential flow of transaction verification.</p>
        </div>

        <div class="diag-container">
          <div class="diag-row">
            <div class="diag-node highlight">Sui Checkpoint Stream</div>
            <div class="diag-arrow">&rarr;</div>
            <div class="diag-node">GraphQL Client Streamer</div>
          </div>
          <div class="diag-arrow">&darr;</div>
          <div class="diag-row">
            <div class="diag-node">State Evaluation Engine</div>
            <div class="diag-arrow">&rarr;</div>
            <div class="diag-node highlight">Telemetry & Rules Context</div>
          </div>
          <div class="diag-arrow">&darr;</div>
          <div class="diag-row">
            <div class="diag-node">Incident Aggregator</div>
            <div class="diag-arrow">&rarr;</div>
            <div class="diag-node highlight">Discord / Webhook Dispatcher</div>
          </div>
        </div>
      </section>

      <!-- CTA -->
      <section class="cta-section">
        <div class="cta-card">
          <h2>Ready to secure your deployment?</h2>
          <p>Integrate Sui Guardian telemetry rules, check deployment logs, and guard your on-chain state.</p>
          <a href="/dashboard" class="btn-primary" id="ctaLaunchBtn">Open Console</a>
        </div>
      </section>
    </main>

    <footer>
      <p>&copy; 2026 Sui Guardian. Built for Sui Overflow. All rights reserved.</p>
      <div class="operational-status">
        <svg width="8" height="8" viewBox="0 0 8 8" fill="var(--accent-klein)">
          <circle cx="4" cy="4" r="3.5"/>
        </svg>
        Audit Engine Operational
      </div>
    </footer>
  </body>
</html>`;
}
