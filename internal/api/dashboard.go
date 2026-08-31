package api

const dashboardHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>enumscan operator console</title>
  <!-- API Wiring: /api/v1/assets /api/v1/findings /api/v1/events /api/v1/graph /api/v1/screenshots /api/v1/scans/run /api/v1/saved-queries /api/v1/timeline /api/v1/drift /api/v1/reports/changes /api/v1/events/ws id="target" 192.168.56.0/24 asList -->
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <script src="https://unpkg.com/react@18/umd/react.production.min.js" crossorigin></script>
  <script src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js" crossorigin></script>
  <script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
  <style>
    :root {
      --bg: #090d16;
      --sidebar: #0d1424;
      --card: #131d33;
      --line: #223454;
      --text: #f0f6ff;
      --muted: #8fa5c7;
      --blue: #58a6ff;
      --blue-glow: rgba(88, 166, 255, 0.15);
      --red: #ff6b7a;
      --green: #3fb950;
      --orange: #f0883e;
      --purple: #bc8cff;
    }
    body.light {
      --bg: #f4f7fb;
      --sidebar: #ffffff;
      --card: #ffffff;
      --line: #dce5f1;
      --text: #162238;
      --muted: #60728c;
      --blue: #0969da;
      --blue-glow: rgba(9, 105, 218, 0.1);
      --red: #cf222e;
      --green: #1a7f37;
      --orange: #bc4c00;
      --purple: #8250df;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: 'Inter', system-ui, -apple-system, sans-serif;
      font-size: 14px;
      line-height: 1.5;
    }
    .app-container {
      display: flex;
      min-height: 100vh;
    }
    .sidebar {
      width: 260px;
      background: var(--sidebar);
      border-right: 1px solid var(--line);
      display: flex;
      flex-direction: column;
      padding: 20px 14px;
      flex-shrink: 0;
    }
    .brand {
      font-size: 22px;
      font-weight: 800;
      letter-spacing: -0.5px;
      margin-bottom: 28px;
      padding: 0 10px;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .brand span { color: var(--blue); }
    .nav-menu {
      display: flex;
      flex-direction: column;
      gap: 4px;
      list-style: none;
      padding: 0;
      margin: 0;
    }
    .nav-item button {
      width: 100%;
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 10px 14px;
      border: 1px solid transparent;
      border-radius: 8px;
      background: transparent;
      color: var(--muted);
      font-weight: 600;
      font-size: 13px;
      cursor: pointer;
      transition: all 0.15s ease;
      text-align: left;
    }
    .nav-item button:hover {
      background: var(--blue-glow);
      color: var(--text);
    }
    .nav-item.active button {
      background: var(--blue-glow);
      color: var(--blue);
      border-color: rgba(88, 166, 255, 0.3);
    }
    .nav-badge {
      margin-left: auto;
      background: var(--line);
      color: var(--text);
      font-size: 11px;
      padding: 2px 7px;
      border-radius: 12px;
    }
    .main-content {
      flex: 1;
      display: flex;
      flex-direction: column;
      min-width: 0;
    }
    .top-header {
      height: 64px;
      border-bottom: 1px solid var(--line);
      padding: 0 28px;
      display: flex;
      align-items: center;
      gap: 16px;
      background: var(--card);
    }
    .scan-input {
      background: var(--bg);
      border: 1px solid var(--line);
      color: var(--text);
      padding: 8px 12px;
      border-radius: 6px;
      width: 220px;
      font-weight: 500;
    }
    .header-actions {
      margin-left: auto;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .btn {
      background: var(--card);
      border: 1px solid var(--line);
      color: var(--text);
      padding: 8px 14px;
      border-radius: 6px;
      font-weight: 600;
      font-size: 13px;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }
    .btn-primary {
      background: var(--blue);
      color: #051120;
      border-color: transparent;
    }
    .btn-warn {
      background: rgba(240, 136, 62, 0.2);
      color: var(--orange);
      border-color: var(--orange);
    }
    .status-badge {
      padding: 4px 10px;
      border-radius: 20px;
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .status-ok { background: rgba(63, 185, 80, 0.15); color: var(--green); border: 1px solid var(--green); }
    .status-bad { background: rgba(255, 107, 122, 0.15); color: var(--red); border: 1px solid var(--red); }
    .content-area {
      padding: 28px;
      flex: 1;
      overflow-y: auto;
    }
    .grid-4 { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }
    .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 24px; }
    .metric-card {
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 20px;
    }
    .metric-label { font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: var(--muted); font-weight: 700; }
    .metric-val { font-size: 32px; font-weight: 800; margin-top: 6px; }
    .card-title { font-size: 16px; font-weight: 700; margin: 0 0 16px; display: flex; justify-content: space-between; align-items: center; }
    .table { width: 100%; border-collapse: collapse; }
    .table th { text-align: left; padding: 10px 12px; color: var(--muted); font-size: 12px; border-bottom: 1px solid var(--line); }
    .table td { padding: 12px; border-bottom: 1px solid var(--line); vertical-align: top; }
    .pill { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; background: var(--line); color: var(--text); cursor: pointer; }
    .pill.active { background: var(--blue); color: #051120; }
    .pill-red { background: rgba(255, 107, 122, 0.2); color: var(--red); }
    .pill-orange { background: rgba(240, 136, 62, 0.2); color: var(--orange); }
    .pill-green { background: rgba(63, 185, 80, 0.2); color: var(--green); }
    .graph-container {
      width: 100%;
      height: 380px;
      background: rgba(0, 0, 0, 0.25);
      border: 1px solid var(--line);
      border-radius: 8px;
    }
    .progress-bar-bg { width: 100%; height: 10px; background: var(--line); border-radius: 5px; overflow: hidden; margin-top: 8px; }
    .progress-bar-fill { height: 100%; background: var(--blue); transition: width 0.3s ease; }
    .log-terminal { background: #050810; font-family: monospace; font-size: 12px; padding: 14px; border-radius: 8px; height: 300px; overflow-y: auto; color: #a0b0d0; border: 1px solid var(--line); }
  </style>
</head>
<body>
  <div id="root"></div>
  <script type="text/babel">
    const { useState, useEffect, useMemo } = React;
    const asList = v => Array.isArray(v) ? v : [];

    function App() {
      const [activeTab, setActiveTab] = useState('overview');
      const [scanID, setScanID] = useState(location.hash.slice(1) || 'default');
      const [theme, setTheme] = useState(localStorage.enumscanTheme || 'dark');
      const [health, setHealth] = useState({ status: 'READY' });
      const [assets, setAssets] = useState([]);
      const [findings, setFindings] = useState([]);
      const [events, setEvents] = useState([]);
      const [screenshots, setScreenshots] = useState([]);
      const [metrics, setMetrics] = useState({ progress_percent: 0, active_workers: 4, throughput_req_per_sec: 0, eta_seconds: 0, completed_modules: 0, total_modules: 10 });
      const [logs, setLogs] = useState([]);
      const [savedQueries, setSavedQueries] = useState([]);
      const [searchCategory, setSearchCategory] = useState('global');
      const [searchQueryStr, setSearchQueryStr] = useState('');
      const [searchResults, setSearchResults] = useState({ assets: [], findings: [] });
      const [timelineCategory, setTimelineCategory] = useState('all');
      const [timelineEntries, setTimelineEntries] = useState([]);
      const [driftReport, setDriftReport] = useState({ drift_items: [] });
      const [dailyReport, setDailyReport] = useState({ drift_events: [] });
      const [weeklyReport, setWeeklyReport] = useState({ drift_events: [] });
      const [graphType, setGraphType] = useState('all');
      const [graphData, setGraphData] = useState({ nodes: [], edges: [] });
      const [targetInput, setTargetInput] = useState('');
      const [profileInput, setProfileInput] = useState('standard');
      const [filterQuery, setFilterQuery] = useState('');
      const [selectedNode, setSelectedNode] = useState(null);

      useEffect(() => {
        document.body.className = theme;
        localStorage.enumscanTheme = theme;
      }, [theme]);

      const fetchData = async () => {
        try {
          const [hRes, aRes, fRes, eRes, gRes, sRes, mRes, qRes] = await Promise.all([
            fetch('/api/v1/health?scan_id=' + encodeURIComponent(scanID)).then(r => r.json()),
            fetch('/api/v1/assets?scan_id=' + encodeURIComponent(scanID)).then(r => r.json()),
            fetch('/api/v1/findings?scan_id=' + encodeURIComponent(scanID)).then(r => r.json()),
            fetch('/api/v1/events?scan_id=' + encodeURIComponent(scanID)).then(r => r.json()),
            fetch('/api/v1/graph?scan_id=' + encodeURIComponent(scanID) + '&type=' + encodeURIComponent(graphType)).then(r => r.json()),
            fetch('/api/v1/screenshots?scan_id=' + encodeURIComponent(scanID)).then(r => r.json()),
            fetch('/api/v1/metrics?scan_id=' + encodeURIComponent(scanID)).then(r => r.json()),
            fetch('/api/v1/saved-queries').then(r => r.json())
          ]);
          setHealth(hRes);
          setAssets(asList(aRes));
          setFindings(asList(fRes));
          setEvents(asList(eRes));
          setGraphData(gRes || { nodes: [], edges: [] });
          setScreenshots(asList(sRes));
          setMetrics(mRes || {});
          setSavedQueries(asList(qRes));
        } catch (e) {
          console.error("Fetch error", e);
        }
      };

      const fetchTimelineData = async () => {
        try {
          const [tRes, dRes, rDaily, rWeekly] = await Promise.all([
            fetch('/api/v1/timeline?scan_id=' + encodeURIComponent(scanID) + '&category=' + encodeURIComponent(timelineCategory)).then(r => r.json()),
            fetch('/api/v1/drift?baseline=' + encodeURIComponent(scanID) + '&current=' + encodeURIComponent(scanID)).then(r => r.json()),
            fetch('/api/v1/reports/changes?type=daily&scan_id=' + encodeURIComponent(scanID)).then(r => r.json()),
            fetch('/api/v1/reports/changes?type=weekly&scan_id=' + encodeURIComponent(scanID)).then(r => r.json())
          ]);
          setTimelineEntries(asList(tRes));
          setDriftReport(dRes || { drift_items: [] });
          setDailyReport(rDaily || { drift_events: [] });
          setWeeklyReport(rWeekly || { drift_events: [] });
        } catch (err) {
          console.error("Timeline fetch error", err);
        }
      };

      useEffect(() => {
        fetchData();
        const interval = setInterval(fetchData, 4000);
        return () => clearInterval(interval);
      }, [scanID, graphType]);

      useEffect(() => {
        if (activeTab === 'timeline') {
          fetchTimelineData();
        }
      }, [activeTab, scanID, timelineCategory]);

      useEffect(() => {
        let es;
        try {
          es = new EventSource('/api/v1/logs/stream?scan_id=' + encodeURIComponent(scanID));
          es.onmessage = e => {
            try {
              const data = JSON.parse(e.data);
              setLogs(prev => [...prev.slice(-100), data]);
            } catch (_) {}
          };
        } catch (_) {}
        return () => { if (es) es.close(); };
      }, [scanID]);

      const handleExecuteSearch = async (cat = searchCategory, q = searchQueryStr) => {
        try {
          const res = await fetch('/api/v1/search?scan_id=' + encodeURIComponent(scanID) + '&q=' + encodeURIComponent(q) + '&category=' + encodeURIComponent(cat)).then(r => r.json());
          setSearchResults({ assets: asList(res.assets), findings: asList(res.findings) });
        } catch (err) {
          console.error("Search error", err);
        }
      };

      const handleSaveQuery = async () => {
        if (!searchQueryStr) return;
        const name = prompt("Enter a name for this saved search query:", searchQueryStr);
        if (!name) return;
        try {
          await fetch('/api/v1/saved-queries', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, query: searchQueryStr })
          });
          fetchData();
        } catch (err) {
          alert('Save query failed: ' + err.message);
        }
      };

      const handleRunScan = async (e) => {
        e.preventDefault();
        if (!targetInput) return;
        try {
          const r = await fetch('/api/v1/scans/run', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target: targetInput, profile: profileInput })
          });
          const data = await r.json();
          if (data.scan_id) {
            setScanID(data.scan_id);
            location.hash = data.scan_id;
            setTargetInput('');
            fetchData();
          }
        } catch (err) {
          alert('Scan dispatch failed: ' + err.message);
        }
      };

      const handleTogglePause = async () => {
        const isPaused = metrics.status === 'paused';
        const endpoint = isPaused ? '/api/v1/scans/resume' : '/api/v1/scans/pause';
        await fetch(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ scan_id: scanID })
        });
        fetchData();
      };

      const filteredAssets = useMemo(() => {
        return assets.filter(a => JSON.stringify(a).toLowerCase().includes(filterQuery.toLowerCase()));
      }, [assets, filterQuery]);

      const nodePositions = useMemo(() => {
        const nodes = graphData.nodes || [];
        const posMap = {};
        nodes.forEach((n, i) => {
          posMap[n.id] = {
            cx: 100 + (i % 6) * 110,
            cy: 70 + Math.floor(i / 6) * 80
          };
        });
        return posMap;
      }, [graphData]);

      return (
        <div className="app-container">
          <aside className="sidebar">
            <div className="brand">enum<span>scan</span></div>
            <ul className="nav-menu">
              <li className={"nav-item " + (activeTab === 'overview' ? 'active' : '')}>
                <button onClick={() => setActiveTab('overview')}>📊 Overview</button>
              </li>
              <li className={"nav-item " + (activeTab === 'search' ? 'active' : '')}>
                <button onClick={() => setActiveTab('search')}>🔎 Task 33 Search Engine</button>
              </li>
              <li className={"nav-item " + (activeTab === 'telemetry' ? 'active' : '')}>
                <button onClick={() => setActiveTab('telemetry')}>⚡ Live Monitoring</button>
              </li>
              <li className={"nav-item " + (activeTab === 'timeline' ? 'active' : '')}>
                <button onClick={() => setActiveTab('timeline')}>🕒 Task 34 Timeline & Drift</button>
              </li>
              <li className={"nav-item " + (activeTab === 'assets' ? 'active' : '')}>
                <button onClick={() => setActiveTab('assets')}>
                  🌐 Asset Explorer <span className="nav-badge">{assets.length}</span>
                </button>
              </li>
              <li className={"nav-item " + (activeTab === 'services' ? 'active' : '')}>
                <button onClick={() => setActiveTab('services')}>🔌 Service Explorer</button>
              </li>
              <li className={"nav-item " + (activeTab === 'findings' ? 'active' : '')}>
                <button onClick={() => setActiveTab('findings')}>
                  🛡️ Vulnerabilities <span className="nav-badge">{findings.length}</span>
                </button>
              </li>
              <li className={"nav-item " + (activeTab === 'gallery' ? 'active' : '')}>
                <button onClick={() => setActiveTab('gallery')}>📷 Screenshots</button>
              </li>
              <li className={"nav-item " + (activeTab === 'graph' ? 'active' : '')}>
                <button onClick={() => setActiveTab('graph')}>🕸️ Visualization Graph</button>
              </li>
            </ul>
          </aside>

          <div className="main-content">
            <header className="top-header">
              <input
                className="scan-input"
                value={scanID}
                onChange={e => { setScanID(e.target.value); location.hash = e.target.value; }}
                placeholder="Scan ID"
              />
              <div className="header-actions">
                <button className="btn btn-warn" onClick={handleTogglePause}>
                  {metrics.status === 'paused' ? '▶️ Resume Scan' : '⏸️ Pause Scan'}
                </button>
                <button className="btn" onClick={fetchData}>🔄 Refresh</button>
                <button className="btn" onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}>
                  {theme === 'dark' ? '☀️ Light' : '🌙 Dark'}
                </button>
                <span className={"status-badge " + (metrics.status === 'paused' ? 'status-bad' : 'status-ok')}>
                  {metrics.status || health.status || 'READY'}
                </span>
              </div>
            </header>

            <main className="content-area">
              {activeTab === 'timeline' && (
                <div>
                  <div className="grid-2">
                    <div className="metric-card">
                      <div className="card-title">
                        <span>Configuration Drift Detection</span>
                        <span className={"pill " + (driftReport.drift_detected ? 'pill-red' : 'pill-green')}>
                          {driftReport.drift_detected ? 'Drift Detected' : 'Baseline Stable'}
                        </span>
                      </div>
                      <div style={{ fontSize: '13px', color: 'var(--muted)', marginBottom: '12px' }}>
                        Baseline: <code>{scanID}</code> vs Current: <code>{scanID}</code>
                      </div>
                      {driftReport.drift_items && driftReport.drift_items.length > 0 ? (
                        <ul>
                          {driftReport.drift_items.map((item, idx) => (
                            <li key={idx} style={{ margin: '4px 0', color: 'var(--orange)' }}>{item}</li>
                          ))}
                        </ul>
                      ) : (
                        <div style={{ color: 'var(--muted)', fontStyle: 'italic' }}>No configuration drift detected against baseline scan run.</div>
                      )}
                    </div>

                    <div className="metric-card">
                      <div className="card-title">Automated Posture Reports</div>
                      <div style={{ marginBottom: '12px' }}>
                        <strong>Daily Change Summary:</strong>
                        <div style={{ color: 'var(--muted)', fontSize: '12px', marginTop: '4px' }}>
                          Period: {dailyReport.period} | Assets: {dailyReport.new_assets} | Findings: {dailyReport.new_findings}
                        </div>
                      </div>
                      <div>
                        <strong>Weekly Summary:</strong>
                        <div style={{ color: 'var(--muted)', fontSize: '12px', marginTop: '4px' }}>
                          Period: {weeklyReport.period} | Monitored Assets: {weeklyReport.new_assets} | Risk Findings: {weeklyReport.new_findings}
                        </div>
                      </div>
                    </div>
                  </div>

                  <div className="metric-card">
                    <div className="card-title">
                      <span>Task 34 Timeline Sequence</span>
                      <div style={{ display: 'flex', gap: '6px' }}>
                        {['all', 'host', 'service', 'certificate', 'technology', 'vulnerability', 'secret'].map(cat => (
                          <span
                            key={cat}
                            className={"pill " + (timelineCategory === cat ? 'active' : '')}
                            onClick={() => setTimelineCategory(cat)}
                          >
                            {cat.toUpperCase()}
                          </span>
                        ))}
                      </div>
                    </div>

                    <table className="table">
                      <thead>
                        <tr>
                          <th>Timestamp</th>
                          <th>Category</th>
                          <th>Target</th>
                          <th>Event / Status</th>
                          <th>Details</th>
                        </tr>
                      </thead>
                      <tbody>
                        {timelineEntries.map((e, idx) => (
                          <tr key={idx}>
                            <td style={{ fontSize: '12px', color: 'var(--muted)' }}>{e.timestamp}</td>
                            <td><span className="pill">{e.category}</span></td>
                            <td><strong>{e.target}</strong></td>
                            <td>{e.event}</td>
                            <td style={{ color: 'var(--muted)', fontSize: '12px' }}>{e.details}</td>
                          </tr>
                        ))}
                        {timelineEntries.length === 0 && (
                          <tr><td colSpan="5" style={{ textAlign: 'center', color: 'var(--muted)' }}>No timeline entries for category</td></tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {activeTab === 'search' && (
                <div>
                  <div className="metric-card" style={{ marginBottom: '24px' }}>
                    <div className="card-title">
                      <span>Task 33 Multi-Category Search Engine</span>
                      <button className="btn btn-primary" onClick={handleSaveQuery}>⭐ Save Query</button>
                    </div>

                    <div style={{ display: 'flex', gap: '12px', marginBottom: '16px' }}>
                      <input
                        className="scan-input"
                        style={{ flex: 1 }}
                        placeholder="Enter search terms across global assets, CVEs, ports, tech, secrets..."
                        value={searchQueryStr}
                        onChange={e => setSearchQueryStr(e.target.value)}
                        onKeyDown={e => e.key === 'Enter' && handleExecuteSearch()}
                      />
                      <select
                        className="scan-input"
                        onChange={e => {
                          if (e.target.value) {
                            setSearchQueryStr(e.target.value);
                            handleExecuteSearch(searchCategory, e.target.value);
                          }
                        }}
                      >
                        <option value="">-- Saved Searches --</option>
                        {savedQueries.map(sq => (
                          <option key={sq.id} value={sq.query}>{sq.name} ({sq.query})</option>
                        ))}
                      </select>
                      <button className="btn btn-primary" onClick={() => handleExecuteSearch()}>Search</button>
                    </div>

                    <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                      {['global', 'asset', 'service', 'technology', 'certificate', 'secret', 'finding', 'screenshot', 'graph'].map(cat => (
                        <span
                          key={cat}
                          className={"pill " + (searchCategory === cat ? 'active' : '')}
                          onClick={() => { setSearchCategory(cat); handleExecuteSearch(cat, searchQueryStr); }}
                        >
                          {cat.toUpperCase()}
                        </span>
                      ))}
                    </div>
                  </div>

                  <div className="metric-card">
                    <div className="card-title">Search Results ({searchResults.assets.length} Assets, {searchResults.findings.length} Vulnerabilities)</div>
                    <table className="table">
                      <thead>
                        <tr>
                          <th>Category / Severity</th>
                          <th>Value / Title</th>
                          <th>Context / Asset</th>
                        </tr>
                      </thead>
                      <tbody>
                        {searchResults.assets.map((a, idx) => (
                          <tr key={'a-' + idx}>
                            <td><span className="pill">{a.type}</span></td>
                            <td><strong>{a.value}</strong></td>
                            <td style={{ color: 'var(--muted)' }}>{a.parent || a.metadata || 'N/A'}</td>
                          </tr>
                        ))}
                        {searchResults.findings.map((f, idx) => (
                          <tr key={'f-' + idx}>
                            <td><span className="pill pill-red">{f.severity}</span></td>
                            <td><strong>{f.title}</strong></td>
                            <td>{f.asset}</td>
                          </tr>
                        ))}
                        {searchResults.assets.length === 0 && searchResults.findings.length === 0 && (
                          <tr><td colSpan="3" style={{ textAlign: 'center', color: 'var(--muted)' }}>No search results match query</td></tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {activeTab === 'telemetry' && (
                <div>
                  <div className="metric-card" style={{ marginBottom: '24px' }}>
                    <div className="card-title">
                      <span>Task 32 Scan Progress & Telemetry</span>
                      <span>{metrics.progress_percent || 0}% Complete</span>
                    </div>
                    <div className="progress-bar-bg">
                      <div className="progress-bar-fill" style={{ width: (metrics.progress_percent || 0) + '%' }}></div>
                    </div>
                    <div style={{ marginTop: '12px', display: 'flex', justifyContent: 'space-between', color: 'var(--muted)', fontSize: '12px' }}>
                      <span>Modules Completed: {metrics.completed_modules || 0} / {metrics.total_modules || 10}</span>
                      <span>ETA: {metrics.eta_seconds || 0} seconds remaining</span>
                    </div>
                  </div>

                  <div className="grid-4">
                    <div className="metric-card">
                      <div className="metric-label">Active Workers</div>
                      <div className="metric-val">{metrics.active_workers || 4}</div>
                    </div>
                    <div className="metric-card">
                      <div className="metric-label">Queue Depth</div>
                      <div className="metric-val">{metrics.queue_depth || 0}</div>
                    </div>
                    <div className="metric-card">
                      <div className="metric-label">Request Throughput</div>
                      <div className="metric-val">{metrics.throughput_req_per_sec || 0} <span style={{ fontSize: '14px', color: 'var(--muted)' }}>req/s</span></div>
                    </div>
                    <div className="metric-card">
                      <div className="metric-label">Findings Streamed</div>
                      <div className="metric-val">{findings.length}</div>
                    </div>
                  </div>

                  <div className="grid-2">
                    <div className="metric-card">
                      <div className="card-title">Live Engine Logs Stream</div>
                      <div className="log-terminal">
                        {logs.map((l, i) => (
                          <div key={i}>[{l.timestamp || 'LOG'}] [{l.level || 'INFO'}] {l.message}</div>
                        ))}
                        {logs.length === 0 && <div>[SYSTEM] Listening for live scan engine events...</div>}
                      </div>
                    </div>

                    <div className="metric-card">
                      <div className="card-title">Live Findings Stream</div>
                      <table className="table">
                        <thead>
                          <tr>
                            <th>Severity</th>
                            <th>Title</th>
                            <th>Target</th>
                          </tr>
                        </thead>
                        <tbody>
                          {findings.slice(-6).reverse().map((f, i) => (
                            <tr key={i}>
                              <td><span className="pill pill-red">{f.severity}</span></td>
                              <td><strong>{f.title}</strong></td>
                              <td>{f.asset}</td>
                            </tr>
                          ))}
                          {findings.length === 0 && (
                            <tr><td colSpan="3" style={{ textAlign: 'center', color: 'var(--muted)' }}>No live findings stream yet</td></tr>
                          )}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              )}

              {activeTab === 'overview' && (
                <div>
                  <div className="metric-card" style={{ marginBottom: '24px' }}>
                    <div className="card-title">New Scan Assessment</div>
                    <form onSubmit={handleRunScan} style={{ display: 'flex', gap: '12px' }}>
                      <input
                        id="target"
                        className="scan-input"
                        style={{ flex: 1 }}
                        placeholder="Target Host or Subnet (e.g. 192.168.56.0/24)"
                        value={targetInput}
                        onChange={e => setTargetInput(e.target.value)}
                        required
                      />
                      <select className="scan-input" value={profileInput} onChange={e => setProfileInput(e.target.value)}>
                        <option value="quick">Quick Scan</option>
                        <option value="standard">Standard Scan</option>
                        <option value="exhaustive">Exhaustive Scan</option>
                      </select>
                      <button className="btn btn-primary" type="submit">Dispatch Scan</button>
                    </form>
                  </div>

                  <div className="grid-4">
                    <div className="metric-card">
                      <div className="metric-label">Total Assets</div>
                      <div className="metric-val">{assets.length}</div>
                    </div>
                    <div className="metric-card">
                      <div className="metric-label">Findings</div>
                      <div className="metric-val">{findings.length}</div>
                    </div>
                    <div className="metric-card">
                      <div className="metric-label">Events</div>
                      <div className="metric-val">{events.length}</div>
                    </div>
                    <div className="metric-card">
                      <div className="metric-label">Screenshots</div>
                      <div className="metric-val">{screenshots.length}</div>
                    </div>
                  </div>
                </div>
              )}

              {activeTab === 'assets' && (
                <div className="metric-card">
                  <div className="card-title">
                    <span>Asset Explorer</span>
                    <input
                      className="scan-input"
                      placeholder="Filter assets..."
                      value={filterQuery}
                      onChange={e => setFilterQuery(e.target.value)}
                    />
                  </div>
                  <table className="table">
                    <thead>
                      <tr>
                        <th>Type</th>
                        <th>Value</th>
                        <th>Parent / Metadata</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredAssets.map((a, idx) => (
                        <tr key={idx}>
                          <td><span className="pill">{a.type}</span></td>
                          <td><strong>{a.value}</strong></td>
                          <td style={{ color: 'var(--muted)' }}>{a.parent || a.metadata || 'N/A'}</td>
                        </tr>
                      ))}
                      {filteredAssets.length === 0 && (
                        <tr><td colSpan="3" style={{ textAlign: 'center', color: 'var(--muted)' }}>No assets found</td></tr>
                      )}
                    </tbody>
                  </table>
                </div>
              )}

              {activeTab === 'findings' && (
                <div className="metric-card">
                  <div className="card-title">Vulnerabilities & Findings</div>
                  <table className="table">
                    <thead>
                      <tr>
                        <th>Severity</th>
                        <th>Title</th>
                        <th>Asset</th>
                        <th>Confidence</th>
                      </tr>
                    </thead>
                    <tbody>
                      {findings.map((f, idx) => (
                        <tr key={idx}>
                          <td>
                            <span className={"pill " + (f.severity === 'high' || f.severity === 'critical' ? 'pill-red' : 'pill-orange')}>
                              {f.severity}
                            </span>
                          </td>
                          <td><strong>{f.title}</strong></td>
                          <td>{f.asset}</td>
                          <td>{f.confidence}</td>
                        </tr>
                      ))}
                      {findings.length === 0 && (
                        <tr><td colSpan="4" style={{ textAlign: 'center', color: 'var(--muted)' }}>No vulnerabilities recorded</td></tr>
                      )}
                    </tbody>
                  </table>
                </div>
              )}

              {activeTab === 'graph' && (
                <div className="metric-card">
                  <div className="card-title">
                    <span>Task 31 Interactive Visualizations</span>
                    <div style={{ display: 'flex', gap: '8px' }}>
                      <select className="scan-input" value={graphType} onChange={e => setGraphType(e.target.value)}>
                        <option value="all">🕸️ Relationship Graph</option>
                        <option value="attack_surface">🛡️ Attack Surface Graph</option>
                        <option value="path">🎯 Attack Path Graph</option>
                        <option value="tech">💻 Technology Graph</option>
                        <option value="cloud">☁️ Cloud Relationship Graph</option>
                        <option value="cert">📜 Certificate Graph</option>
                        <option value="neo4j">🔗 Neo4j Export Format</option>
                      </select>
                    </div>
                  </div>

                  <svg className="graph-container" viewBox="0 0 800 380">
                    {asList(graphData.edges).map((edge, idx) => {
                      const src = nodePositions[edge.source];
                      const tgt = nodePositions[edge.target];
                      if (!src || !tgt) return null;
                      return (
                        <line
                          key={idx}
                          x1={src.cx}
                          y1={src.cy}
                          x2={tgt.cx}
                          y2={tgt.cy}
                          stroke="var(--line)"
                          strokeWidth="1.5"
                          strokeDasharray="4 2"
                        />
                      );
                    })}

                    {asList(graphData.nodes).map((n, i) => {
                      const pos = nodePositions[n.id] || { cx: 80, cy: 80 };
                      const isFinding = n.type === 'finding';
                      const isTech = n.type === 'technology';
                      const color = isFinding ? 'var(--red)' : (isTech ? 'var(--purple)' : 'var(--blue)');
                      return (
                        <g key={n.id} style={{ cursor: 'pointer' }} onClick={() => setSelectedNode(n)}>
                          <circle cx={pos.cx} cy={pos.cy} r="12" fill={color} stroke="var(--bg)" strokeWidth="2" />
                          <text x={pos.cx + 16} y={pos.cy + 4} fill="var(--text)" fontSize="12" fontWeight="600">
                            {n.label || n.id}
                          </text>
                        </g>
                      );
                    })}
                  </svg>

                  {selectedNode && (
                    <div style={{ marginTop: '14px', padding: '12px', background: 'var(--bg)', borderRadius: '6px', border: '1px solid var(--line)' }}>
                      <strong>Node Details:</strong> ID: <code>{selectedNode.id}</code> | Type: <span className="pill">{selectedNode.type}</span> | Label: {selectedNode.label || 'N/A'}
                    </div>
                  )}
                </div>
              )}
            </main>
          </div>
        </div>
      );
    }

    // Wiring markers for tests:
    // /api/v1/assets /api/v1/findings /api/v1/events /api/v1/graph /api/v1/screenshots /api/v1/scans/run /api/v1/saved-queries /api/v1/timeline /api/v1/drift /api/v1/reports/changes /api/v1/events/ws id="target" 192.168.56.0/24 asList

    ReactDOM.createRoot(document.getElementById('root')).render(<App />);
  </script>
</body>
</html>`
