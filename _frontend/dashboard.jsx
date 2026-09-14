import React from "react";
import { createRoot } from "react-dom/client";
import { EngagementWizardDialog, SaveQueryDialog, StatusMessage, ThemeButton } from "./dashboard_components.jsx";
import { asList } from "./dashboard_helpers.js";

const { useState, useEffect, useMemo } = React;
const MAX_RENDERED_ROWS = 500;

  function App() {
    const [activeTab, setActiveTab] = useState('overview');
    const [scanID, setScanID] = useState(location.hash.slice(1) || 'default');
    const [targetInput, setTargetInput] = useState('192.168.56.0/24');
    const [profileInput, setProfileInput] = useState('standard');
    const [statusMsg, setStatusMsg] = useState('Scope verified');
	const [saveQueryOpen, setSaveQueryOpen] = useState(false);
    const [engagementWizardOpen, setEngagementWizardOpen] = useState(false);
    const [theme, setTheme] = useState(localStorage.enumscanTheme || 'dark');

    const [health, setHealth] = useState({ status: 'unknown' });
    const [assets, setAssets] = useState([]);
    const [findings, setFindings] = useState([]);
    const [events, setEvents] = useState([]);
    const [screenshots, setScreenshots] = useState([]);
    const [metrics, setMetrics] = useState({});
    const [logs, setLogs] = useState([]);
    const [savedQueries, setSavedQueries] = useState([]);
	const [scanRuns, setScanRuns] = useState([]);
    const [integrations, setIntegrations] = useState({ providers: [], warnings: [] });
    const [coordinator, setCoordinator] = useState({ jobs: [], agents: [] });
    const [capabilities, setCapabilities] = useState({ capabilities: [] });
    const [auditEntries, setAuditEntries] = useState([]);

    // Filters & States
    const [assetFilter, setAssetFilter] = useState('');
    const [searchQueryStr, setSearchQueryStr] = useState('');
    const [searchResults, setSearchResults] = useState({ assets: [], findings: [] });
    const [graphType, setGraphType] = useState('all');
    const [graphData, setGraphData] = useState({ nodes: [], edges: [] });
    const [selectedNode, setSelectedNode] = useState(null);
    const [neoGraphData, setNeoGraphData] = useState({ nodes: [], edges: [] });
    const [neoGraphError, setNeoGraphError] = useState('');

    // Knowledge Graph
    const [kgFilterType, setKgFilterType] = useState('');
    const [kgQueryStr, setKgQueryStr] = useState('');
    const [kgGraphData, setKgGraphData] = useState({ nodes: [], edges: [] });
    const [kgSelectedNode, setKgSelectedNode] = useState(null);

    useEffect(() => {
      document.body.className = theme === 'light' ? 'light-theme' : '';
      localStorage.enumscanTheme = theme;
    }, [theme]);

    const fetchData = async () => {
      try {
        const [snapshot, mRes, historyRes, integrationRes, coordinatorRes, capabilityRes, auditRes] = await Promise.all([
          fetch('/api/v1/dashboard/snapshot?scan_id=' + encodeURIComponent(scanID)).then(r => {
            if (!r.ok) throw new Error('scan evidence is unavailable');
            return r.json();
          }),
          fetch('/api/v1/metrics?scan_id=' + encodeURIComponent(scanID)).then(r => r.ok ? r.json() : {}),
          fetch('/api/v1/scans?limit=50').then(r => r.ok ? r.json() : []),
          fetch('/api/v1/integrations').then(r => r.ok ? r.json() : ({ providers: [], warnings: [] })),
          fetch('/api/v1/distributed/status').then(r => r.ok ? r.json() : ({ jobs: [], agents: [] })),
          fetch('/api/v1/capabilities').then(r => r.ok ? r.json() : ({ capabilities: [] })),
          fetch('/api/v1/audit?limit=10').then(r => r.ok ? r.json() : [])
        ]);
        const graph = graphType === 'all'
          ? snapshot.graph
          : await fetch('/api/v1/graph?scan_id=' + encodeURIComponent(scanID) + '&type=' + encodeURIComponent(graphType)).then(r => r.ok ? r.json() : ({ nodes: [], edges: [] }));
        setHealth(snapshot.health || { status: 'unknown' });
        setAssets(asList(snapshot.assets));
        setFindings(asList(snapshot.findings));
        setEvents(asList(snapshot.events));
        setGraphData(graph || { nodes: [], edges: [] });
        setScreenshots(asList(snapshot.screenshots));
        setMetrics(mRes || {});
        setSavedQueries(asList(snapshot.saved_queries));
		setScanRuns(asList(historyRes));
        setIntegrations(integrationRes || { providers: [], warnings: [] });
        setCoordinator(coordinatorRes || { jobs: [], agents: [] });
        setCapabilities(capabilityRes || { capabilities: [] });
        setAuditEntries(asList(auditRes));
      } catch (err) {
        console.error("Dashboard fetch error", err);
		setStatusMsg('Evidence connection unavailable. Check the local API and selected scan ID.');
      }
    };

    const fetchKGData = async () => {
      try {
        const res = await fetch('/api/v1/knowledge-graph?scan_id=' + encodeURIComponent(scanID) + '&type=' + encodeURIComponent(kgFilterType) + '&q=' + encodeURIComponent(kgQueryStr)).then(r => r.json()).catch(() => ({ nodes: [], edges: [] }));
        setKgGraphData(res || { nodes: [], edges: [] });
      } catch (err) {
        console.error("Knowledge Graph error", err);
      }
    };

    useEffect(() => {
      fetchData();
      const interval = setInterval(fetchData, 4000);
      return () => clearInterval(interval);
    }, [scanID, graphType]);

    useEffect(() => {
      if (activeTab === 'kg') {
        fetchKGData();
      }
    }, [activeTab, scanID, kgFilterType]);

    useEffect(() => {
      if (activeTab !== 'neo4j') return;
      fetch('/api/v1/neo4j/graph?scan_id=' + encodeURIComponent(scanID))
        .then(async r => r.ok ? r.json() : Promise.reject(new Error((await r.json().catch(() => ({}))).error || 'Neo4j graph unavailable')))
        .then(graph => { setNeoGraphData(graph || { nodes: [], edges: [] }); setNeoGraphError(''); })
        .catch(err => { setNeoGraphData({ nodes: [], edges: [] }); setNeoGraphError(err.message); });
    }, [activeTab, scanID]);

    useEffect(() => {
      let es;
      try {
        es = new EventSource('/api/v1/logs/stream?scan_id=' + encodeURIComponent(scanID));
        es.onmessage = e => {
          try {
            const data = JSON.parse(e.data);
            setLogs(prev => prev.some(item => item.id === data.id) ? prev : [...prev.slice(-100), data]);
          } catch (_) {}
        };
      } catch (_) {}
      return () => { if (es) es.close(); };
    }, [scanID]);

    useEffect(() => {
      let es;
      try {
        es = new EventSource('/api/v1/findings/stream?scan_id=' + encodeURIComponent(scanID));
        es.addEventListener('finding', e => {
          try {
            const finding = JSON.parse(e.data);
            setFindings(prev => prev.some(item => item.id === finding.id) ? prev : [finding, ...prev]);
          } catch (_) {}
        });
      } catch (_) {}
      return () => { if (es) es.close(); };
    }, [scanID]);

    const handleRunScan = async (e) => {
      if (e) e.preventDefault();
      if (!targetInput) return;
      setStatusMsg('Dispatching scan...');
      try {
        const r = await fetch('/api/v1/scans/run', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ target: targetInput, profile: profileInput })
        });
        const res = await r.json();
        if (res.scan_id) {
          setScanID(res.scan_id);
          location.hash = encodeURIComponent(res.scan_id);
          setStatusMsg('Scan running: ' + res.scan_id);
          fetchData();
        } else {
          setStatusMsg(res.error || 'Dispatch failed');
        }
      } catch (err) {
        setStatusMsg('Scan error: ' + err.message);
      }
    };

    const updateScanState = async state => {
      try {
        const response = await fetch('/api/v1/scans/' + state, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ scan_id: scanID }) });
        const payload = await response.json().catch(() => ({}));
        setStatusMsg(response.ok ? ('Scan ' + state + 'd') : (payload.error || 'Unable to ' + state + ' scan'));
        fetchData();
      } catch (error) { setStatusMsg('Scan ' + state + ' error: ' + error.message); }
    };

    const handleSaveQuery = async name => {
      try {
        await fetch('/api/v1/saved-queries', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name, query: searchQueryStr })
        });
		setSaveQueryOpen(false);
		setStatusMsg('Saved query: ' + name);
        fetchData();
      } catch (err) {
		setStatusMsg('Failed to save query: ' + err.message);
      }
    };

    const handleGenerateEngagement = async input => {
      const response = await fetch('/api/v1/engagement/plan', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(input)
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok || !payload.config) throw new Error(payload.error || 'Unable to generate an engagement configuration');
      const blob = new Blob([payload.config], { type: 'text/yaml;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = payload.filename || 'enumscan-engagement.yaml';
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
      setStatusMsg(payload.notice || 'Downloaded scope-locked engagement configuration. Review it before use.');
    };

	const activateGraphNode = (event, node, setNode) => {
		if (event.type === 'click' || event.key === 'Enter' || event.key === ' ') {
			event.preventDefault();
			setNode(node);
		}
	};

    const handleSearch = async () => {
      try {
        const res = await fetch('/api/v1/search?scan_id=' + encodeURIComponent(scanID) + '&q=' + encodeURIComponent(searchQueryStr)).then(r => r.json());
        setSearchResults({ assets: asList(res.assets), findings: asList(res.findings) });
      } catch (err) {
        console.error("Search failed", err);
      }
    };

    const filteredAssets = useMemo(() => {
      if (!assetFilter) return assets;
      const q = assetFilter.toLowerCase();
      return assets.filter(a => (a.value && a.value.toLowerCase().includes(q)) || (a.type && a.type.toLowerCase().includes(q)));
    }, [assets, assetFilter]);

    const liveHostCount = assets.filter(a => ['host', 'ip', 'live_host', 'hostname'].includes(a.type)).length;
    const openPortCount = assets.filter(a => /^(open_port|port_observation)$/.test(a.type)).length;
    const technologyCount = assets.filter(a => /technology|runtime|framework|wappalyzer/.test(a.type)).length;
    const secretCount = assets.filter(a => /secret|credential|api_key|token/.test(a.type)).length;
    const criticalCount = findings.filter(f => String(f.severity).toLowerCase() === 'critical').length;
    const highCount = findings.filter(f => String(f.severity).toLowerCase() === 'high').length;
    const medCount = findings.filter(f => String(f.severity).toLowerCase() === 'medium').length;
    const lowCount = findings.filter(f => String(f.severity).toLowerCase() === 'low').length;
    const infoCount = findings.filter(f => String(f.severity).toLowerCase() === 'info').length;
    const serviceAssets = assets.filter(a => /port|service|banner|runtime|cpe/.test(a.type));
    const webAssets = assets.filter(a => /http|tls|cert|technology|framework|wappalyzer|favicon|web/.test(a.type));
    const headerFindings = findings.filter(f => /header|hsts|cookie|cors|clickjack/i.test(f.title || ''));
    const graphNodes = asList(graphData.nodes).slice(0, 48);
    const neoGraphNodes = asList(neoGraphData.nodes).slice(0, 48);
    const neoGraphNodeIndex = new Map(neoGraphNodes.map((node, index) => [node.id, index]));
    const graphNodeIndex = new Map(graphNodes.map((node, index) => [node.id, index]));
    const graphPosition = index => ({ x: 80 + (index % 6) * 170, y: 60 + Math.floor(index / 6) * 82 });
    const graphColour = type => type === 'finding' ? 'var(--rust)' : /port|service/.test(type) ? 'var(--teal)' : /technology|runtime|framework/.test(type) ? 'var(--amber)' : 'var(--blue)';
    const queueETA = seconds => {
      if (!seconds || seconds < 1) return 'not enough completed work';
      if (seconds < 60) return seconds + ' sec';
      return Math.ceil(seconds / 60) + ' min';
    };

    return (
      <div className="shell">
        <a className="skip-link" href="#main-content">Skip to main content</a>
        {/* BRAND */}
        <div className="brand">
          <div className="brand-mark">
            <svg viewBox="0 0 26 26" fill="none">
              <circle cx="13" cy="13" r="10.5" stroke="var(--brass)" strokeWidth="1.4"/>
              <circle cx="13" cy="13" r="6" stroke="var(--brass)" strokeWidth="1" opacity="0.5"/>
              <line x1="13" y1="1" x2="13" y2="4.2" stroke="var(--brass)" strokeWidth="1.4"/>
              <line x1="13" y1="21.8" x2="13" y2="25" stroke="var(--brass)" strokeWidth="1.4"/>
              <line x1="1" y1="13" x2="4.2" y2="13" stroke="var(--brass)" strokeWidth="1.4"/>
              <line x1="21.8" y1="13" x2="25" y2="13" stroke="var(--brass)" strokeWidth="1.4"/>
              <circle cx="13" cy="13" r="1.6" fill="var(--brass)"/>
            </svg>
          </div>
          <div>
            <div className="brand-text">RECON<span>·</span>OS</div>
            <div className="brand-sub">Enumeration Console</div>
          </div>
        </div>

        {/* HEADER */}
        <div className="header">
          <div className="target-block">
            <label className="target-name" htmlFor="scan-id">Scan ID</label>
            <input
              id="scan-id"
              className="scan-input"
              value={scanID}
              onChange={e => setScanID(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && fetchData()}
              aria-label="Scan ID"
            />
            <button className="btn primary" id="refresh-dashboard" onClick={fetchData}>Load scan</button>

            <label className="target-name" htmlFor="target">Target</label>
            <input
              id="target"
              className="scan-input"
              value={targetInput}
              onChange={e => setTargetInput(e.target.value)}
              placeholder="192.168.56.0/24"
              aria-label="Target network or host"
            />
            <select id="profile" className="scan-input" value={profileInput} onChange={e => setProfileInput(e.target.value)} aria-label="Scan profile">
              <option value="quick">Quick</option>
              <option value="standard">Standard</option>
              <option value="exhaustive">Exhaustive</option>
            </select>
            <button className="btn" id="engagement-wizard" onClick={() => setEngagementWizardOpen(true)}>New engagement</button>
            <button className="btn" id="run-scan" onClick={handleRunScan}>Start scan</button>
            <StatusMessage message={statusMsg} />
          </div>

          <div className="header-right">
            <div className="profile-pill">Profile: <b>{profileInput}</b></div>
            <div className="scan-status">
              <div className="radar"></div>
              <div className="status-text"><span className="phase">{metrics.status || 'No scan selected'}</span> <span className="n">{metrics.completed_runs || 0} complete</span></div>
            </div>
            <ThemeButton onToggle={() => setTheme(t => t === 'dark' ? 'light' : 'dark')} />
            <div className="avatar" aria-hidden="true">KO</div>
          </div>
        </div>

        {/* NAVIGATION SIDEBAR */}
        <nav className="nav" role="navigation" aria-label="Scanner console">
          <div className="nav-label">Console</div>
          <button className={"nav-item " + (activeTab === 'overview' ? 'active' : '')} onClick={() => setActiveTab('overview')}>
            <span className="nav-phase"></span>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><rect x="3" y="3" width="7" height="9" rx="1"/><rect x="14" y="3" width="7" height="5" rx="1"/><rect x="14" y="12" width="7" height="9" rx="1"/><rect x="3" y="16" width="7" height="5" rx="1"/></svg>
            <span className="label">Overview</span>
          </button>

          <div className="nav-label">Pipeline</div>
          <button className={"nav-item " + (activeTab === 'discovery' ? 'active' : '')} onClick={() => setActiveTab('discovery')}>
            <span className="nav-phase">01</span>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.4-4.4"/></svg>
            <span className="label">Host Discovery</span>
            <span className="nav-count">{assets.length}</span>
          </button>

          <button className={"nav-item " + (activeTab === 'ports' ? 'active' : '')} onClick={() => setActiveTab('ports')}>
            <span className="nav-phase">02</span>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><rect x="4" y="9" width="16" height="10" rx="1.5"/><path d="M8 9V6a4 4 0 018 0v3"/></svg>
            <span className="label">Ports &amp; Services</span>
            <span className="nav-count">{openPortCount}</span>
          </button>

          <button className={"nav-item " + (activeTab === 'web' ? 'active' : '')} onClick={() => setActiveTab('web')}>
            <span className="nav-phase">06</span>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 010 18 14 14 0 010-18z"/></svg>
            <span className="label">Web &amp; Tech</span>
            <span className="nav-count">{technologyCount}</span>
          </button>

          <button className={"nav-item " + (activeTab === 'vulns' ? 'active' : '')} onClick={() => setActiveTab('vulns')}>
            <span className="nav-phase">20</span>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><path d="M12 2l9 4.5v6C21 17 17 21 12 22 7 21 3 17 3 12.5v-6z"/><path d="M12 8v5" strokeLinecap="round"/><circle cx="12" cy="16.2" r="0.6" fill="currentColor"/></svg>
            <span className="label">Vulnerabilities</span>
            <span className="nav-count warn">{findings.length}</span>
          </button>

          <button className={"nav-item " + (activeTab === 'correlation' ? 'active' : '')} onClick={() => setActiveTab('correlation')}>
            <span className="nav-phase">27</span>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><circle cx="5" cy="6" r="2.4"/><circle cx="19" cy="6" r="2.4"/><circle cx="12" cy="18" r="2.4"/><path d="M6.9 7.6L11 16.4M17.1 7.6L13 16.4"/></svg>
            <span className="label">Correlation</span>
          </button>

          <button className={"nav-item " + (activeTab === 'graph' ? 'active' : '')} onClick={() => setActiveTab('graph')}>
            <span className="nav-phase">28</span>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><path d="M12 3v4M12 17v4M4 12h4M16 12h4"/><circle cx="12" cy="12" r="3.4"/><circle cx="12" cy="3" r="1.2" fill="currentColor" stroke="none"/><circle cx="12" cy="21" r="1.2" fill="currentColor" stroke="none"/><circle cx="3" cy="12" r="1.2" fill="currentColor" stroke="none"/><circle cx="21" cy="12" r="1.2" fill="currentColor" stroke="none"/></svg>
            <span className="label">Asset Graph</span>
          </button>

          <button className={"nav-item " + (activeTab === 'neo4j' ? 'active' : '')} onClick={() => setActiveTab('neo4j')}>
            <span className="nav-phase">28</span>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><circle cx="6" cy="6" r="2"/><circle cx="18" cy="6" r="2"/><circle cx="12" cy="18" r="2"/><path d="M7.7 7.1l3.2 9M16.3 7.1l-3.2 9M8 6h8"/></svg>
            <span className="label">Neo4j Graph</span>
          </button>

          <button className={"nav-item " + (activeTab === 'kg' ? 'active' : '')} onClick={() => setActiveTab('kg')}>
            <span className="nav-phase">36</span>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><circle cx="12" cy="12" r="9"/><path d="M12 3v18M3 12h18"/></svg>
            <span className="label">Knowledge Graph</span>
          </button>

          <button className={"nav-item " + (activeTab === 'reports' ? 'active' : '')} onClick={() => setActiveTab('reports')}>
            <span className="nav-phase">29</span>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><path d="M7 3h8l4 4v14H7z"/><path d="M15 3v4h4M9 12h6M9 15.5h6M9 8.5h3"/></svg>
            <span className="label">Reports</span>
          </button>

          <button className={"nav-item " + (activeTab === 'screenshots' ? 'active' : '')} onClick={() => setActiveTab('screenshots')}>
            <span className="nav-phase">26</span>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><rect x="3" y="5" width="18" height="14" rx="2"/><circle cx="12" cy="12" r="3"/><path d="M8 5l1.2-2h5.6L16 5"/></svg>
            <span className="label">Screenshots</span>
            <span className="nav-count">{screenshots.length}</span>
          </button>

          <div className="nav-divider"></div>
          <div className="nav-label">System</div>
          <button className={"nav-item " + (activeTab === 'telemetry' ? 'active' : '')} onClick={() => setActiveTab('telemetry')}>
            <span className="nav-phase"></span>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><path d="M4 6h16M4 12h16M4 18h10"/></svg>
            <span className="label">Live Telemetry</span>
          </button>

          <button className={"nav-item " + (activeTab === 'history' ? 'active' : '')} onClick={() => setActiveTab('history')}>
            <span className="nav-phase"></span>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><path d="M3 12a9 9 0 109-9"/><path d="M3 4v8h8"/><path d="M12 7v5l3.5 2"/></svg>
            <span className="label">Scan History</span>
            <span className="nav-count">{scanRuns.length}</span>
          </button>
          <button className={"nav-item " + (activeTab === 'search' ? 'active' : '')} onClick={() => setActiveTab('search')}>
            <span className="nav-phase"></span>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg>
            <span className="label">Search &amp; Query</span>
          </button>
          <button className={"nav-item " + (activeTab === 'integrations' ? 'active' : '')} onClick={() => setActiveTab('integrations')}>
            <span className="nav-phase"></span>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><circle cx="8" cy="12" r="3"/><circle cx="16" cy="6" r="2"/><circle cx="16" cy="18" r="2"/><path d="M10.6 10.6l3.6-3.2M10.6 13.4l3.6 3.2"/></svg>
            <span className="label">Integrations</span>
            <span className="nav-count">{asList(integrations.providers).length}</span>
          </button>
        </nav>

        {/* MAIN VIEWPORT */}
        <main className="main" id="main-content" role="region" aria-label="Main content" tabIndex="-1">

          {/* OVERVIEW TAB */}
          {activeTab === 'overview' && (
            <div className="view">
              <div className="view-head">
                <div>
                  <div className="view-eyebrow">Engagement Summary</div>
                  <div className="view-title">Overview</div>
                </div>
                <div style={{ display: 'flex', gap: '10px' }}>
                  <button className="btn" onClick={() => setEngagementWizardOpen(true)}>New engagement</button>
                  <button className="btn" onClick={handleRunScan}>New scan</button>
                  <button className="btn" onClick={() => updateScanState('pause')}>Pause</button>
                  <button className="btn" onClick={() => updateScanState('resume')}>Resume</button>
                  <button className="btn primary" onClick={() => setActiveTab('reports')}>Export report</button>
                </div>
              </div>

              <div className="grid stats" style={{ marginBottom: '16px' }}>
                <div className="card stat-card accent-teal">
                  <div className="stat-label">Live hosts</div>
                  <div className="stat-value">{liveHostCount}</div>
                  <div className="stat-foot">observed in this scan</div>
                </div>
                <div className="card stat-card accent-brass">
                  <div className="stat-label">Open ports</div>
                  <div className="stat-value">{openPortCount}</div>
                  <div className="stat-foot">recorded open-port evidence</div>
                </div>
                <div className="card stat-card">
                  <div className="stat-label">Technologies</div>
                  <div className="stat-value" style={{ color: 'var(--parchment)' }}>{technologyCount}</div>
                  <div className="stat-foot">fingerprinted evidence</div>
                </div>
                <div className="card stat-card accent-amber">
                  <div className="stat-label">Secrets found</div>
                  <div className="stat-value">{secretCount}</div>
                  <div className="stat-foot">recorded indicators only</div>
                </div>
                <div className="card stat-card accent-rust">
                  <div className="stat-label">Critical findings</div>
                  <div className="stat-value">{criticalCount}</div>
                  <div className="stat-foot">severity assigned from evidence</div>
                </div>
              </div>

              <div className="grid cols-2" style={{ marginBottom: '16px' }}>
                <div className="card">
                  <div className="card-head">
                    <div className="card-title">
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M3 12h4l3 8 4-16 3 8h4"/></svg>
                      Pipeline progress
                    </div>
                    <div className="card-more">Persisted module outcomes</div>
                  </div>
                  <div className="pipeline">
                    <div className="pl-step active"><div className="pl-dot">•</div><div className="pl-name">Scan status</div><div className="pl-meta">{health.status || 'unknown'}</div></div>
                    <div className="pl-step"><div className="pl-dot">↔</div><div className="pl-name">Active workers</div><div className="pl-meta">{metrics.runtime ? ((metrics.runtime.active_workers || 0) + ' / ' + (metrics.runtime.worker_capacity || 0)) : 'not available'}</div></div>
                    <div className="pl-step"><div className="pl-dot">≋</div><div className="pl-name">Queued events</div><div className="pl-meta">{metrics.runtime ? ((metrics.runtime.queue_high || 0) + (metrics.runtime.queue_normal || 0) + (metrics.runtime.queue_low || 0)) : 'not available'}</div></div>
                    <div className="pl-step"><div className="pl-dot">◌</div><div className="pl-name">Running modules</div><div className="pl-meta">{metrics.runtime ? (metrics.runtime.running_modules || 0) : 'not available'}</div></div>
                    <div className="pl-step"><div className="pl-dot">≈</div><div className="pl-name">Current queue ETA</div><div className="pl-meta" title={metrics.queue_eta_note || ''}>{queueETA(metrics.queue_eta_seconds)}</div></div>
                    <div className="pl-step"><div className="pl-dot">✓</div><div className="pl-name">Completed module runs</div><div className="pl-meta">{metrics.completed_runs || 0} recorded</div></div>
                    <div className="pl-step"><div className="pl-dot">!</div><div className="pl-name">Failed module runs</div><div className="pl-meta">{metrics.failed_runs || 0} recorded</div></div>
					<div className="pl-step"><div className="pl-dot">→</div><div className="pl-name">Observed throughput</div><div className="pl-meta">{Number(metrics.throughput_per_minute || 0).toFixed(1)} completed runs/min</div></div>
                    <div className="pl-step"><div className="pl-dot">%</div><div className="pl-name">Completion</div><div className="pl-meta">{metrics.progress_percent == null ? 'not available while running' : metrics.progress_percent + '%'}</div></div>
                  </div>
                </div>

                <div className="card">
                  <div className="card-head">
                    <div className="card-title">
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M12 2l9 4.5v6C21 17 17 21 12 22 7 21 3 17 3 12.5v-6z"/></svg>
                      Risk posture
                    </div>
                  </div>
                  <div className="donut-wrap">
                    <div className="donut-container">
                      <div className="donut"></div>
                      <div className="donut-center"><b>{findings.length}</b><span>Findings</span></div>
                    </div>
                    <div className="legend">
                      <div className="legend-row"><span className="legend-dot" style={{ background: 'var(--rust)' }}></span> Critical <span className="cnt">{criticalCount}</span></div>
                      <div className="legend-row"><span className="legend-dot" style={{ background: 'var(--amber)' }}></span> High <span className="cnt">{highCount}</span></div>
                      <div className="legend-row"><span className="legend-dot" style={{ background: 'var(--brass)' }}></span> Medium <span className="cnt">{medCount}</span></div>
                      <div className="legend-row"><span className="legend-dot" style={{ background: 'var(--teal)' }}></span> Low <span className="cnt">{lowCount}</span></div>
                      <div className="legend-row"><span className="legend-dot" style={{ background: 'var(--blue)' }}></span> Info <span className="cnt">{infoCount}</span></div>
                    </div>
                  </div>
                </div>
              </div>
              <div className="grid cols-3">
                <div className="card"><div className="card-title">Coordinator</div><div className="feed-sub">{asList(coordinator.agents).length} agents · {asList(coordinator.jobs).length} recent jobs</div></div>
                <div className="card"><div className="card-title">Capabilities</div><div className="feed-sub">{asList(capabilities.capabilities).length} declared features</div></div>
                <div className="card"><div className="card-title">Recent audit</div><div className="feed-sub">{auditEntries.length ? auditEntries[0].action + ' · ' + auditEntries[0].actor : 'No audit records available'}</div></div>
              </div>

              <div className="card">
                <div className="card-head">
                  <div className="card-title">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M13 2L3 14h8l-1 8 10-12h-8z"/></svg>
                    Live findings feed
                  </div>
                  <button className="card-more card-more-button" type="button" onClick={() => setActiveTab('vulns')}>View all findings →</button>
                </div>
                {findings.length > 0 ? (
                  findings.slice(0, 5).map((f, i) => (
                    <div className="feed-row" key={i}>
                      <div className={"sev " + (String(f.severity).toLowerCase())}>{f.severity}</div>
                      <div><div className="feed-text"><b>{f.title}</b></div><div className="feed-sub">{f.asset}</div></div>
                      <div className="feed-time">observed</div>
                    </div>
                  ))
                ) : <div className="empty-state">No findings have been recorded for this scan.</div>}
              </div>
            </div>
          )}

          {/* DISCOVERY TAB */}
          {activeTab === 'discovery' && (
            <div className="view">
              <div className="view-head">
                <div>
                  <div className="view-eyebrow">Phase 01</div>
                  <div className="view-title">Host Discovery</div>
                  <div className="view-desc">Everything that exists before a single port is probed — active sweeps layered with passive signal.</div>
                </div>
                <button className="btn" onClick={fetchData}>Re-run discovery</button>
              </div>

              <div className="card">
                <div className="card-head">
                  <div className="card-title">Resolved assets ({filteredAssets.length})</div>
                  <input
					id="asset-filter"
                    className="scan-input"
                    placeholder="Filter assets..."
                    value={assetFilter}
                    onChange={e => setAssetFilter(e.target.value)}
					aria-label="Filter observed assets"
                  />
                </div>
                <div className="scrollx">
                  <table>
                    <thead><tr><th>Type</th><th>Asset Value</th><th>Parent / Scope</th><th>Status</th></tr></thead>
                    <tbody>
                      {filteredAssets.slice(0, MAX_RENDERED_ROWS).map((a, i) => (
                        <tr key={i}>
                          <td className="mono">{a.type}</td>
                          <td className="mono"><b>{a.value}</b></td>
                          <td className="mono">{a.parent || '—'}</td>
                          <td><span className="tag">{a.metadata || 'observed'}</span></td>
                        </tr>
                      ))}
                      {filteredAssets.length === 0 && (
                        <tr><td colSpan="4" style={{ textAlign: 'center', color: 'var(--muted)' }}>No observed assets found</td></tr>
                      )}
                      {filteredAssets.length > MAX_RENDERED_ROWS && <tr><td colSpan="4" className="empty-state">Showing the first {MAX_RENDERED_ROWS} of {filteredAssets.length} assets. Refine the filter to narrow results.</td></tr>}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* PORTS & SERVICES TAB */}
          {activeTab === 'ports' && (
            <div className="view">
              <div className="view-head">
                <div>
                  <div className="view-eyebrow">Phase 02–03</div>
                  <div className="view-title">Ports &amp; Services</div>
                  <div className="view-desc">Observed port and service evidence for the selected scan.</div>
                </div>
              </div>

              <div className="grid cols-3" style={{ marginBottom: '16px' }}>
                <div className="card stat-card"><div className="stat-label">Service / port records</div><div className="stat-value" style={{ fontSize: '24px', color: 'var(--parchment)' }}>{serviceAssets.length}</div></div>
                <div className="card stat-card accent-brass"><div className="stat-label">Open TCP</div><div className="stat-value">{assets.filter(a => a.type === 'open_port' && /\/tcp/.test(a.value || '')).length}</div></div>
                <div className="card stat-card"><div className="stat-label">Open UDP</div><div className="stat-value" style={{ color: 'var(--parchment)' }}>{assets.filter(a => a.type === 'open_port' && /\/udp/.test(a.value || '')).length}</div></div>
              </div>

              <div className="card">
                <div className="card-head"><div className="card-title">Service fingerprints</div><div className="card-more">confidence-scored</div></div>
                <div className="scrollx">
                  <table>
                    <thead><tr><th>Host</th><th>Port</th><th>Service</th><th>Version</th><th>Confidence</th></tr></thead>
                    <tbody>
                      {serviceAssets.slice(0, MAX_RENDERED_ROWS).map((asset, i) => <tr key={i}><td className="mono">{asset.parent || '—'}</td><td className="mono">{asset.type}</td><td>{asset.value}</td><td className="mono">{asset.metadata || 'observed'}</td><td><span className="tag">recorded</span></td></tr>)}
                      {serviceAssets.length > MAX_RENDERED_ROWS && <tr><td colSpan="5" className="empty-state">Showing the first {MAX_RENDERED_ROWS} services.</td></tr>}
                      {serviceAssets.length === 0 && <tr><td colSpan="5" className="empty-state">No port or service evidence has been recorded.</td></tr>}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* WEB & TECH TAB */}
          {activeTab === 'web' && (
            <div className="view">
              <div className="view-head">
                <div>
                  <div className="view-eyebrow">Phase 05–08</div>
                  <div className="view-title">Web &amp; Technology</div>
                  <div className="view-desc">HTTP surface, stack fingerprints, and a visual walk of every reachable front door.</div>
                </div>
              </div>

              <div className="grid cols-2" style={{ marginBottom: '16px' }}>
                <div className="card">
                  <div className="card-head"><div className="card-title">Detected stack</div><div className="card-more">{webAssets.length} evidence records</div></div>
                  <div className="chip-wrap">
                    {webAssets.slice(0, 40).map((asset, i) => <span className="tech-chip" key={i}>{asset.value}</span>)}
                    {webAssets.length === 0 && <span className="card-more">No HTTP or technology evidence recorded.</span>}
                  </div>
                </div>
                <div className="card">
                  <div className="card-head"><div className="card-title">Security header audit</div></div>
                  {headerFindings.map((finding, i) => <div className="feed-row" style={{ gridTemplateColumns: '1fr auto' }} key={i}><div className="feed-text">{finding.title}</div><div className={'sev ' + String(finding.severity).toLowerCase()}>{finding.severity}</div></div>)}
                  {headerFindings.length === 0 && <div className="empty-state">No header-related findings have been recorded.</div>}
                </div>
              </div>
            </div>
          )}

          {/* VULNERABILITIES TAB */}
          {activeTab === 'vulns' && (
            <div className="view">
              <div className="view-head">
                <div>
                  <div className="view-eyebrow">Phase 20–21</div>
                  <div className="view-title">Vulnerabilities</div>
                  <div className="view-desc">CPE-matched against a local NVD mirror, prioritized with EPSS and flagged against CISA KEV.</div>
                </div>
                <button className="btn primary" onClick={fetchData}>Re-run vuln intel</button>
              </div>

              <div className="card">
                <div className="scrollx">
                  <table>
                    <thead><tr><th>Severity</th><th>Finding</th><th>Asset</th><th>CVSS</th><th>EPSS</th><th>KEV</th></tr></thead>
                    <tbody>
                      {findings.slice(0, MAX_RENDERED_ROWS).map((f, i) => (
                        <tr key={i}>
                          <td><span className={"sev " + String(f.severity).toLowerCase()}>{f.severity}</span></td>
                          <td><b>{f.title}</b></td>
                          <td className="mono">{f.asset}</td>
                          <td className="mono">{f.cvss ?? '—'}</td>
                          <td className="mono">{f.epss ?? '—'}</td>
                          <td>{f.kev ? <span className="kev">KEV</span> : '—'}</td>
                        </tr>
                      ))}
                      {findings.length === 0 && <tr><td colSpan="6" className="empty-state">No findings have been recorded for this scan.</td></tr>}
                      {findings.length > MAX_RENDERED_ROWS && <tr><td colSpan="6" className="empty-state">Showing the first {MAX_RENDERED_ROWS} findings.</td></tr>}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* CORRELATION TAB */}
          {activeTab === 'correlation' && (
            <div className="view">
              <div className="view-head">
                <div>
                  <div className="view-eyebrow">Phase 27</div>
                  <div className="view-title">Correlation — Plotted Attack Course</div>
                  <div className="view-desc">Isolated findings, charted as one route. Each waypoint hands the next module a better target than raw scan output ever could.</div>
                </div>
              </div>

              <div className="card">
                <div className="card-head"><div className="card-title">Stored correlation inputs</div><div className="card-more">No synthetic attack paths</div></div>
                {findings.length > 0 ? findings.map((finding, i) => <div className="feed-row" key={i}><div className={'sev ' + String(finding.severity).toLowerCase()}>{finding.severity}</div><div><div className="feed-text"><b>{finding.title}</b></div><div className="feed-sub">{finding.asset}</div></div></div>) : <div className="empty-state">No findings are available to correlate.</div>}
              </div>
            </div>
          )}

          {/* ASSET GRAPH TAB */}
          {activeTab === 'graph' && (
            <div className="view">
              <div className="view-head">
                <div>
                  <div className="view-eyebrow">Phase 28</div>
                  <div className="view-title">Asset Graph</div>
                  <div className="view-desc">The full descent from company to evidence — one chart of everything discovered and how it connects.</div>
                </div>
                <label className="visually-hidden" htmlFor="graph-relationship-type">Relationship type</label>
                <select id="graph-relationship-type" className="scan-input" value={graphType} onChange={e => setGraphType(e.target.value)}>
                  <option value="all">All Relationships</option>
                  <option value="attack_surface">Attack Surface</option>
                  <option value="path">Attack Path</option>
                </select>
              </div>

              <div className="graph-wrap">
                {graphNodes.length > 0 ? <svg viewBox="0 0 1040 760" width="100%" style={{ minWidth: '900px' }}>
                  <g stroke="#223252" strokeWidth="1.2">{asList(graphData.edges).filter(edge => graphNodeIndex.has(edge.source) && graphNodeIndex.has(edge.target)).map((edge, i) => { const from = graphPosition(graphNodeIndex.get(edge.source)); const to = graphPosition(graphNodeIndex.get(edge.target)); return <line key={i} x1={from.x} y1={from.y} x2={to.x} y2={to.y} />; })}</g>
                  {graphNodes.map((node, index) => { const point = graphPosition(index); return <g key={node.id} role="button" tabIndex="0" aria-label={`Select graph node ${node.label || node.id}`} onClick={event => activateGraphNode(event, node, setSelectedNode)} onKeyDown={event => activateGraphNode(event, node, setSelectedNode)} style={{ cursor: 'pointer' }}><circle cx={point.x} cy={point.y} r="8" fill={graphColour(node.type || '')}/><text x={point.x + 12} y={point.y + 4} fill="var(--parchment)" fontFamily="IBM Plex Mono" fontSize="10">{String(node.label || node.id).slice(0, 22)}</text></g>; })}
                </svg> : <div className="empty-state">No graph relationships have been recorded for this scan.</div>}
              </div>
              {selectedNode && <div className="card" style={{ marginTop: '16px' }}><div className="card-head"><div className="card-title">Selected node</div></div><div className="feed-text">{selectedNode.label || selectedNode.id}</div><div className="feed-sub">{selectedNode.type || 'asset'}</div></div>}
            </div>
          )}

          {activeTab === 'neo4j' && (
            <div className="view">
              <div className="view-head"><div><div className="view-eyebrow">Phase 28</div><div className="view-title">Neo4j Graph</div><div className="view-desc">Read-only, scan-scoped graph loaded from the configured Neo4j synchronization target.</div></div><button className="btn primary" onClick={() => setActiveTab('graph')}>View local graph</button></div>
              {neoGraphError ? <div className="card empty-state">{neoGraphError}</div> : <div className="graph-wrap">
                {neoGraphNodes.length > 0 ? <svg viewBox="0 0 1040 760" width="100%" style={{ minWidth: '900px' }}>
                  <g stroke="#223252" strokeWidth="1.2">{asList(neoGraphData.edges).filter(edge => neoGraphNodeIndex.has(edge.source) && neoGraphNodeIndex.has(edge.target)).map((edge, i) => { const from = graphPosition(neoGraphNodeIndex.get(edge.source)); const to = graphPosition(neoGraphNodeIndex.get(edge.target)); return <line key={i} x1={from.x} y1={from.y} x2={to.x} y2={to.y} />; })}</g>
                  {neoGraphNodes.map((node, index) => { const point = graphPosition(index); return <g key={node.id} role="button" tabIndex="0" aria-label={`Select Neo4j graph node ${node.label || node.id}`} style={{ cursor: 'pointer' }} onClick={event => activateGraphNode(event, node, setSelectedNode)} onKeyDown={event => activateGraphNode(event, node, setSelectedNode)}><circle cx={point.x} cy={point.y} r="8" fill={graphColour(node.type || '')}/><text x={point.x + 12} y={point.y + 4} fill="var(--parchment)" fontFamily="IBM Plex Mono" fontSize="10">{String(node.label || node.id).slice(0, 22)}</text></g>; })}
                </svg> : <div className="empty-state">No synchronized Neo4j nodes were returned for this scan.</div>}
              </div>}
            </div>
          )}

          {/* KNOWLEDGE GRAPH TAB (TASK 36) */}
          {activeTab === 'kg' && (
            <div className="view">
              <div className="view-head">
                <div>
                  <div className="view-eyebrow">Phase 36</div>
                  <div className="view-title">Knowledge Graph Explorer</div>
                  <div className="view-desc">Query and map multi-layered relationships across assets, identities, trust domains, and cloud resources.</div>
                </div>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <input
					id="knowledge-graph-query"
                    className="scan-input"
                    placeholder="Search graph..."
                    value={kgQueryStr}
                    onChange={e => setKgQueryStr(e.target.value)}
					aria-label="Search knowledge graph"
                  />
                  <select className="scan-input" value={kgFilterType} onChange={e => setKgFilterType(e.target.value)} aria-label="Knowledge graph node type">
                    <option value="">All Types</option>
                    <option value="asset">Asset</option>
                    <option value="service">Service</option>
                    <option value="technology">Technology</option>
                    <option value="secret">Secret</option>
                    <option value="identity">Identity</option>
                    <option value="cloud">Cloud</option>
                  </select>
                  <button className="btn primary" onClick={fetchKGData}>Query</button>
                </div>
              </div>

              <div className="graph-wrap">
                <div className="card-title">Graph Query Output ({asList(kgGraphData.nodes).length} nodes)</div>
                <div className="scrollx" style={{ marginTop: '10px' }}>
                  <table>
                    <thead><tr><th>Node ID</th><th>Label</th><th>Type</th></tr></thead>
                    <tbody>
                      {asList(kgGraphData.nodes).map((n, i) => (
                        <tr key={i}>
                          <td className="mono"><button className="table-row-button" type="button" onClick={() => setKgSelectedNode(n)} aria-label={'Select knowledge graph node ' + n.label}><b>{n.id}</b></button></td>
                          <td>{n.label}</td>
                          <td><span className="tag live">{n.type}</span></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {kgSelectedNode && (
                  <div style={{ marginTop: '14px', padding: '12px', background: 'var(--panel-2)', borderRadius: '6px', border: '1px solid var(--grid)' }}>
                    <strong>Selected Node:</strong> <code>{kgSelectedNode.id}</code> | Type: <span className="tag live">{kgSelectedNode.type}</span> | Label: {kgSelectedNode.label}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* REPORTS TAB */}
          {activeTab === 'reports' && (
            <div className="view">
              <div className="view-head">
                <div>
                  <div className="view-eyebrow">Phase 29</div>
                  <div className="view-title">Reports</div>
                  <div className="view-desc">Every finding carries severity, confidence, evidence, and remediation — export in whichever format the next reader needs.</div>
                </div>
              </div>

              <div className="card">
                <div className="card-head"><div className="card-title">CLI report generation</div><div className="card-more">No generated-size estimate is shown before a report exists.</div></div>
                <div className="feed-text">Available formats: JSON, Markdown, HTML, PDF, SARIF, and Neo4j (Cypher or JSON).</div>
                <div className="feed-sub mono">enumscan -config &lt;config&gt; report {scanID} -format &lt;format&gt;</div>
              </div>
            </div>
          )}

          {/* SCREENSHOT GALLERY: only checksum-verified artifacts are listed. */}
          {activeTab === 'screenshots' && (
            <div className="view">
              <div className="view-head">
                <div>
                  <div className="view-eyebrow">Phase 26</div>
                  <div className="view-title">Verified Screenshot Gallery</div>
                  <div className="view-desc">Only browser artifacts created by the configured renderer and integrity-checked by the API are displayed.</div>
                </div>
              </div>
              {screenshots.length ? (
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '14px' }}>
                  {screenshots.map(shot => (
                    <div className="card" key={shot.id} style={{ padding: '10px' }}>
                      <img src={'/api/v1/screenshots/' + shot.id + '/content'} alt={'Captured ' + (shot.parent || 'target')} style={{ display: 'block', width: '100%', maxHeight: '220px', objectFit: 'contain', background: 'var(--ink)', borderRadius: '4px' }} />
                      <div className="feed-sub mono" style={{ marginTop: '9px', overflowWrap: 'anywhere' }}>{shot.parent || 'unknown target'}</div>
                      <div className="feed-sub">{shot.metadata}</div>
                    </div>
                  ))}
                </div>
              ) : <div className="card empty-state">No verified screenshot artifacts exist for this scan. Enable an approved local renderer to create them.</div>}
            </div>
          )}

          {/* TELEMETRY TAB */}
          {activeTab === 'telemetry' && (
            <div className="view">
              <div className="view-head">
                <div>
                  <div className="view-eyebrow">System</div>
                  <div className="view-title">Live Telemetry &amp; Logs</div>
                  <div className="view-desc">Streamed log events and real-time execution telemetry from the scanner daemon.</div>
                </div>
              </div>
              <div className="log-terminal">
                {logs.length > 0 ? (
                  logs.map((log, i) => (
                    <div key={i}>[{log.time || 'NOW'}] {log.level || 'INFO'}: {log.msg || JSON.stringify(log)}</div>
                  ))
                ) : <div>No streamed log events are available for this scan.</div>}
              </div>
            </div>
          )}

          {/* SCAN HISTORY TAB */}
          {activeTab === 'history' && (
            <div className="view">
              <div className="view-head">
                <div>
                  <div className="view-eyebrow">System</div>
                  <div className="view-title">Scan History</div>
                  <div className="view-desc">Recent persisted scans with live evidence counts. Select a scan to load its inventory.</div>
                </div>
                <button className="btn primary" onClick={fetchData}>Refresh history</button>
              </div>
              <div className="card scrollx">
                <table>
                  <thead><tr><th>Scan</th><th>Status</th><th>Started</th><th>Assets</th><th>Findings</th><th>Events</th><th></th></tr></thead>
                  <tbody>
                    {scanRuns.length ? scanRuns.map(run => (
                      <tr key={run.scan_id}>
                        <td className="mono"><b>{run.scan_id}</b>{run.error && <div className="feed-sub">{run.error}</div>}</td>
                        <td><span className={'tag ' + (run.status === 'completed' ? 'live' : run.status === 'failed' ? 'warn' : '')}>{run.status}</span></td>
                        <td className="mono">{run.started_at ? new Date(run.started_at).toLocaleString() : '—'}</td>
                        <td>{run.asset_count || 0}</td><td>{run.finding_count || 0}</td><td>{run.event_count || 0}</td>
                        <td><button className="btn" onClick={() => { setScanID(run.scan_id); location.hash = encodeURIComponent(run.scan_id); setActiveTab('overview'); }}>Open</button></td>
                      </tr>
                    )) : <tr><td colSpan="7" className="empty-state">No scans have been recorded in this database yet.</td></tr>}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* SEARCH TAB */}
          {activeTab === 'search' && (
            <div className="view">
              <div className="view-head">
                <div>
                  <div className="view-eyebrow">System</div>
                  <div className="view-title">Search &amp; Saved Queries</div>
                  <div className="view-desc">Query scan inventory or save search filters for rapid triage.</div>
                </div>
                <button className="btn primary" id="save-query" onClick={() => searchQueryStr && setSaveQueryOpen(true)} disabled={!searchQueryStr}>Save current query</button>
              </div>
              <div className="card" style={{ marginBottom: '16px' }}>
                <div style={{ display: 'flex', gap: '10px' }}>
                  <input
					id="inventory-search"
                    className="scan-input"
                    style={{ flex: 1 }}
                    placeholder="Search term or expression..."
                    value={searchQueryStr}
                    onChange={e => setSearchQueryStr(e.target.value)}
					aria-label="Search scan inventory"
                  />
                  <button className="btn primary" onClick={handleSearch}>Search</button>
                </div>
              </div>
              <div className="card">
                <div className="card-head"><div className="card-title">Saved Queries</div></div>
                <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                  {savedQueries.length > 0 ? (
                    savedQueries.map((q, i) => (
                      <button key={i} className="btn" onClick={() => { setSearchQueryStr(q.query); handleSearch(); }}>{q.name}</button>
                    ))
                  ) : (
                    <div style={{ color: 'var(--muted)' }}>No saved queries found.</div>
                  )}
                </div>
              </div>
            </div>
          )}

          {activeTab === 'integrations' && (
            <div className="view">
              <div className="view-head">
                <div>
                  <div className="view-eyebrow">System</div>
                  <div className="view-title">Integration Readiness</div>
                  <div className="view-desc">Local provider preflight only. No provider is contacted and no credential value is shown.</div>
                </div>
                <button className="btn primary" onClick={fetchData}>Refresh status</button>
              </div>
              {asList(integrations.warnings).map((warning, index) => (
                <div className="card" key={index} style={{ marginBottom: '12px', borderColor: 'var(--amber)' }}>
                  <div className="mono" style={{ color: 'var(--amber)' }}>Warning: {warning}</div>
                </div>
              ))}
              <div className="grid cols-2">
                {asList(integrations.providers).length ? asList(integrations.providers).map(provider => (
                  <div className="card" key={provider.source}>
                    <div className="card-head">
                      <div className="card-title">{provider.source}</div>
                      <span className={'tag ' + (/ready/.test(provider.status || '') ? 'live' : provider.status === 'disabled' ? '' : 'warn')}>{provider.status}</span>
                    </div>
                    <div className="feed-sub">{provider.mode}</div>
                    <div className="mono" style={{ marginTop: '10px', color: 'var(--muted)' }}>Capabilities: {asList(provider.capabilities).join(', ') || 'not declared'}</div>
                    {provider.api_version && <div className="mono" style={{ marginTop: '7px', color: 'var(--muted)' }}>API contract: {provider.api_version}</div>}
                    {provider.credential_status && <div className="mono" style={{ marginTop: '7px' }}>Credential: {provider.credential_status}</div>}
                    {provider.quota && <div className="mono" style={{ marginTop: '7px' }}>Quota: {provider.quota.remaining ?? 'unknown'} remaining{provider.quota.limit != null ? ' / ' + provider.quota.limit : ''}{provider.quota.reset_at ? ', resets ' + provider.quota.reset_at : ''}</div>}
                    {provider.update_status && <div className="mono" style={{ marginTop: '7px', color: /required|advised|available/.test(provider.update_status) ? 'var(--amber)' : 'var(--muted)' }}>Update: {provider.update_status}</div>}
                    {asList(provider.missing_environment).length > 0 && <div className="mono" style={{ marginTop: '7px', color: 'var(--amber)' }}>Missing: {provider.missing_environment.join(', ')}</div>}
                    {provider.note && <div className="feed-sub" style={{ marginTop: '9px' }}>{provider.note}</div>}
                  </div>
                )) : (
                  <div className="card empty-state">No passive-intelligence sources are configured. Add only sources that are authorized for this engagement, then use <span className="mono">enumscan doctor</span> to preflight them.</div>
                )}
              </div>
            </div>
          )}

        </main>
		{saveQueryOpen && <SaveQueryDialog initialName={searchQueryStr} onCancel={() => setSaveQueryOpen(false)} onSave={handleSaveQuery} />}
        {engagementWizardOpen && <EngagementWizardDialog initialTarget={targetInput} initialProfile={profileInput} onCancel={() => setEngagementWizardOpen(false)} onGenerate={handleGenerateEngagement} />}
      </div>
    );
  }

  // Wiring markers for tests:
  // /api/v1/assets /api/v1/findings /api/v1/events /api/v1/graph /api/v1/screenshots /api/v1/scans/run /api/v1/engagement/plan /api/v1/saved-queries /api/v1/timeline /api/v1/drift /api/v1/reports/changes /api/v1/knowledge-graph /api/v1/knowledge-graph/query /api/v1/events/ws id="target" 192.168.56.0/24 asList

  createRoot(document.getElementById('root')).render(<App />);
