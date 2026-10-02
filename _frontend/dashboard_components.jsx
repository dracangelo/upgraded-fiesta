import React from "react";

export function StatusMessage({ message }) {
  return <div className="scope-badge" id="dashboard-message" role="status" aria-live="polite">{message}</div>;
}

export function ThemeButton({ onToggle }) {
  return (
    <button className="icon-btn" title="Toggle Theme" aria-label="Toggle color theme" onClick={onToggle}>
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true">
        <circle cx="12" cy="12" r="5" />
        <path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42" />
      </svg>
    </button>
  );
}

export function SaveQueryDialog({ initialName, onCancel, onSave }) {
  const [name, setName] = React.useState(initialName);
  const submit = event => {
    event.preventDefault();
    const value = name.trim();
    if (value) onSave(value);
  };
  return (
    <div className="dialog-backdrop" role="presentation" onMouseDown={onCancel}>
      <div
        className="dialog-card"
        role="dialog"
        aria-modal="true"
        aria-labelledby="save-query-title"
        onKeyDown={event => {
          if (event.key === "Escape") {
            event.preventDefault();
            onCancel();
          }
        }}
        onMouseDown={event => event.stopPropagation()}
      >
        <form onSubmit={submit}>
          <h2 id="save-query-title">Save search query</h2>
          <p id="save-query-help">Choose a descriptive name. The current search text is saved, not target evidence or credentials.</p>
          <label htmlFor="saved-query-name">Query name</label>
          <input id="saved-query-name" className="scan-input" autoFocus value={name} onChange={event => setName(event.target.value)} aria-describedby="save-query-help" />
          <div className="dialog-actions">
            <button className="btn" type="button" onClick={onCancel}>Cancel</button>
            <button className="btn primary" type="submit">Save query</button>
          </div>
        </form>
      </div>
    </div>
  );
}

export function EngagementWizardDialog({ initialTarget, initialProfile, onCancel, onGenerate }) {
  const [target, setTarget] = React.useState(initialTarget);
  const [profile, setProfile] = React.useState(initialProfile || "standard");
  const [filename, setFilename] = React.useState("enumscan-engagement.yaml");
  const [authorization, setAuthorization] = React.useState("");
  const [error, setError] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const submit = async event => {
    event.preventDefault();
    setError("");
    setBusy(true);
    try {
      await onGenerate({
        target: target.trim(),
        profile,
        authorization: authorization.trim(),
        filename: filename.trim() || "enumscan-engagement.yaml"
      });
      onCancel();
    } catch (err) {
      setError(err.message || "Unable to create the engagement configuration.");
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="dialog-backdrop" role="presentation" onMouseDown={onCancel}>
      <div className="dialog-card engagement-wizard" role="dialog" aria-modal="true" aria-labelledby="engagement-wizard-title" aria-describedby="engagement-wizard-help" onMouseDown={event => event.stopPropagation()}>
        <form onSubmit={submit}>
          <h2 id="engagement-wizard-title">New authorized engagement</h2>
          <p id="engagement-wizard-help">This downloads a reviewable YAML plan locked to one target. It enables safe discovery, port scanning, and HTTP enumeration only; it never enables active testing or includes credentials.</p>
          <label htmlFor="engagement-target">Authorized target</label>
          <input id="engagement-target" className="scan-input" autoFocus required value={target} onChange={event => setTarget(event.target.value)} placeholder="192.168.56.0/24 or app.example.com" />
          <label htmlFor="engagement-filename">Configuration file name</label>
          <input id="engagement-filename" className="scan-input" required value={filename} onChange={event => setFilename(event.target.value)} placeholder="enumscan-engagement.yaml" />
          <label htmlFor="engagement-profile">Scan type / profile</label>
          <select id="engagement-profile" className="scan-input" value={profile} onChange={event => setProfile(event.target.value)}>
            <option value="quick">Quick</option>
            <option value="standard">Standard</option>
            <option value="exhaustive">Exhaustive</option>
            <option value="all">All scan types</option>
            <option value="web">Web application</option>
            <option value="network">Internal network</option>
            <option value="api">API assessment</option>
            <option value="external">External infrastructure</option>
            <option value="cloud">Cloud infrastructure</option>
          </select>
          <label htmlFor="engagement-authorization">Written authorization reference</label>
          <input id="engagement-authorization" className="scan-input" required value={authorization} onChange={event => setAuthorization(event.target.value)} placeholder="ENG-2026-004" aria-describedby="engagement-wizard-help" />
          {error && <div className="dialog-error" role="alert">{error}</div>}
          <div className="dialog-actions">
            <button className="btn" type="button" onClick={onCancel} disabled={busy}>Cancel</button>
            <button className="btn primary" type="submit" disabled={busy}>{busy ? "Generating…" : "Download config"}</button>
          </div>
        </form>
      </div>
    </div>
  );
}
