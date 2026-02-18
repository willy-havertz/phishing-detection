import { useState, useEffect, useCallback } from "react";
import { getScanHistory, clearHistory } from "../utils/scanStorage";

function History() {
  const [scans, setScans] = useState([]);
  const [filter, setFilter] = useState({ classification: "", content_type: "" });
  const [expandedId, setExpandedId] = useState(null);

  const loadScans = useCallback(() => { setScans(getScanHistory()); }, []);

  useEffect(() => { loadScans(); const handleUpdate = () => loadScans(); window.addEventListener("scanUpdated", handleUpdate); return () => window.removeEventListener("scanUpdated", handleUpdate); }, [loadScans]);

  const handleClearHistory = () => {
    if (window.confirm("Are you sure you want to clear all scan history? This cannot be undone.")) {
      clearHistory();
      setScans([]);
    }
  };

  const filteredScans = scans.filter((s) => {
    if (filter.classification && s.classification !== filter.classification) return false;
    if (filter.content_type && s.content_type !== filter.content_type) return false;
    return true;
  });

  const getIcon = (c) => c === "safe" ? "fas fa-check-circle" : c === "suspicious" ? "fas fa-exclamation-triangle" : "fas fa-exclamation-circle";
  const getTypeIcon = (t) => t === "email" ? "fas fa-envelope" : t === "sms" ? "fas fa-mobile-alt" : "fas fa-link";
  const getTypeLabel = (t) => t === "email" ? "Email" : t === "sms" ? "SMS" : "URL";

  const getRiskConfig = (risk) => {
    const configs = {
      critical: { bg: "#FEE2E2", color: "#DC2626", label: "Critical" },
      high: { bg: "#FFF7ED", color: "#EA580C", label: "High" },
      medium: { bg: "#FFFBEB", color: "#D97706", label: "Medium" },
      low: { bg: "#ECFDF5", color: "#059669", label: "Low" },
    };
    return configs[risk] || configs.low;
  };

  const getConfidenceColor = (score) => score < 0.3 ? "#10B981" : score < 0.6 ? "#F59E0B" : "#EF4444";

  return (
    <div className="history-page">
      <div className="page-header">
        <div>
          <h1 className="page-title"><i className="fas fa-history" style={{ marginRight: '15px' }}></i> Scan History</h1>
          <p className="page-subtitle">Review all your past scans and their results</p>
        </div>
        {scans.length > 0 && (
          <button onClick={handleClearHistory} className="clear-btn"><i className="fas fa-trash-alt" style={{ marginRight: '8px' }}></i> Clear History</button>
        )}
      </div>

      {scans.length === 0 ? (
        <div className="empty-state">
          <div className="empty-icon"><i className="fas fa-inbox"></i></div>
          <h3>No Scan History Yet</h3>
          <p>All your scan results will be automatically saved here. Go to the <a href="/">Scanner</a> page to start checking content.</p>
          <a href="/" className="empty-cta"><i className="fas fa-search" style={{ marginRight: '8px' }}></i> Go to Scanner</a>
        </div>
      ) : (
        <>
          {/* Filters */}
          <div className="filter-bar">
            <div className="filter-group">
              <label className="filter-label">Filter by result:</label>
              <div className="filter-chips">
                <button className={`filter-chip ${filter.classification === "" ? "active" : ""}`} onClick={() => setFilter({...filter, classification: ""})}>All</button>
                <button className={`filter-chip chip-danger ${filter.classification === "phishing" ? "active" : ""}`} onClick={() => setFilter({...filter, classification: "phishing"})}><i className="fas fa-exclamation-circle" style={{ marginRight: '5px' }}></i> Phishing</button>
                <button className={`filter-chip chip-warn ${filter.classification === "suspicious" ? "active" : ""}`} onClick={() => setFilter({...filter, classification: "suspicious"})}><i className="fas fa-exclamation-triangle" style={{ marginRight: '5px' }}></i> Suspicious</button>
                <button className={`filter-chip chip-safe ${filter.classification === "safe" ? "active" : ""}`} onClick={() => setFilter({...filter, classification: "safe"})}><i className="fas fa-check-circle" style={{ marginRight: '5px' }}></i> Safe</button>
              </div>
            </div>
            <div className="filter-group">
              <label className="filter-label">Content type:</label>
              <div className="filter-chips">
                <button className={`filter-chip ${filter.content_type === "" ? "active" : ""}`} onClick={() => setFilter({...filter, content_type: ""})}>All</button>
                <button className={`filter-chip ${filter.content_type === "email" ? "active" : ""}`} onClick={() => setFilter({...filter, content_type: "email"})}><i className="fas fa-envelope" style={{ marginRight: '5px' }}></i> Email</button>
                <button className={`filter-chip ${filter.content_type === "sms" ? "active" : ""}`} onClick={() => setFilter({...filter, content_type: "sms"})}><i className="fas fa-mobile-alt" style={{ marginRight: '5px' }}></i> SMS</button>
                <button className={`filter-chip ${filter.content_type === "url" ? "active" : ""}`} onClick={() => setFilter({...filter, content_type: "url"})}><i className="fas fa-link" style={{ marginRight: '5px' }}></i> URL</button>
              </div>
            </div>
          </div>

          <div className="history-count">
            Showing {filteredScans.length} of {scans.length} scan{scans.length !== 1 ? "s" : ""}
          </div>

          {/* Scan Cards */}
          <div className="history-list">
            {filteredScans.map((s) => {
              const riskConfig = getRiskConfig(s.risk_level);
              const isExpanded = expandedId === s.id;
              return (
                <div key={s.id} className={`history-card card-${s.classification}`} onClick={() => setExpandedId(isExpanded ? null : s.id)}>
                  <div className="history-card-top">
                    <div className="history-card-left">
                      <span className={`classification-badge ${s.classification}`}>
                        <i className={getIcon(s.classification)} style={{ marginRight: '6px' }}></i> {s.classification.charAt(0).toUpperCase() + s.classification.slice(1)}
                      </span>
                      <span className="history-type"><i className={getTypeIcon(s.content_type)} style={{ marginRight: '6px' }}></i> {getTypeLabel(s.content_type)}</span>
                    </div>
                    <div className="history-card-right">
                      <div className="history-confidence">
                        <span className="confidence-text">{Math.round(s.confidence_score * 100)}%</span>
                        <div className="confidence-mini-bar">
                          <div className="confidence-mini-fill" style={{ width: `${s.confidence_score * 100}%`, background: getConfidenceColor(s.confidence_score) }}></div>
                        </div>
                      </div>
                      <span className="history-risk" style={{ color: riskConfig.color, background: riskConfig.bg }}>{riskConfig.label}</span>
                      <span className="history-date">{new Date(s.created_at).toLocaleString()}</span>
                    </div>
                  </div>
                  {isExpanded && (
                    <div className="history-card-detail">
                      <div className="detail-section">
                        <h4>Analysis Summary</h4>
                        <p>{s.explanation}</p>
                      </div>
                      {s.threat_indicators && s.threat_indicators.length > 0 && (
                        <div className="detail-section">
                          <h4>Threat Indicators ({s.threat_indicators.length})</h4>
                          <div className="detail-indicators">
                            {s.threat_indicators.map((ind, i) => (
                              <div key={i} className="detail-indicator">
                                <span className="detail-ind-severity" style={{ color: getRiskConfig(ind.severity).color }}>{ind.severity.toUpperCase()}</span>
                                <span className="detail-ind-cat">{ind.category}</span>
                                <span className="detail-ind-desc">{ind.description}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                      {s.content_preview && (
                        <div className="detail-section">
                          <h4>Content Preview</h4>
                          <p className="detail-preview">{s.content_preview}</p>
                        </div>
                      )}
                    </div>
                  )}
                  <div className="expand-hint">{isExpanded ? <><i className="fas fa-chevron-up" style={{ marginRight: '5px' }}></i> Click to collapse</> : <><i className="fas fa-chevron-down" style={{ marginRight: '5px' }}></i> Click to see details</>}</div>
                </div>
              );
            })}
          </div>
        </>
      )}
    </div>
  );
}

export default History;
