import { useState, useEffect, useCallback } from "react";
import { getScanHistory, clearHistory } from "../utils/scanStorage";

function History() {
  const [scans, setScans] = useState([]);
  const [filter, setFilter] = useState({
    classification: "",
    content_type: "",
  });

  const loadScans = useCallback(() => {
    setScans(getScanHistory());
  }, []);

  useEffect(() => {
    loadScans();

    // Listen for real-time updates
    const handleUpdate = () => loadScans();
    window.addEventListener("scanUpdated", handleUpdate);

    return () => window.removeEventListener("scanUpdated", handleUpdate);
  }, [loadScans]);

  const handleClearHistory = () => {
    if (window.confirm("Are you sure you want to clear all scan history?")) {
      clearHistory();
      setScans([]);
    }
  };

  const filteredScans = scans.filter((s) => {
    if (filter.classification && s.classification !== filter.classification)
      return false;
    if (filter.content_type && s.content_type !== filter.content_type)
      return false;
    return true;
  });

  const getEmoji = (c) => {
    if (c === "safe") return "✅";
    if (c === "suspicious") return "⚠️";
    return "🚨";
  };

  const getTypeEmoji = (t) => {
    if (t === "email") return "📧";
    if (t === "sms") return "📱";
    return "🔗";
  };

  const getRiskStyle = (risk) => {
    const styles = {
      critical: { background: "#FEE2E2", color: "#DC2626" },
      high: { background: "#FEF3C7", color: "#D97706" },
      medium: { background: "#FEF9C3", color: "#CA8A04" },
      low: { background: "#D1FAE5", color: "#059669" },
    };
    return styles[risk] || styles.low;
  };

  const getConfidenceColor = (score) => {
    if (score < 0.3) return "#10B981";
    if (score < 0.6) return "#F59E0B";
    return "#EF4444";
  };

  return (
    <div>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: "0.5rem",
        }}
      >
        <h1>📋 Scan History</h1>
        {scans.length > 0 && (
          <button
            onClick={handleClearHistory}
            style={{
              padding: "0.5rem 1rem",
              border: "2px solid #EF4444",
              borderRadius: "8px",
              background: "white",
              color: "#EF4444",
              cursor: "pointer",
              fontWeight: 500,
            }}
          >
            🗑️ Clear History
          </button>
        )}
      </div>
      <p
        style={{ color: "#6B736B", marginBottom: "1.5rem", fontSize: "0.9rem" }}
      >
        Real-time history of all your scanned content
      </p>

      {scans.length === 0 ? (
        <div
          className="chart-section"
          style={{ textAlign: "center", padding: "3rem" }}
        >
          <div style={{ fontSize: "3rem", marginBottom: "1rem" }}>📭</div>
          <h3 style={{ marginBottom: "0.5rem" }}>No Scan History Yet</h3>
          <p style={{ color: "#6B736B" }}>
            Go to the{" "}
            <a href="/" style={{ color: "#1A2517", fontWeight: 600 }}>
              Scanner
            </a>{" "}
            page to analyze emails, SMS messages, or URLs.
            <br />
            All your scan results will be saved here automatically.
          </p>
        </div>
      ) : (
        <>
          <div className="chart-section" style={{ marginBottom: "1.5rem" }}>
            <div style={{ display: "flex", gap: "1rem", flexWrap: "wrap" }}>
              <div>
                <label
                  style={{
                    display: "block",
                    fontSize: "0.875rem",
                    marginBottom: "0.25rem",
                    color: "#6B736B",
                  }}
                >
                  Classification
                </label>
                <select
                  value={filter.classification}
                  onChange={(e) =>
                    setFilter({ ...filter, classification: e.target.value })
                  }
                  style={{
                    padding: "0.5rem 1rem",
                    border: "2px solid #E5E7E5",
                    borderRadius: "8px",
                    background: "white",
                    minWidth: "150px",
                  }}
                >
                  <option value="">All</option>
                  <option value="phishing">🚨 Phishing</option>
                  <option value="suspicious">⚠️ Suspicious</option>
                  <option value="safe">✅ Safe</option>
                </select>
              </div>
              <div>
                <label
                  style={{
                    display: "block",
                    fontSize: "0.875rem",
                    marginBottom: "0.25rem",
                    color: "#6B736B",
                  }}
                >
                  Content Type
                </label>
                <select
                  value={filter.content_type}
                  onChange={(e) =>
                    setFilter({ ...filter, content_type: e.target.value })
                  }
                  style={{
                    padding: "0.5rem 1rem",
                    border: "2px solid #E5E7E5",
                    borderRadius: "8px",
                    background: "white",
                    minWidth: "150px",
                  }}
                >
                  <option value="">All</option>
                  <option value="email">📧 Email</option>
                  <option value="sms">📱 SMS</option>
                  <option value="url">🔗 URL</option>
                </select>
              </div>
              <div style={{ display: "flex", alignItems: "flex-end" }}>
                <button
                  onClick={() =>
                    setFilter({ classification: "", content_type: "" })
                  }
                  style={{
                    padding: "0.5rem 1rem",
                    border: "2px solid #E5E7E5",
                    borderRadius: "8px",
                    background: "white",
                    cursor: "pointer",
                  }}
                >
                  Clear Filters
                </button>
              </div>
            </div>
          </div>

          <div className="chart-section">
            <div style={{ overflowX: "auto" }}>
              <table className="history-table">
                <thead>
                  <tr>
                    <th>Type</th>
                    <th>Classification</th>
                    <th>Confidence</th>
                    <th>Risk</th>
                    <th>Explanation</th>
                    <th>Date</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredScans.map((s) => (
                    <tr key={s.id}>
                      <td>
                        {getTypeEmoji(s.content_type)} {s.content_type}
                      </td>
                      <td>
                        <span
                          className={"classification-badge " + s.classification}
                        >
                          {getEmoji(s.classification)} {s.classification}
                        </span>
                      </td>
                      <td>
                        <div
                          style={{
                            display: "flex",
                            alignItems: "center",
                            gap: "0.5rem",
                          }}
                        >
                          <div
                            style={{
                              width: "60px",
                              height: "8px",
                              background: "#E5E7E5",
                              borderRadius: "4px",
                              overflow: "hidden",
                            }}
                          >
                            <div
                              style={{
                                width: s.confidence_score * 100 + "%",
                                height: "100%",
                                borderRadius: "4px",
                                background: getConfidenceColor(
                                  s.confidence_score,
                                ),
                              }}
                            />
                          </div>
                          <span style={{ fontSize: "0.875rem" }}>
                            {Math.round(s.confidence_score * 100)}%
                          </span>
                        </div>
                      </td>
                      <td>
                        <span
                          style={{
                            padding: "0.25rem 0.5rem",
                            borderRadius: "4px",
                            fontSize: "0.75rem",
                            fontWeight: 500,
                            ...getRiskStyle(s.risk_level),
                          }}
                        >
                          {s.risk_level.toUpperCase()}
                        </span>
                      </td>
                      <td
                        style={{
                          maxWidth: "250px",
                          fontSize: "0.875rem",
                          color: "#6B736B",
                        }}
                      >
                        {s.explanation}
                      </td>
                      <td
                        style={{ whiteSpace: "nowrap", fontSize: "0.875rem" }}
                      >
                        {new Date(s.created_at).toLocaleString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div
              style={{
                marginTop: "1rem",
                color: "#6B736B",
                fontSize: "0.875rem",
                textAlign: "center",
              }}
            >
              Showing {filteredScans.length} of {scans.length} records
            </div>
          </div>
        </>
      )}
    </div>
  );
}

export default History;
