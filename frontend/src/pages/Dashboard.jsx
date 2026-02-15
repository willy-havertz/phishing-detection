import { useState, useEffect, useCallback } from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  LineChart,
  Line,
  Legend,
} from "recharts";
import {
  getStats,
  getDailyTrends,
  getTopPatterns,
  getRecentThreats,
} from "../utils/scanStorage";

const COLORS = {
  phishing: "#EF4444",
  suspicious: "#F59E0B",
  safe: "#10B981",
  primary: "#ACC8A2",
  dark: "#1A2517",
};

function Dashboard() {
  const [overview, setOverview] = useState({
    total_scans: 0,
    phishing_count: 0,
    suspicious_count: 0,
    safe_count: 0,
    email_count: 0,
    sms_count: 0,
    url_count: 0,
  });
  const [dailyTrends, setDailyTrends] = useState([]);
  const [topPatterns, setTopPatterns] = useState([]);
  const [recentThreats, setRecentThreats] = useState([]);

  const loadData = useCallback(() => {
    setOverview(getStats());
    setDailyTrends(getDailyTrends());
    setTopPatterns(getTopPatterns());
    setRecentThreats(getRecentThreats());
  }, []);

  useEffect(() => {
    loadData();

    // Listen for real-time updates
    const handleUpdate = () => loadData();
    window.addEventListener("scanUpdated", handleUpdate);

    return () => window.removeEventListener("scanUpdated", handleUpdate);
  }, [loadData]);

  const pieData = [
    {
      name: "Phishing",
      value: overview.phishing_count,
      color: COLORS.phishing,
    },
    {
      name: "Suspicious",
      value: overview.suspicious_count,
      color: COLORS.suspicious,
    },
    { name: "Safe", value: overview.safe_count, color: COLORS.safe },
  ];

  const contentTypeData = [
    { name: "Email", value: overview.email_count },
    { name: "SMS", value: overview.sms_count },
    { name: "URL", value: overview.url_count },
  ];

  const formatLabel = (entry) => {
    return entry.name + " " + Math.round(entry.percent * 100) + "%";
  };

  return (
    <div>
      <h1 style={{ marginBottom: "0.5rem" }}>📊 Threat Dashboard</h1>
      <p
        style={{ color: "#6B736B", marginBottom: "1.5rem", fontSize: "0.9rem" }}
      >
        Real-time statistics from your phishing scans
      </p>

      {overview.total_scans === 0 ? (
        <div
          className="chart-section"
          style={{ textAlign: "center", padding: "3rem" }}
        >
          <div style={{ fontSize: "3rem", marginBottom: "1rem" }}>📭</div>
          <h3 style={{ marginBottom: "0.5rem" }}>No Scans Yet</h3>
          <p style={{ color: "#6B736B" }}>
            Go to the{" "}
            <a href="/" style={{ color: COLORS.dark, fontWeight: 600 }}>
              Scanner
            </a>{" "}
            page to analyze emails, SMS messages, or URLs.
            <br />
            All your scan results will appear here in real-time.
          </p>
        </div>
      ) : (
        <>
          <div className="dashboard-grid">
            <div className="stat-card highlight">
              <div className="stat-icon">🛡️</div>
              <div className="stat-value">{overview.total_scans}</div>
              <div className="stat-label">Total Scans</div>
            </div>

            <div className="stat-card">
              <div className="stat-icon">🚨</div>
              <div className="stat-value" style={{ color: COLORS.phishing }}>
                {overview.phishing_count}
              </div>
              <div className="stat-label">Phishing Detected</div>
            </div>

            <div className="stat-card">
              <div className="stat-icon">⚠️</div>
              <div className="stat-value" style={{ color: COLORS.suspicious }}>
                {overview.suspicious_count}
              </div>
              <div className="stat-label">Suspicious</div>
            </div>

            <div className="stat-card">
              <div className="stat-icon">✅</div>
              <div className="stat-value" style={{ color: COLORS.safe }}>
                {overview.safe_count}
              </div>
              <div className="stat-label">Safe</div>
            </div>
          </div>

          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(400px, 1fr))",
              gap: "1.5rem",
            }}
          >
            <div className="chart-section">
              <h3 className="chart-title">Classification Distribution</h3>
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={pieData.filter((d) => d.value > 0)}
                    cx="50%"
                    cy="50%"
                    outerRadius={100}
                    innerRadius={60}
                    dataKey="value"
                    label={formatLabel}
                  >
                    {pieData
                      .filter((d) => d.value > 0)
                      .map((entry, index) => (
                        <Cell key={"cell-" + index} fill={entry.color} />
                      ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </div>

            <div className="chart-section">
              <h3 className="chart-title">Scans by Content Type</h3>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={contentTypeData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="name" />
                  <YAxis />
                  <Tooltip />
                  <Bar
                    dataKey="value"
                    fill={COLORS.primary}
                    radius={[4, 4, 0, 0]}
                  />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="chart-section" style={{ marginTop: "1.5rem" }}>
            <h3 className="chart-title">Daily Scan Trends (Last 7 Days)</h3>
            <ResponsiveContainer width="100%" height={350}>
              <LineChart data={dailyTrends}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis
                  dataKey="date"
                  tickFormatter={(v) => {
                    const d = new Date(v);
                    return d.toLocaleDateString("en-US", {
                      month: "short",
                      day: "numeric",
                    });
                  }}
                />
                <YAxis />
                <Tooltip
                  labelFormatter={(v) => new Date(v).toLocaleDateString()}
                />
                <Legend />
                <Line
                  type="monotone"
                  dataKey="total"
                  stroke={COLORS.dark}
                  strokeWidth={2}
                  name="Total"
                />
                <Line
                  type="monotone"
                  dataKey="phishing"
                  stroke={COLORS.phishing}
                  strokeWidth={2}
                  name="Phishing"
                />
                <Line
                  type="monotone"
                  dataKey="suspicious"
                  stroke={COLORS.suspicious}
                  strokeWidth={2}
                  name="Suspicious"
                />
                <Line
                  type="monotone"
                  dataKey="safe"
                  stroke={COLORS.safe}
                  strokeWidth={2}
                  name="Safe"
                />
              </LineChart>
            </ResponsiveContainer>
          </div>

          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(400px, 1fr))",
              gap: "1.5rem",
              marginTop: "1.5rem",
            }}
          >
            <div className="chart-section">
              <h3 className="chart-title">🚨 Recent Threats</h3>
              {recentThreats.length === 0 ? (
                <p
                  style={{
                    color: "#6B736B",
                    textAlign: "center",
                    padding: "2rem",
                  }}
                >
                  No threats detected yet. Keep scanning to stay protected!
                </p>
              ) : (
                <div
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    gap: "0.75rem",
                  }}
                >
                  {recentThreats.map((threat, i) => (
                    <div
                      key={i}
                      style={{
                        padding: "0.75rem",
                        background: "#F9FAF9",
                        borderRadius: "8px",
                        borderLeft:
                          "4px solid " +
                          (threat.classification === "phishing"
                            ? COLORS.phishing
                            : COLORS.suspicious),
                      }}
                    >
                      <div
                        style={{
                          display: "flex",
                          justifyContent: "space-between",
                          alignItems: "center",
                        }}
                      >
                        <span
                          className={
                            "classification-badge " + threat.classification
                          }
                        >
                          {threat.classification}
                        </span>
                        <span style={{ fontSize: "0.75rem", color: "#9CA39C" }}>
                          {new Date(threat.created_at).toLocaleString()}
                        </span>
                      </div>
                      <p
                        style={{
                          fontSize: "0.875rem",
                          marginTop: "0.5rem",
                          color: "#6B736B",
                        }}
                      >
                        {threat.explanation}
                      </p>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="chart-section">
              <h3 className="chart-title">📈 Top Threat Patterns</h3>
              {topPatterns.length === 0 ? (
                <p
                  style={{
                    color: "#6B736B",
                    textAlign: "center",
                    padding: "2rem",
                  }}
                >
                  Patterns will appear here after scanning phishing content.
                </p>
              ) : (
                <div
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    gap: "0.5rem",
                  }}
                >
                  {topPatterns.map((p, i) => (
                    <div
                      key={i}
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                        padding: "0.75rem",
                        background: i % 2 === 0 ? "#F9FAF9" : "white",
                        borderRadius: "6px",
                      }}
                    >
                      <div>
                        <span style={{ fontWeight: 500 }}>
                          {p.pattern_text}
                        </span>
                        <span
                          style={{
                            marginLeft: "0.5rem",
                            fontSize: "0.75rem",
                            color: "#9CA39C",
                            background: "#E5E7E5",
                            padding: "0.125rem 0.5rem",
                            borderRadius: "4px",
                          }}
                        >
                          {p.pattern_category}
                        </span>
                      </div>
                      <span
                        style={{
                          background: COLORS.primary,
                          color: COLORS.dark,
                          padding: "0.25rem 0.75rem",
                          borderRadius: "12px",
                          fontWeight: 600,
                          fontSize: "0.875rem",
                        }}
                      >
                        {p.occurrence_count}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}

export default Dashboard;
