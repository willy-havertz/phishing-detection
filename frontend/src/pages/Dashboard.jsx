import { useState, useEffect, useCallback } from "react";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, PieChart, Pie, Cell, LineChart, Line, Legend,
} from "recharts";
import { getStats, getDailyTrends, getTopPatterns, getRecentThreats } from "../utils/scanStorage";

const COLORS = { phishing: "#EF4444", suspicious: "#F59E0B", safe: "#10B981", primary: "#ACC8A2", dark: "#1A2517" };

function Dashboard() {
  const [overview, setOverview] = useState({ total_scans: 0, phishing_count: 0, suspicious_count: 0, safe_count: 0, email_count: 0, sms_count: 0, url_count: 0 });
  const [dailyTrends, setDailyTrends] = useState([]);
  const [topPatterns, setTopPatterns] = useState([]);
  const [recentThreats, setRecentThreats] = useState([]);

  const loadData = useCallback(() => { setOverview(getStats()); setDailyTrends(getDailyTrends()); setTopPatterns(getTopPatterns()); setRecentThreats(getRecentThreats()); }, []);

  useEffect(() => { loadData(); const handleUpdate = () => loadData(); window.addEventListener("scanUpdated", handleUpdate); return () => window.removeEventListener("scanUpdated", handleUpdate); }, [loadData]);

  const pieData = [
    { name: "Phishing", value: overview.phishing_count, color: COLORS.phishing },
    { name: "Suspicious", value: overview.suspicious_count, color: COLORS.suspicious },
    { name: "Safe", value: overview.safe_count, color: COLORS.safe },
  ];

  const contentTypeData = [
    { name: "Email", value: overview.email_count, icon: "📧" },
    { name: "SMS", value: overview.sms_count, icon: "📱" },
    { name: "URL", value: overview.url_count, icon: "🔗" },
  ];

  const formatLabel = (entry) => entry.name + " " + Math.round(entry.percent * 100) + "%";

  const detectionRate = overview.total_scans > 0 ? Math.round(((overview.phishing_count + overview.suspicious_count) / overview.total_scans) * 100) : 0;

  return (
    <div className="dashboard-page">
      <div className="page-header">
        <div>
          <h1 className="page-title">📊 Threat Dashboard</h1>
          <p className="page-subtitle">A real-time overview of your scanning activity and detected threats</p>
        </div>
      </div>

      {overview.total_scans === 0 ? (
        <div className="empty-state">
          <div className="empty-icon">📭</div>
          <h3>No Scans Yet</h3>
          <p>Start by scanning some content on the <a href="/">Scanner</a> page. All your results will appear here in real-time as interactive charts and statistics.</p>
          <a href="/" className="empty-cta">🔍 Go to Scanner</a>
        </div>
      ) : (
        <>
          {/* Stats Cards */}
          <div className="stats-grid">
            <div className="stat-card stat-total">
              <div className="stat-card-inner">
                <div className="stat-icon-wrap">🛡️</div>
                <div className="stat-content">
                  <div className="stat-value">{overview.total_scans}</div>
                  <div className="stat-label">Total Scans</div>
                  <div className="stat-sub">Content analyzed so far</div>
                </div>
              </div>
            </div>
            <div className="stat-card stat-danger">
              <div className="stat-card-inner">
                <div className="stat-icon-wrap">🚨</div>
                <div className="stat-content">
                  <div className="stat-value" style={{ color: COLORS.phishing }}>{overview.phishing_count}</div>
                  <div className="stat-label">Phishing Detected</div>
                  <div className="stat-sub">Dangerous content caught</div>
                </div>
              </div>
            </div>
            <div className="stat-card stat-warn">
              <div className="stat-card-inner">
                <div className="stat-icon-wrap">⚠️</div>
                <div className="stat-content">
                  <div className="stat-value" style={{ color: COLORS.suspicious }}>{overview.suspicious_count}</div>
                  <div className="stat-label">Suspicious</div>
                  <div className="stat-sub">Needs further review</div>
                </div>
              </div>
            </div>
            <div className="stat-card stat-safe">
              <div className="stat-card-inner">
                <div className="stat-icon-wrap">✅</div>
                <div className="stat-content">
                  <div className="stat-value" style={{ color: COLORS.safe }}>{overview.safe_count}</div>
                  <div className="stat-label">Safe</div>
                  <div className="stat-sub">Clean content verified</div>
                </div>
              </div>
            </div>
          </div>

          {/* Detection Rate Banner */}
          <div className="detection-banner">
            <div className="detection-info">
              <span className="detection-label">Threat Detection Rate</span>
              <span className="detection-desc">{overview.phishing_count + overview.suspicious_count} out of {overview.total_scans} scans flagged as potentially dangerous</span>
            </div>
            <div className="detection-gauge">
              <div className="detection-bar">
                <div className="detection-fill" style={{ width: `${detectionRate}%`, background: detectionRate > 50 ? COLORS.phishing : detectionRate > 25 ? COLORS.suspicious : COLORS.safe }}></div>
              </div>
              <span className="detection-pct">{detectionRate}%</span>
            </div>
          </div>

          {/* Charts Row */}
          <div className="charts-grid">
            <div className="chart-card">
              <h3 className="chart-title">Classification Distribution</h3>
              <p className="chart-desc">Breakdown of scan results by threat level</p>
              <ResponsiveContainer width="100%" height={280}>
                <PieChart>
                  <Pie data={pieData.filter(d => d.value > 0)} cx="50%" cy="50%" outerRadius={100} innerRadius={60} dataKey="value" label={formatLabel}>
                    {pieData.filter(d => d.value > 0).map((entry, index) => (<Cell key={"cell-" + index} fill={entry.color} />))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </div>

            <div className="chart-card">
              <h3 className="chart-title">Scans by Content Type</h3>
              <p className="chart-desc">What types of content you&apos;ve been checking</p>
              <ResponsiveContainer width="100%" height={280}>
                <BarChart data={contentTypeData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#E5E7E5" />
                  <XAxis dataKey="name" />
                  <YAxis />
                  <Tooltip />
                  <Bar dataKey="value" fill={COLORS.primary} radius={[6, 6, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Trends */}
          <div className="chart-card" style={{ marginBottom: "1.5rem" }}>
            <h3 className="chart-title">Daily Scan Trends</h3>
            <p className="chart-desc">Your scanning activity over the last 7 days</p>
            <ResponsiveContainer width="100%" height={320}>
              <LineChart data={dailyTrends}>
                <CartesianGrid strokeDasharray="3 3" stroke="#E5E7E5" />
                <XAxis dataKey="date" tickFormatter={(v) => { const d = new Date(v); return d.toLocaleDateString("en-US", { month: "short", day: "numeric" }); }} />
                <YAxis />
                <Tooltip labelFormatter={(v) => new Date(v).toLocaleDateString()} />
                <Legend />
                <Line type="monotone" dataKey="total" stroke={COLORS.dark} strokeWidth={2} name="Total" />
                <Line type="monotone" dataKey="phishing" stroke={COLORS.phishing} strokeWidth={2} name="Phishing" />
                <Line type="monotone" dataKey="suspicious" stroke={COLORS.suspicious} strokeWidth={2} name="Suspicious" />
                <Line type="monotone" dataKey="safe" stroke={COLORS.safe} strokeWidth={2} name="Safe" />
              </LineChart>
            </ResponsiveContainer>
          </div>

          {/* Bottom Row */}
          <div className="charts-grid">
            <div className="chart-card">
              <h3 className="chart-title">🚨 Recent Threats</h3>
              <p className="chart-desc">Latest phishing and suspicious content detected</p>
              {recentThreats.length === 0 ? (
                <div className="chart-empty"><p>No threats detected yet. Keep scanning to stay protected!</p></div>
              ) : (
                <div className="threats-list">
                  {recentThreats.map((threat, i) => (
                    <div key={i} className={`threat-item threat-${threat.classification}`}>
                      <div className="threat-top">
                        <span className={"classification-badge " + threat.classification}>{threat.classification === "phishing" ? "🚨" : "⚠️"} {threat.classification}</span>
                        <span className="threat-date">{new Date(threat.created_at).toLocaleString()}</span>
                      </div>
                      <p className="threat-explain">{threat.explanation}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="chart-card">
              <h3 className="chart-title">📈 Top Threat Patterns</h3>
              <p className="chart-desc">Most frequently detected phishing tactics</p>
              {topPatterns.length === 0 ? (
                <div className="chart-empty"><p>Patterns will appear after scanning phishing content.</p></div>
              ) : (
                <div className="patterns-list">
                  {topPatterns.map((p, i) => (
                    <div key={i} className="pattern-item">
                      <div className="pattern-info">
                        <span className="pattern-name">{p.pattern_text}</span>
                        <span className="pattern-cat">{p.pattern_category}</span>
                      </div>
                      <span className="pattern-count">{p.occurrence_count}</span>
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
