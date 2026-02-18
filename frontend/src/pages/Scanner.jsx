import { useState, useRef, useEffect } from "react";
import { saveScan } from "../utils/scanStorage";
import { sanitizeInput, createRateLimiter } from "../utils/security";

const API_URL = import.meta.env.VITE_API_URL || "/api";
const MAX_CONTENT_LENGTH = 50000;
const checkRateLimit = createRateLimiter(10, 60000);

function Scanner() {
  const [content, setContent] = useState("");
  const [contentType, setContentType] = useState("email");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [showTechnical, setShowTechnical] = useState(false);
  const abortControllerRef = useRef(null);
  const resultRef = useRef(null);

  const [lastScannedContent, setLastScannedContent] = useState("");
  const [contentChanged, setContentChanged] = useState(false);

  useEffect(() => {
    if (lastScannedContent && content !== lastScannedContent && result) {
      setContentChanged(true);
    } else {
      setContentChanged(false);
    }
  }, [content, lastScannedContent, result]);

  const handleContentChange = (e) => {
    const value = e.target.value;
    if (value.length <= MAX_CONTENT_LENGTH) setContent(value);
  };

  const handleScan = async () => {
    const trimmedContent = content.trim();
    if (!trimmedContent) { setError("Please enter content to scan"); return; }
    if (!checkRateLimit()) { setError("Too many requests. Please wait a moment."); return; }
    if (abortControllerRef.current) abortControllerRef.current.abort();
    abortControllerRef.current = new AbortController();

    setLoading(true); setError(null); setResult(null);
    try {
      const sanitizedContent = sanitizeInput(trimmedContent);
      const response = await fetch(`${API_URL}/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({ content: sanitizedContent, content_type: contentType }),
        signal: abortControllerRef.current.signal,
      });
      if (response.status === 429) throw new Error("Rate limit exceeded. Please wait.");
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.detail || "Scan failed. Please try again.");
      }
      const data = await response.json();
      setResult(data);
      setLastScannedContent(sanitizedContent);
      setContentChanged(false);
      saveScan({
        content_type: contentType,
        content_preview: sanitizedContent.substring(0, 100),
        classification: data.classification,
        confidence_score: data.confidence_score,
        risk_level: data.risk_level,
        explanation: data.explanation,
        threat_indicators: data.threat_indicators,
      });
      setTimeout(() => resultRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }), 100);
    } catch (err) {
      if (err.name === "AbortError") return;
      setError(err.message || "Analysis failed. Make sure the backend is running.");
    } finally { setLoading(false); }
  };

  const getResultConfig = (classification) => {
    switch (classification) {
      case "safe": return { 
        icon: "fas fa-check-circle", 
        icon_action: "fas fa-info-circle",
        title: "Looks Safe", 
        color: "var(--success)", 
        bg: "var(--success-light)", 
        border: "var(--theme-border)", 
        message: "No significant threats detected. This content appears legitimate.", 
        action: "You can proceed with confidence, but always stay vigilant." 
      };
      case "suspicious": return { 
        icon: "fas fa-exclamation-triangle", 
        icon_action: "fas fa-exclamation-circle",
        title: "Potentially Suspicious", 
        color: "var(--warning)", 
        bg: "var(--warning-light)", 
        border: "var(--theme-border)", 
        message: "Some warning signs were detected. This content may not be safe.", 
        action: "Proceed with caution. Verify the sender before taking any action." 
      };
      case "phishing": return { 
        icon: "fas fa-shield-virus", 
        icon_action: "fas fa-exclamation-circle",
        title: "Phishing Detected!", 
        color: "var(--danger)", 
        bg: "var(--danger-light)", 
        border: "var(--theme-border)", 
        message: "This content shows strong signs of being a phishing attempt!", 
        action: "Do NOT click any links, share personal info, or respond to this message." 
      };
      default: return { 
        icon: "fas fa-question-circle", 
        icon_action: "fas fa-info-circle",
        title: "Unknown", 
        color: "var(--theme-text-tertiary)", 
        bg: "var(--theme-bg-tertiary)", 
        border: "var(--theme-border)", 
        message: "", 
        action: "" 
      };
    }
  };

  const getSeverityLabel = (severity) => {
    switch (severity) {
      case "critical": return { label: "CRITICAL", color: "#DC2626", bg: "#FEE2E2" };
      case "high": return { label: "HIGH RISK", color: "#EA580C", bg: "#FFF7ED" };
      case "medium": return { label: "MEDIUM", color: "#D97706", bg: "#FFFBEB" };
      case "low": return { label: "LOW", color: "#6B7280", bg: "#F3F4F6" };
      default: return { label: severity, color: "#6B7280", bg: "#F3F4F6" };
    }
  };

  const placeholders = {
    email: "Paste the email content you want to check here...\n\nFor example, paste that suspicious email from your \"bank\" asking you to verify your account.",
    sms: "Paste the SMS message here...\n\nFor example, that text saying your M-Pesa has been suspended.",
    url: "Paste the URL (web link) you want to check...\n\nExample: http://suspicious-site.xyz/login",
  };

  const confidencePercent = result ? Math.round(result.confidence_score * 100) : 0;

  return (
    <div className="scanner-page">
      <div className="scanner-hero">
        <h1 className="scanner-hero-title">Stop. Think. Analyze.</h1>
        <p className="scanner-hero-subtitle">Phishing protection at your fingertips. Our AI unmasks threats in emails, SMS, and URLs instantly. Don&apos;t let scammers rush your decisions.</p>
      </div>

      <section className="scanner-card">
        <div className="step-header">
          <span className="step-number">1</span>
          <div>
            <h2 className="step-title">What do you want to check?</h2>
            <p className="step-desc">Select the type of content you received</p>
          </div>
        </div>
        <div className="content-type-selector">
          {[
            { key: "email", icon: "fas fa-envelope", label: "Email", desc: "Check if an email is phishing" },
            { key: "sms", icon: "fas fa-mobile-alt", label: "SMS / Text", desc: "Verify if a text message is a scam" },
            { key: "url", icon: "fas fa-link", label: "Website Link", desc: "Analyze a web link for threats" },
          ].map((type) => (
            <button key={type.key} className={`type-card ${contentType === type.key ? "active" : ""}`} onClick={() => setContentType(type.key)}>
              <i className={`type-icon ${type.icon}`}></i>
              <span className="type-label">{type.label}</span>
              <span className="type-desc">{type.desc}</span>
            </button>
          ))}
        </div>
      </section>

      <section className="scanner-card">
        <div className="step-header">
          <span className="step-number">2</span>
          <div>
            <h2 className="step-title">Paste the content</h2>
            <p className="step-desc">Copy and paste the {contentType === "url" ? "link" : contentType} you want to check</p>
          </div>
        </div>
        <div className="input-wrapper">
          <textarea className={`scan-input ${contentChanged ? "input-modified" : ""}`} placeholder={placeholders[contentType]} value={content} onChange={handleContentChange} maxLength={MAX_CONTENT_LENGTH} />
          {contentChanged && <div className="change-badge" onClick={handleScan}><i className="fas fa-pencil-alt"></i> Content changed — Click to re-scan</div>}
        </div>
        <div className="input-footer">
          <span className="char-count">{content.length.toLocaleString()} / {MAX_CONTENT_LENGTH.toLocaleString()} characters</span>
        </div>
        {error && <div className="error-banner"><i className="fas fa-exclamation-triangle error-icon"></i><span>{error}</span></div>}
        <button className="scan-btn" onClick={handleScan} disabled={loading || !content.trim()}>
          {loading ? (<><span className="spinner" style={{ width: 20, height: 20, borderWidth: 2 }}></span>Analyzing...</>) : (<><i className="fas fa-search"></i> Analyze Now</>)}
        </button>
        {loading && <div className="loading-info"><div className="loading-dots"><span></span><span></span><span></span></div><p>Our AI is checking for phishing patterns, suspicious links, and known scam tactics...</p></div>}
      </section>

      {result && (
        <div ref={resultRef}>
          {(() => {
            const config = getResultConfig(result.classification);
            return (<>
              <section className="result-verdict" style={{ background: config.bg, borderColor: config.border }}>
                <div className="verdict-main">
                  <i className={`verdict-icon ${config.icon}`} style={{ color: config.color }}></i>
                  <div className="verdict-text">
                    <h2 className="verdict-title" style={{ color: config.color }}>{config.title}</h2>
                    <p className="verdict-message">{config.message}</p>
                  </div>
                </div>
                <div className="verdict-action" style={{ borderColor: config.border }}>
                  <strong>What should you do?</strong> {config.action}
                </div>
                <div className="threat-gauge-wrapper">
                  <div className="threat-gauge-labels"><span>Safe</span><span>Suspicious</span><span>Dangerous</span></div>
                  <div className="threat-gauge">
                    <div className="threat-gauge-track">
                      <div className="threat-gauge-safe"></div>
                      <div className="threat-gauge-warn"></div>
                      <div className="threat-gauge-danger"></div>
                    </div>
                    <div className="threat-gauge-needle" style={{ left: `${Math.min(confidencePercent, 100)}%` }}>
                      <div className="needle-dot"></div>
                      <div className="needle-label">{confidencePercent}%</div>
                    </div>
                  </div>
                  <p className="gauge-explain">
                    Threat Score: {confidencePercent}% — {confidencePercent < 20 ? "Very low risk" : confidencePercent < 40 ? "Low risk" : confidencePercent < 60 ? "Moderate risk" : confidencePercent < 80 ? "High risk" : "Very high risk — dangerous!"}
                  </p>
                </div>
              </section>

              {result.threat_indicators && result.threat_indicators.length > 0 && (
                <section className="scanner-card findings-card">
                  <h3 className="findings-title">
                    <i className="fas fa-microscope" style={{ marginRight: '10px', color: 'var(--primary)' }}></i> 
                    Analysis Findings 
                    <span className="findings-count">{result.threat_indicators.length} issue{result.threat_indicators.length !== 1 ? "s" : ""}</span>
                  </h3>
                  <p className="findings-subtitle">Here are the specific warning signs detected in your content:</p>
                  <div className="findings-list">
                    {result.threat_indicators.map((indicator, index) => {
                      const sev = getSeverityLabel(indicator.severity);
                      return (
                        <div key={index} className={`finding-item severity-${indicator.severity}`}>
                          <div className="finding-header">
                            <span className="finding-severity" style={{ color: sev.color, background: sev.bg }}>{sev.label}</span>
                            <span className="finding-category">{indicator.category}</span>
                          </div>
                          <p className="finding-description">{indicator.description}</p>
                          {indicator.matched_text && <div className="finding-evidence"><span className="evidence-label">Evidence:</span><code className="evidence-text">&quot;{indicator.matched_text}&quot;</code></div>}
                        </div>
                      );
                    })}
                  </div>
                </section>
              )}

              {(!result.threat_indicators || result.threat_indicators.length === 0) && result.classification === "safe" && (
                <section className="scanner-card safe-card">
                  <div className="safe-icon"><i className="fas fa-check-double"></i></div>
                  <h3>No Threats Found</h3>
                  <p>We checked against our database of known phishing patterns, suspicious links, and scam tactics. No warning signs were detected.</p>
                  <p className="safe-reminder"><i className="fas fa-lightbulb" style={{ color: 'var(--warning)', marginRight: '6px' }}></i> <strong>Remember:</strong> Always be cautious with unsolicited messages. If something feels off, trust your instincts.</p>
                </section>
              )}

              {result.recommendations && result.recommendations.length > 0 && (
                <section className="scanner-card">
                  <h3 className="rec-title"><i className="fas fa-clipboard-list" style={{ marginRight: '10px', color: 'var(--primary)' }}></i> What To Do Next</h3>
                  <div className="rec-list">
                    {result.recommendations.map((rec, index) => (
                      <div key={index} className="rec-item"><span className="rec-number">{index + 1}</span><span className="rec-text">{rec}</span></div>
                    ))}
                  </div>
                </section>
              )}

              <section className="scanner-card technical-section">
                <button className="technical-toggle" onClick={() => setShowTechnical(!showTechnical)}>
                  <span><i className="fas fa-microchip" style={{ marginRight: '8px' }}></i> Technical Analysis</span>
                  <span className="toggle-hint">{showTechnical ? "Hide" : "Show"} how our AI analyzed this</span>
                  <i className={`fas fa-chevron-down toggle-arrow ${showTechnical ? "open" : ""}`}></i>
                </button>
                {showTechnical && (
                  <div className="technical-content">
                    {result.analysis_details && (
                      <div className="tech-block">
                        <h4><i className="fas fa-balance-scale" style={{ marginRight: '8px', color: 'var(--primary)' }}></i> Detection Methodology</h4>
                        <p className="tech-explain">We combine pattern matching with real-time AI inference:</p>
                        <div className="score-breakdown">
                          <div className="score-row">
                            <div className="score-info">
                              <span className="score-label">Pattern Matching</span>
                              <span className="score-desc">Checks against 200+ known phishing patterns</span>
                            </div>
                            <div className="score-bar-wrapper">
                              <div className="score-bar">
                                <div className="score-bar-fill heuristic" style={{ width: `${Math.round((result.analysis_details.heuristic_score || 0) * 100)}%` }} />
                              </div>
                              <span className="score-pct">{Math.round((result.analysis_details.heuristic_score || 0) * 100)}%</span>
                            </div>
                          </div>
                          <div className="score-row">
                            <div className="score-info">
                              <span className="score-label">Machine Learning</span>
                              <span className="score-desc">AI trained on thousands of real phishing samples</span>
                            </div>
                            <div className="score-bar-wrapper">
                              <div className="score-bar">
                                <div className="score-bar-fill ml" style={{ width: `${Math.round((result.analysis_details.ml_score || 0) * 100)}%` }} />
                              </div>
                              <span className="score-pct">{Math.round((result.analysis_details.ml_score || 0) * 100)}%</span>
                            </div>
                          </div>
                          <div className="score-row combined-row">
                            <div className="score-info">
                              <span className="score-label">Final Threat Score</span>
                              <span className="score-desc">Weighted confidence level</span>
                            </div>
                            <div className="score-bar-wrapper">
                              <div className="score-bar">
                                <div className="score-bar-fill combined" style={{ width: `${Math.round((result.analysis_details.combined_score || 0) * 100)}%` }} />
                              </div>
                              <span className="score-pct">{Math.round((result.analysis_details.combined_score || 0) * 100)}%</span>
                            </div>
                          </div>
                        </div>
                      </div>
                    )}
                    {result.ml_features && (<>
                      <div className="tech-block">
                        <h4><i className="fas fa-brain" style={{ marginRight: '8px', color: 'var(--primary)' }}></i> AI Model Insights</h4>
                        <div className="tech-stats">
                          <div className="tech-stat"><span className="tech-stat-label">Model Engine</span><span className="tech-stat-value">{result.ml_features.model_used}</span></div>
                          <div className="tech-stat"><span className="tech-stat-label">AI Consensus</span><span className="tech-stat-value">{Math.round(result.ml_features.ml_phishing_probability * 100)}% phishing</span></div>
                          <div className="tech-stat"><span className="tech-stat-label">Features analyzed</span><span className="tech-stat-value">{result.analysis_details?.features_extracted || 0} signals</span></div>
                        </div>
                      </div>
                      {result.ml_features.ssl_status && (
                        <div className="tech-block">
                          <h4><i className="fas fa-shield-alt" style={{ marginRight: '8px', color: 'var(--primary)' }}></i> Site Infrastructure</h4>
                          <div className="tech-stats">
                            <div className="tech-stat">
                              <span className="tech-stat-label">Security Protocol</span>
                              <span className={`tech-stat-value ${result.ml_features.ssl_status.ssl_valid ? "text-safe" : "text-danger"}`}>
                                {result.ml_features.ssl_status.ssl_valid ? <><i className="fas fa-check-circle" style={{ marginRight: '5px' }}></i> SSL Secured</> : result.ml_features.ssl_status.has_ssl ? <><i className="fas fa-exclamation-triangle" style={{ marginRight: '5px' }}></i> SSL invalid</> : <><i className="fas fa-times-circle" style={{ marginRight: '5px' }}></i> No Encryption</>}
                              </span>
                            </div>
                            {result.ml_features.ssl_status.ssl_issuer && <div className="tech-stat"><span className="tech-stat-label">Cert Authority</span><span className="tech-stat-value">{result.ml_features.ssl_status.ssl_issuer}</span></div>}
                            {result.ml_features.ssl_status.ssl_expiry_days !== null && <div className="tech-stat"><span className="tech-stat-label">Days to Expiry</span><span className="tech-stat-value">{result.ml_features.ssl_status.ssl_expiry_days}d</span></div>}
                          </div>
                        </div>
                      )}
                      {result.ml_features.domain_age && result.ml_features.domain_age.domain_age_days !== null && (
                        <div className="tech-block">
                          <h4><i className="fas fa-calendar-alt" style={{ marginRight: '8px', color: 'var(--primary)' }}></i> Website Longevity</h4>
                          <div className="tech-stats">
                            <div className="tech-stat"><span className="tech-stat-label">Domain Age</span><span className={`tech-stat-value ${result.ml_features.domain_age.domain_age_days > 365 ? "text-safe" : "text-danger"}`}>{result.ml_features.domain_age.domain_age_days > 365 ? `${Math.floor(result.ml_features.domain_age.domain_age_days / 365)}y (Established)` : <><i className="fas fa-exclamation-triangle" style={{ marginRight: '5px' }}></i> {result.ml_features.domain_age.domain_age_days}d (Newly registered)</>}</span></div>
                          </div>
                        </div>
                      )}
                      {result.ml_features.top_ml_features && result.ml_features.top_ml_features.length > 0 && (
                        <div className="tech-block">
                          <h4><i className="fas fa-chart-line" style={{ marginRight: '8px', color: 'var(--primary)' }}></i> High Significance Signals</h4>
                          <div className="feature-bars">{result.ml_features.top_ml_features.map((feat, i) => (<div key={i} className="feature-bar-item"><span className="feature-name">{feat.feature.replace(/_/g, " ")}</span><div className="feature-bar-bg"><div className="feature-bar-fill" style={{ width: `${Math.min(feat.importance * 500, 100)}%` }} /></div><span className="feature-value">{(feat.importance * 100).toFixed(1)}%</span></div>))}</div>
                        </div>
                      )}
                      {result.ml_features.lexical_features && (
                        <details className="raw-features"><summary><i className="fas fa-spell-check" style={{ marginRight: '5px' }}></i> Lexical Features ({Object.keys(result.ml_features.lexical_features).length})</summary><div className="features-table">{Object.entries(result.ml_features.lexical_features).map(([key, value]) => (<div key={key} className="feature-row"><span className="feature-key">{key.replace(/_/g, " ")}</span><span className="feature-val">{typeof value === "number" ? value.toFixed(4) : String(value)}</span></div>))}</div></details>
                      )}
                      {result.ml_features.text_features && (
                        <details className="raw-features"><summary><i className="fas fa-align-left" style={{ marginRight: '5px' }}></i> Semantic Features ({Object.keys(result.ml_features.text_features).length})</summary><div className="features-table">{Object.entries(result.ml_features.text_features).map(([key, value]) => (<div key={key} className="feature-row"><span className="feature-key">{key.replace(/_/g, " ")}</span><span className="feature-val">{typeof value === "number" ? value.toFixed(4) : String(value)}</span></div>))}</div></details>
                      )}
                    </>)}
                  </div>
                )}
              </section>
            </>);
          })()}
        </div>
      )}

      {!result && !loading && (
        <section className="how-it-works">
          <h3 className="hiw-title">How It Works</h3>
          <div className="hiw-steps">
            <div className="hiw-step"><div className="hiw-icon"><i className="fas fa-clipboard-list"></i></div><h4>1. Paste</h4><p>Copy the suspicious email, text message, or link</p></div>
            <div className="hiw-arrow"><i className="fas fa-long-arrow-alt-right"></i></div>
            <div className="hiw-step"><div className="hiw-icon"><i className="fas fa-robot"></i></div><h4>2. Analyze</h4><p>Our AI scans for 200+ phishing patterns and tactics</p></div>
            <div className="hiw-arrow"><i className="fas fa-long-arrow-alt-right"></i></div>
            <div className="hiw-step"><div className="hiw-icon"><i className="fas fa-clipboard-check" style={{ color: 'var(--success)' }}></i> </div><h4>3. Know</h4><p>Get a clear verdict: Safe, Suspicious, or Phishing</p></div>
          </div>
        </section>
      )}
    </div>
  );
}

export default Scanner;
