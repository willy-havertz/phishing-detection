import { useState, useRef, useEffect } from "react";
import { saveScan } from "../utils/scanStorage";
import { sanitizeInput, createRateLimiter } from "../utils/security";

// API URL - uses environment variable in production, proxy in development
const API_URL = import.meta.env.VITE_API_URL || "/api";
const MAX_CONTENT_LENGTH = 50000;

// Rate limit: 10 scans per minute
const checkRateLimit = createRateLimiter(10, 60000);

function Scanner() {
  const [content, setContent] = useState("");
  const [contentType, setContentType] = useState("email");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const abortControllerRef = useRef(null);

  // Change detection state
  const [lastScannedContent, setLastScannedContent] = useState("");
  const [contentChanged, setContentChanged] = useState(false);
  const [changeHighlight, setChangeHighlight] = useState(false);

  // Detect content changes after scan
  useEffect(() => {
    if (lastScannedContent && content !== lastScannedContent && result) {
      setContentChanged(true);
    } else {
      setContentChanged(false);
    }
  }, [content, lastScannedContent, result]);

  const handleContentChange = (e) => {
    const value = e.target.value;
    // Limit input length
    if (value.length <= MAX_CONTENT_LENGTH) {
      setContent(value);
    }
  };

  const handleChangedClick = () => {
    setChangeHighlight(true);
    setTimeout(() => setChangeHighlight(false), 1500);
  };

  const handleScan = async () => {
    const trimmedContent = content.trim();

    if (!trimmedContent) {
      setError("Please enter content to scan");
      return;
    }

    // Check rate limit
    if (!checkRateLimit()) {
      setError(
        "Too many requests. Please wait a moment before scanning again.",
      );
      return;
    }

    // Cancel any pending request
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
    abortControllerRef.current = new AbortController();

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      // Sanitize content before sending
      const sanitizedContent = sanitizeInput(trimmedContent);

      const response = await fetch(`${API_URL}/analyze`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify({
          content: sanitizedContent,
          content_type: contentType,
        }),
        signal: abortControllerRef.current.signal,
      });

      if (response.status === 429) {
        throw new Error(
          "Rate limit exceeded. Please wait before trying again.",
        );
      }

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.detail || "Scan failed. Please try again.");
      }

      const data = await response.json();
      setResult(data);
      setLastScannedContent(sanitizedContent);
      setContentChanged(false);

      // Save scan to localStorage for real-time Dashboard/History
      saveScan({
        content_type: contentType,
        content_preview: sanitizedContent.substring(0, 100),
        classification: data.classification,
        confidence_score: data.confidence_score,
        risk_level: data.risk_level,
        explanation: data.explanation,
        threat_indicators: data.threat_indicators,
      });
    } catch (err) {
      if (err.name === "AbortError") {
        return; // Request was cancelled
      }
      setError(
        err.message || "Analysis failed. Make sure the backend is running.",
      );
    } finally {
      setLoading(false);
    }
  };

  const getClassificationEmoji = (classification) => {
    switch (classification) {
      case "safe":
        return "✅";
      case "suspicious":
        return "⚠️";
      case "phishing":
        return "🚨";
      default:
        return "❓";
    }
  };

  const placeholders = {
    email:
      "Paste the email content here...\n\nExample:\nDear Customer,\nYour account has been suspended. Click here immediately to verify your identity: http://secure-bank-login.xyz/verify\nBest regards,\nSecurity Team",
    sms: "Paste the SMS content here...\n\nExample:\nURGENT! Your M-Pesa account will be blocked. Send your PIN to 0712345678 to avoid suspension.",
    url: "Paste a URL to analyze...\n\nExample:\nhttp://secure-bank-ke.xyz/login",
  };

  return (
    <div>
      <section className="scanner-section">
        <h1 className="scanner-title">🔍 Scan for Phishing Threats</h1>
        <p className="scanner-subtitle">
          Paste an email, SMS, or URL to analyze with our ML-powered detection
          engine
        </p>

        <div className="content-type-tabs">
          <button
            className={`tab-btn ${contentType === "email" ? "active" : ""}`}
            onClick={() => setContentType("email")}
          >
            📧 Email
          </button>
          <button
            className={`tab-btn ${contentType === "sms" ? "active" : ""}`}
            onClick={() => setContentType("sms")}
          >
            📱 SMS
          </button>
          <button
            className={`tab-btn ${contentType === "url" ? "active" : ""}`}
            onClick={() => setContentType("url")}
          >
            🔗 URL
          </button>
        </div>

        <div style={{ position: "relative" }}>
          <textarea
            className={`scan-input ${changeHighlight ? "input-changed-highlight" : ""} ${contentChanged ? "input-modified" : ""}`}
            placeholder={placeholders[contentType]}
            value={content}
            onChange={handleContentChange}
            maxLength={MAX_CONTENT_LENGTH}
          />
          {contentChanged && (
            <div
              className="change-badge"
              onClick={handleChangedClick}
              title="Content has been modified since last scan. Click to highlight changes."
            >
              ✏️ Content Modified — Click to Re-scan
            </div>
          )}
        </div>

        <div
          style={{
            fontSize: "0.75rem",
            color: "#9CA39C",
            textAlign: "right",
            marginTop: "0.25rem",
          }}
        >
          {content.length.toLocaleString()} /{" "}
          {MAX_CONTENT_LENGTH.toLocaleString()} characters
        </div>

        {error && (
          <div
            style={{
              color: "#EF4444",
              marginTop: "1rem",
              padding: "0.75rem",
              background: "#FEE2E2",
              borderRadius: "8px",
            }}
          >
            ❌ {error}
          </div>
        )}

        <button className="scan-btn" onClick={handleScan} disabled={loading}>
          {loading ? (
            <>
              <span
                className="spinner"
                style={{ width: 20, height: 20, borderWidth: 2 }}
              ></span>
              Analyzing...
            </>
          ) : (
            <>🛡️ Analyze Content</>
          )}
        </button>
      </section>

      {result && (
        <section className="results-section">
          <div className="result-header">
            <div className={`result-badge ${result.classification}`}>
              {getClassificationEmoji(result.classification)}{" "}
              {result.classification.toUpperCase()}
            </div>

            <div className="confidence-meter">
              <div className="confidence-label">
                Confidence: {Math.round(result.confidence_score * 100)}%
              </div>
              <div className="confidence-bar">
                <div
                  className={`confidence-fill ${
                    result.confidence_score < 0.3
                      ? "low"
                      : result.confidence_score < 0.6
                        ? "medium"
                        : "high"
                  }`}
                  style={{ width: `${result.confidence_score * 100}%` }}
                />
              </div>
            </div>

            <div
              style={{
                padding: "0.5rem 1rem",
                background: "#F3F4F3",
                borderRadius: "8px",
                fontSize: "0.875rem",
              }}
            >
              Risk Level: <strong>{result.risk_level.toUpperCase()}</strong>
            </div>
          </div>

          <div className="result-explanation">
            <h4>Analysis Summary</h4>
            <p>{result.explanation}</p>
          </div>

          {result.threat_indicators && result.threat_indicators.length > 0 && (
            <div className="threat-indicators">
              <h4>
                ⚠️ Threat Indicators Detected ({result.threat_indicators.length}
                )
              </h4>
              <div className="indicator-list">
                {result.threat_indicators.map((indicator, index) => (
                  <div
                    key={index}
                    className={`indicator-item ${indicator.severity}`}
                  >
                    <div>
                      <div className="indicator-category">
                        {indicator.category}
                      </div>
                      <div className="indicator-description">
                        {indicator.description}
                      </div>
                      {indicator.matched_text && (
                        <div
                          style={{
                            marginTop: "0.25rem",
                            fontFamily: "monospace",
                            fontSize: "0.8rem",
                            color: "#6B736B",
                          }}
                        >
                          Matched: "{indicator.matched_text}"
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {result.recommendations && result.recommendations.length > 0 && (
            <div className="recommendations">
              <h4>📋 Recommendations</h4>
              <ul>
                {result.recommendations.map((rec, index) => (
                  <li key={index}>{rec}</li>
                ))}
              </ul>
            </div>
          )}

          {/* ML Features Section */}
          {result.ml_features && (
            <div className="ml-features-section">
              <h4>🤖 ML Analysis Details</h4>

              <div className="ml-features-grid">
                {/* ML Probability */}
                <div className="ml-feature-card">
                  <div className="ml-feature-title">
                    ML Phishing Probability
                  </div>
                  <div
                    className={`ml-probability ${result.ml_features.ml_phishing_probability > 0.6 ? "danger" : result.ml_features.ml_phishing_probability > 0.3 ? "warning" : "safe"}`}
                  >
                    {Math.round(
                      result.ml_features.ml_phishing_probability * 100,
                    )}
                    %
                  </div>
                  <div className="ml-feature-subtitle">
                    Model: {result.ml_features.model_used}
                  </div>
                </div>

                {/* SSL Status */}
                {result.ml_features.ssl_status && (
                  <div className="ml-feature-card">
                    <div className="ml-feature-title">🔒 SSL/TLS Status</div>
                    <div
                      className={`ssl-status ${result.ml_features.ssl_status.ssl_valid ? "valid" : result.ml_features.ssl_status.has_ssl ? "invalid" : "none"}`}
                    >
                      {result.ml_features.ssl_status.ssl_valid
                        ? "✅ Valid"
                        : result.ml_features.ssl_status.has_ssl
                          ? "⚠️ Invalid"
                          : "❌ No SSL"}
                    </div>
                    {result.ml_features.ssl_status.ssl_issuer && (
                      <div className="ml-feature-subtitle">
                        Issuer: {result.ml_features.ssl_status.ssl_issuer}
                      </div>
                    )}
                    {result.ml_features.ssl_status.ssl_expiry_days !== null && (
                      <div className="ml-feature-subtitle">
                        Expires in:{" "}
                        {result.ml_features.ssl_status.ssl_expiry_days} days
                      </div>
                    )}
                  </div>
                )}

                {/* Domain Age */}
                {result.ml_features.domain_age &&
                  result.ml_features.domain_age.domain_age_days !== null && (
                    <div className="ml-feature-card">
                      <div className="ml-feature-title">📅 Domain Age</div>
                      <div
                        className={`domain-age ${result.ml_features.domain_age.domain_age_days > 365 ? "old" : result.ml_features.domain_age.domain_age_days > 30 ? "medium" : "new"}`}
                      >
                        {result.ml_features.domain_age.domain_age_days > 365
                          ? `${Math.floor(result.ml_features.domain_age.domain_age_days / 365)} years old`
                          : `${result.ml_features.domain_age.domain_age_days} days old`}
                      </div>
                      {result.ml_features.domain_age.registration_date && (
                        <div className="ml-feature-subtitle">
                          Registered:{" "}
                          {result.ml_features.domain_age.registration_date}
                        </div>
                      )}
                      {result.ml_features.domain_age.registrar && (
                        <div className="ml-feature-subtitle">
                          Registrar: {result.ml_features.domain_age.registrar}
                        </div>
                      )}
                    </div>
                  )}
              </div>

              {/* Top ML Features */}
              {result.ml_features.top_ml_features &&
                result.ml_features.top_ml_features.length > 0 && (
                  <div className="top-features">
                    <h5>📊 Top ML Feature Importances</h5>
                    <div className="feature-bars">
                      {result.ml_features.top_ml_features.map((feat, i) => (
                        <div key={i} className="feature-bar-item">
                          <span className="feature-name">
                            {feat.feature.replace(/_/g, " ")}
                          </span>
                          <div className="feature-bar-bg">
                            <div
                              className="feature-bar-fill"
                              style={{
                                width: `${Math.min(feat.importance * 500, 100)}%`,
                              }}
                            />
                          </div>
                          <span className="feature-value">
                            {(feat.importance * 100).toFixed(1)}%
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

              {/* Scoring Breakdown */}
              {result.analysis_details && (
                <div className="scoring-breakdown">
                  <h5>⚖️ Scoring Breakdown</h5>
                  <div className="score-items">
                    <div className="score-item">
                      <span>Heuristic Score</span>
                      <span className="score-value">
                        {Math.round(
                          (result.analysis_details.heuristic_score || 0) * 100,
                        )}
                        %
                      </span>
                    </div>
                    <div className="score-item">
                      <span>ML Score</span>
                      <span className="score-value">
                        {Math.round(
                          (result.analysis_details.ml_score || 0) * 100,
                        )}
                        %
                      </span>
                    </div>
                    <div className="score-item combined">
                      <span>Combined (40% heuristic + 60% ML)</span>
                      <span className="score-value">
                        {Math.round(
                          (result.analysis_details.combined_score || 0) * 100,
                        )}
                        %
                      </span>
                    </div>
                    <div className="score-item">
                      <span>Features Extracted</span>
                      <span className="score-value">
                        {result.analysis_details.features_extracted || 0}
                      </span>
                    </div>
                  </div>
                </div>
              )}

              {/* Lexical Features Summary (for URLs) */}
              {result.ml_features.lexical_features && (
                <details className="features-details">
                  <summary>
                    🔤 Lexical Features (
                    {Object.keys(result.ml_features.lexical_features).length}{" "}
                    extracted)
                  </summary>
                  <div className="features-table">
                    {Object.entries(result.ml_features.lexical_features).map(
                      ([key, value]) => (
                        <div key={key} className="feature-row">
                          <span className="feature-key">
                            {key.replace(/_/g, " ")}
                          </span>
                          <span className="feature-val">
                            {typeof value === "number"
                              ? value.toFixed(4)
                              : String(value)}
                          </span>
                        </div>
                      ),
                    )}
                  </div>
                </details>
              )}

              {/* Text Features Summary (for SMS/Email) */}
              {result.ml_features.text_features && (
                <details className="features-details">
                  <summary>
                    📝 Text NLP Features (
                    {Object.keys(result.ml_features.text_features).length}{" "}
                    extracted)
                  </summary>
                  <div className="features-table">
                    {Object.entries(result.ml_features.text_features).map(
                      ([key, value]) => (
                        <div key={key} className="feature-row">
                          <span className="feature-key">
                            {key.replace(/_/g, " ")}
                          </span>
                          <span className="feature-val">
                            {typeof value === "number"
                              ? value.toFixed(4)
                              : String(value)}
                          </span>
                        </div>
                      ),
                    )}
                  </div>
                </details>
              )}
            </div>
          )}
        </section>
      )}
    </div>
  );
}

export default Scanner;
