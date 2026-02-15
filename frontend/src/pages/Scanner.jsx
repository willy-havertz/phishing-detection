import { useState, useRef } from "react";
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

  const handleContentChange = (e) => {
    const value = e.target.value;
    // Limit input length
    if (value.length <= MAX_CONTENT_LENGTH) {
      setContent(value);
    }
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
          Paste an email, SMS, or URL to check if it's a phishing attempt
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

        <textarea
          className="scan-input"
          placeholder={placeholders[contentType]}
          value={content}
          onChange={handleContentChange}
          maxLength={MAX_CONTENT_LENGTH}
        />

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
        </section>
      )}
    </div>
  );
}

export default Scanner;
