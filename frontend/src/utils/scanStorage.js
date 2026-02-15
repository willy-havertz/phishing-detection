// Scan Storage Utility - localStorage-based persistence for real-time data
import { sanitizeInput, generateSecureId } from "./security";

const STORAGE_KEY = "phishguard_scans";
const MAX_HISTORY = 100;
const MAX_CONTENT_LENGTH = 500;

// Sanitize scan data before storage
const sanitizeScan = (scan) => ({
  ...scan,
  content_preview: sanitizeInput(scan.content_preview || "").slice(
    0,
    MAX_CONTENT_LENGTH,
  ),
  explanation: sanitizeInput(scan.explanation || ""),
  classification: ["safe", "suspicious", "phishing"].includes(
    scan.classification,
  )
    ? scan.classification
    : "unknown",
  content_type: ["email", "sms", "url"].includes(scan.content_type)
    ? scan.content_type
    : "unknown",
  confidence_score: Math.min(
    1,
    Math.max(0, parseFloat(scan.confidence_score) || 0),
  ),
  risk_level: ["low", "medium", "high", "critical"].includes(scan.risk_level)
    ? scan.risk_level
    : "unknown",
});

export const getScanHistory = () => {
  try {
    const data = localStorage.getItem(STORAGE_KEY);
    if (!data) return [];
    const parsed = JSON.parse(data);
    // Validate it's an array
    return Array.isArray(parsed) ? parsed : [];
  } catch (e) {
    console.error("Failed to read scan history:", e);
    return [];
  }
};

export const saveScan = (scan) => {
  try {
    const history = getScanHistory();
    const sanitized = sanitizeScan(scan);
    const newScan = {
      id: generateSecureId(),
      ...sanitized,
      created_at: new Date().toISOString(),
    };
    history.unshift(newScan);
    const trimmed = history.slice(0, MAX_HISTORY);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(trimmed));
    window.dispatchEvent(new CustomEvent("scanUpdated", { detail: newScan }));
    return newScan;
  } catch (e) {
    console.error("Failed to save scan:", e);
    return null;
  }
};

export const clearHistory = () => {
  try {
    localStorage.removeItem(STORAGE_KEY);
    window.dispatchEvent(new CustomEvent("scanUpdated"));
    return true;
  } catch (e) {
    console.error("Failed to clear history:", e);
    return false;
  }
};

export const getStats = () => {
  const scans = getScanHistory();

  const stats = {
    total_scans: scans.length,
    phishing_count: scans.filter((s) => s.classification === "phishing").length,
    suspicious_count: scans.filter((s) => s.classification === "suspicious")
      .length,
    safe_count: scans.filter((s) => s.classification === "safe").length,
    email_count: scans.filter((s) => s.content_type === "email").length,
    sms_count: scans.filter((s) => s.content_type === "sms").length,
    url_count: scans.filter((s) => s.content_type === "url").length,
  };

  return stats;
};

export const getDailyTrends = () => {
  const scans = getScanHistory();
  const last7Days = [];

  for (let i = 6; i >= 0; i--) {
    const date = new Date();
    date.setDate(date.getDate() - i);
    const dateStr = date.toISOString().split("T")[0];

    const dayScans = scans.filter((s) => s.created_at.startsWith(dateStr));

    last7Days.push({
      date: dateStr,
      total: dayScans.length,
      phishing: dayScans.filter((s) => s.classification === "phishing").length,
      suspicious: dayScans.filter((s) => s.classification === "suspicious")
        .length,
      safe: dayScans.filter((s) => s.classification === "safe").length,
    });
  }

  return last7Days;
};

export const getTopPatterns = () => {
  const scans = getScanHistory();
  const patternCounts = {};

  scans.forEach((scan) => {
    if (scan.threat_indicators) {
      scan.threat_indicators.forEach((indicator) => {
        const key =
          indicator.category +
          "|" +
          (indicator.matched_text || indicator.description);
        if (!patternCounts[key]) {
          patternCounts[key] = {
            pattern_category: indicator.category,
            pattern_text: indicator.matched_text || indicator.description,
            occurrence_count: 0,
          };
        }
        patternCounts[key].occurrence_count++;
      });
    }
  });

  return Object.values(patternCounts)
    .sort((a, b) => b.occurrence_count - a.occurrence_count)
    .slice(0, 8);
};

export const getRecentThreats = () => {
  const scans = getScanHistory();
  return scans.filter((s) => s.classification !== "safe").slice(0, 5);
};
