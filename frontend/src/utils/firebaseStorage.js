// Firebase Realtime Database Storage Utility
import { ref, push, set, get, remove, query, orderByChild, limitToLast, onValue } from "firebase/database";
import { database } from "../config/firebase";
import { sanitizeInput, generateSecureId } from "./security";

const MAX_CONTENT_LENGTH = 500;

// Sanitize scan data before storage
const sanitizeScan = (scan) => ({
  ...scan,
  content_preview: sanitizeInput(scan.content_preview || "").slice(0, MAX_CONTENT_LENGTH),
  explanation: sanitizeInput(scan.explanation || ""),
  classification: ["safe", "suspicious", "phishing"].includes(scan.classification)
    ? scan.classification
    : "unknown",
  content_type: ["email", "sms", "url"].includes(scan.content_type)
    ? scan.content_type
    : "unknown",
  confidence_score: Math.min(1, Math.max(0, parseFloat(scan.confidence_score) || 0)),
  risk_level: ["low", "medium", "high", "critical"].includes(scan.risk_level)
    ? scan.risk_level
    : "unknown",
});

// Get user's scan history reference
const getUserScansRef = (userId) => {
  if (!userId) throw new Error("User not authenticated");
  return ref(database, `users/${userId}/scans`);
};

// Get scan history for current user
export const getScanHistory = async (userId) => {
  try {
    if (!userId) return [];
    
    const scansRef = getUserScansRef(userId);
    const snapshot = await get(scansRef);
    
    if (!snapshot.exists()) return [];
    
    const scansObj = snapshot.val();
    const scansArray = Object.entries(scansObj).map(([id, data]) => ({
      id,
      ...data,
    }));
    
    // Sort by created_at descending
    return scansArray.sort((a, b) => 
      new Date(b.created_at) - new Date(a.created_at)
    );
  } catch (e) {
    console.error("Failed to read scan history:", e);
    return [];
  }
};

// Subscribe to real-time scan history updates
export const subscribeScanHistory = (userId, callback) => {
  if (!userId) return () => {};
  
  const scansRef = getUserScansRef(userId);
  
  const unsubscribe = onValue(scansRef, (snapshot) => {
    if (!snapshot.exists()) {
      callback([]);
      return;
    }
    
    const scansObj = snapshot.val();
    const scansArray = Object.entries(scansObj).map(([id, data]) => ({
      id,
      ...data,
    }));
    
    // Sort by created_at descending
    const sorted = scansArray.sort((a, b) => 
      new Date(b.created_at) - new Date(a.created_at)
    );
    
    callback(sorted);
  }, (error) => {
    console.error("Error subscribing to scans:", error);
    callback([]);
  });
  
  return unsubscribe;
};

// Save a new scan
export const saveScan = async (userId, scan) => {
  try {
    if (!userId) throw new Error("User not authenticated");
    
    const scansRef = getUserScansRef(userId);
    const newScanRef = push(scansRef);
    
    const sanitized = sanitizeScan(scan);
    const newScan = {
      ...sanitized,
      created_at: new Date().toISOString(),
    };
    
    await set(newScanRef, newScan);
    
    return { id: newScanRef.key, ...newScan };
  } catch (e) {
    console.error("Failed to save scan:", e);
    throw e;
  }
};

// Clear all scan history for user
export const clearHistory = async (userId) => {
  try {
    if (!userId) throw new Error("User not authenticated");
    
    const scansRef = getUserScansRef(userId);
    await remove(scansRef);
    
    return true;
  } catch (e) {
    console.error("Failed to clear history:", e);
    throw e;
  }
};

// Get statistics from scans
export const getStats = (scans) => {
  const stats = {
    total_scans: scans.length,
    phishing_count: scans.filter((s) => s.classification === "phishing").length,
    suspicious_count: scans.filter((s) => s.classification === "suspicious").length,
    safe_count: scans.filter((s) => s.classification === "safe").length,
    email_count: scans.filter((s) => s.content_type === "email").length,
    sms_count: scans.filter((s) => s.content_type === "sms").length,
    url_count: scans.filter((s) => s.content_type === "url").length,
  };

  return stats;
};

// Get daily trends from scans
export const getDailyTrends = (scans) => {
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
      suspicious: dayScans.filter((s) => s.classification === "suspicious").length,
      safe: dayScans.filter((s) => s.classification === "safe").length,
    });
  }

  return last7Days;
};

// Get top threat patterns
export const getTopPatterns = (scans) => {
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

// Get recent threats
export const getRecentThreats = (scans) => {
  return scans.filter((s) => s.classification !== "safe").slice(0, 5);
};
