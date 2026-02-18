// SMS Listener - monitors Firebase RTDB sms_logs/{userId} for new messages from
// the Android app, auto-scans them via the ML backend, and stores results in the
// user's scan history. Path matches rules: sms_logs/$uid
import { ref, onChildAdded, update } from "firebase/database";
import { database } from "../config/firebase";
import { saveScan } from "./firebaseStorage";

const API_URL = import.meta.env.VITE_API_URL || "/api";

// Track processed SMS IDs per user to avoid re-processing on reconnect
const processedIds = new Set();

/**
 * Scans SMS content via the ML backend API
 */
const scanSmsContent = async (smsText) => {
  const response = await fetch(`${API_URL}/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({ content: smsText, content_type: "sms" }),
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail || "Scan failed");
  }

  return response.json();
};

/**
 * Mark an SMS in Firebase as processed.
 * Path: sms_logs/{userId}/{smsId}
 */
const markSmsProcessed = async (userId, smsId, scanResult) => {
  try {
    const smsRef = ref(database, `sms_logs/${userId}/${smsId}`);
    await update(smsRef, {
      scanned: true,
      scan_classification: scanResult.classification,
      scan_risk_level: scanResult.risk_level,
      scanned_at: new Date().toISOString(),
    });
  } catch (e) {
    console.warn("Could not mark SMS as processed:", e.message);
  }
};

/**
 * Start listening to sms_logs/{userId} for new incoming messages from Android.
 * The Android app must write SMS entries to: sms_logs/{uid}/{pushId}
 *
 * @param {string} userId - authenticated user's UID
 * @param {Function} onNewScan - callback(scan) called after each SMS is scanned
 * @returns {Function} unsubscribe function
 */
export const startSmsListener = (userId, onNewScan) => {
  if (!userId) return () => {};

  // ✅ Listen only to THIS user's SMS logs — matches rules: sms_logs/$uid
  const smsLogsRef = ref(database, `sms_logs/${userId}`);

  const unsubscribe = onChildAdded(smsLogsRef, async (snapshot) => {
    const smsId = snapshot.key;
    const smsData = snapshot.val();

    if (!smsData || processedIds.has(smsId)) return;

    // Skip SMS already scanned in a previous session
    if (smsData.scanned) {
      processedIds.add(smsId);
      return;
    }

    processedIds.add(smsId);

    const smsText = smsData.message || smsData.body || smsData.text || "";
    const sender  = smsData.sender || smsData.from || smsData.address || "Unknown";

    if (!smsText.trim()) return;

    try {
      console.log(`📱 New SMS from ${sender} — scanning...`);

      // Run through ML backend
      const result = await scanSmsContent(smsText);

      // Save to user's scan history in RTDB (users/{uid}/scans)
      const saved = await saveScan(userId, {
        content_type: "sms",
        content_preview: smsText.substring(0, 100),
        classification: result.classification,
        confidence_score: result.confidence_score,
        risk_level: result.risk_level,
        explanation: result.explanation,
        threat_indicators: result.threat_indicators || [],
        source: "android_sms",
        sender,
        sms_id: smsId,
      });

      console.log(`✅ SMS scanned & saved [${result.classification}]:`, smsId);

      // Mark in Firebase so it won't be re-processed
      await markSmsProcessed(userId, smsId, result);

      // Trigger toast notification in the UI
      if (onNewScan && saved) {
        onNewScan({ ...saved, sender, sms_id: smsId });
      }
    } catch (err) {
      console.error(`❌ Failed to scan SMS [${smsId}]:`, err.message);
      processedIds.delete(smsId); // allow retry on next reconnect
    }
  });

  return unsubscribe;
};
};
