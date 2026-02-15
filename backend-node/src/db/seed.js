import pool from "./connection.js";
import { v4 as uuidv4 } from "uuid";

const seedData = async () => {
  // Sample phishing scans with various classifications
  const sampleScans = [
    {
      content:
        "Dear Customer, Your account has been suspended. Click here immediately to verify your identity: http://secure-bank-login.xyz/verify",
      content_type: "email",
      classification: "phishing",
      confidence_score: 0.92,
      risk_level: "critical",
      threat_indicators: [
        {
          category: "Urgency Language",
          description: "Contains urgent/pressure language: 'immediately'",
          severity: "medium",
        },
        {
          category: "Credential Harvesting",
          description: "Requests sensitive information: 'verify your identity'",
          severity: "high",
        },
        {
          category: "Suspicious URL",
          description: "URL matches known phishing pattern",
          severity: "high",
        },
      ],
      explanation: "This email shows strong indicators of a phishing attempt.",
      recommendations: ["Do NOT click any links", "Report to IT security"],
    },
    {
      content:
        "URGENT! Your M-Pesa account will be blocked. Send your PIN to 0712345678 to avoid suspension.",
      content_type: "sms",
      classification: "phishing",
      confidence_score: 0.95,
      risk_level: "critical",
      threat_indicators: [
        {
          category: "Urgency Language",
          description: "Contains urgent/pressure language: 'URGENT'",
          severity: "medium",
        },
        {
          category: "Credential Harvesting",
          description: "Requests sensitive information: 'mpesa pin'",
          severity: "high",
        },
        {
          category: "Threatening Language",
          description: "Contains threatening language: 'blocked'",
          severity: "high",
        },
      ],
      explanation:
        "This SMS is a clear M-Pesa phishing scam targeting Kenyan users.",
      recommendations: ["Never share your M-Pesa PIN", "Report to Safaricom"],
    },
    {
      content:
        "Your Amazon order #12345 has shipped. Track your package at: https://amazon.com/track/12345",
      content_type: "email",
      classification: "safe",
      confidence_score: 0.1,
      risk_level: "low",
      threat_indicators: [],
      explanation: "This email appears to be legitimate.",
      recommendations: ["Always verify sender for financial requests"],
    },
    {
      content:
        "Action Required: Update your banking details within 24 hours or your account will be frozen. Login here: http://equity-bank-ke.tk/login",
      content_type: "email",
      classification: "phishing",
      confidence_score: 0.88,
      risk_level: "high",
      threat_indicators: [
        {
          category: "Urgency Language",
          description: "Contains urgent/pressure language: 'within 24 hours'",
          severity: "medium",
        },
        {
          category: "Credential Harvesting",
          description: "Requests sensitive information: 'banking details'",
          severity: "high",
        },
        {
          category: "Domain Spoofing",
          description: "Possible spoofed domain mimicking equity.co.ke",
          severity: "high",
        },
      ],
      explanation: "This email attempts to impersonate Equity Bank.",
      recommendations: [
        "Contact Equity Bank directly through official channels",
      ],
    },
    {
      content:
        "Congratulations! You've won $1,000,000. Click here to claim: bit.ly/win-now",
      content_type: "email",
      classification: "phishing",
      confidence_score: 0.85,
      risk_level: "high",
      threat_indicators: [
        {
          category: "Suspicious URL",
          description: "URL shortener detected",
          severity: "high",
        },
        {
          category: "Suspicious Phrasing",
          description: "Generic call to action",
          severity: "low",
        },
      ],
      explanation: "This is a classic lottery/prize scam.",
      recommendations: ["If it sounds too good to be true, it probably is"],
    },
    {
      content:
        "Hi team, please review the attached quarterly report. Best, John from Finance",
      content_type: "email",
      classification: "safe",
      confidence_score: 0.05,
      risk_level: "low",
      threat_indicators: [],
      explanation:
        "This email appears to be a legitimate internal communication.",
      recommendations: ["Verify sender for sensitive documents"],
    },
    {
      content:
        "Your KCB account has unusual activity. Verify at http://kcb-secure-login.ml/verify or call 0700000000",
      content_type: "sms",
      classification: "phishing",
      confidence_score: 0.9,
      risk_level: "critical",
      threat_indicators: [
        {
          category: "Urgency Language",
          description: "Contains urgent/pressure language: 'unusual activity'",
          severity: "medium",
        },
        {
          category: "Suspicious URL",
          description: "Suspicious TLD detected (.ml)",
          severity: "high",
        },
        {
          category: "Domain Spoofing",
          description: "Possible spoofed domain mimicking kcbgroup.com",
          severity: "high",
        },
      ],
      explanation: "This SMS attempts to impersonate KCB Bank.",
      recommendations: ["Call KCB directly using the number on your card"],
    },
    {
      content:
        "Meeting reminder: Team standup at 9 AM tomorrow in Conference Room B.",
      content_type: "email",
      classification: "safe",
      confidence_score: 0.02,
      risk_level: "low",
      threat_indicators: [],
      explanation: "This is a standard meeting reminder.",
      recommendations: [],
    },
    {
      content:
        "Dear valued customer, kindly do the needful and update your account here: http://192.168.1.100/update",
      content_type: "email",
      classification: "suspicious",
      confidence_score: 0.45,
      risk_level: "medium",
      threat_indicators: [
        {
          category: "Suspicious Phrasing",
          description: "Unusual phrasing: 'kindly do the needful'",
          severity: "low",
        },
        {
          category: "Suspicious URL",
          description: "IP address instead of domain",
          severity: "high",
        },
        {
          category: "Suspicious Phrasing",
          description: "Generic greeting",
          severity: "low",
        },
      ],
      explanation: "This email contains suspicious elements.",
      recommendations: ["Verify the sender through official channels"],
    },
    {
      content:
        "Your Safaricom bill is ready. View at https://safaricom.co.ke/bills",
      content_type: "sms",
      classification: "safe",
      confidence_score: 0.08,
      risk_level: "low",
      threat_indicators: [],
      explanation: "This appears to be a legitimate Safaricom notification.",
      recommendations: [],
    },
  ];

  // Insert scans with random dates over the past 30 days
  console.log("🌱 Seeding scan data...");

  for (let i = 0; i < sampleScans.length; i++) {
    const scan = sampleScans[i];
    const daysAgo = Math.floor(Math.random() * 30);
    const createdAt = new Date();
    createdAt.setDate(createdAt.getDate() - daysAgo);

    await pool.query(
      `INSERT INTO scans (content, content_type, classification, confidence_score, risk_level, threat_indicators, explanation, recommendations, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [
        scan.content,
        scan.content_type,
        scan.classification,
        scan.confidence_score,
        scan.risk_level,
        JSON.stringify(scan.threat_indicators),
        scan.explanation,
        JSON.stringify(scan.recommendations),
        createdAt,
      ],
    );
  }

  // Add more random scans for better dashboard visualization
  const classifications = ["phishing", "suspicious", "safe"];
  const contentTypes = ["email", "sms", "url"];

  for (let i = 0; i < 40; i++) {
    const classification = classifications[Math.floor(Math.random() * 3)];
    const contentType = contentTypes[Math.floor(Math.random() * 3)];
    const daysAgo = Math.floor(Math.random() * 30);
    const createdAt = new Date();
    createdAt.setDate(createdAt.getDate() - daysAgo);

    let confidence = 0;
    let riskLevel = "low";

    if (classification === "phishing") {
      confidence = 0.7 + Math.random() * 0.3;
      riskLevel = confidence > 0.85 ? "critical" : "high";
    } else if (classification === "suspicious") {
      confidence = 0.3 + Math.random() * 0.3;
      riskLevel = "medium";
    } else {
      confidence = Math.random() * 0.25;
      riskLevel = "low";
    }

    await pool.query(
      `INSERT INTO scans (content, content_type, classification, confidence_score, risk_level, threat_indicators, explanation, recommendations, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [
        `Sample ${contentType} content #${i + 1}`,
        contentType,
        classification,
        parseFloat(confidence.toFixed(2)),
        riskLevel,
        "[]",
        `Sample analysis for ${contentType}`,
        "[]",
        createdAt,
      ],
    );
  }

  // Update daily stats
  console.log("📊 Updating daily statistics...");

  await pool.query(`
    INSERT INTO stats_daily (date, total_scans, phishing_count, suspicious_count, safe_count, email_count, sms_count, url_count)
    SELECT 
      DATE(created_at) as date,
      COUNT(*) as total_scans,
      COUNT(*) FILTER (WHERE classification = 'phishing') as phishing_count,
      COUNT(*) FILTER (WHERE classification = 'suspicious') as suspicious_count,
      COUNT(*) FILTER (WHERE classification = 'safe') as safe_count,
      COUNT(*) FILTER (WHERE content_type = 'email') as email_count,
      COUNT(*) FILTER (WHERE content_type = 'sms') as sms_count,
      COUNT(*) FILTER (WHERE content_type = 'url') as url_count
    FROM scans
    GROUP BY DATE(created_at)
    ON CONFLICT (date) DO UPDATE SET
      total_scans = EXCLUDED.total_scans,
      phishing_count = EXCLUDED.phishing_count,
      suspicious_count = EXCLUDED.suspicious_count,
      safe_count = EXCLUDED.safe_count,
      email_count = EXCLUDED.email_count,
      sms_count = EXCLUDED.sms_count,
      url_count = EXCLUDED.url_count,
      updated_at = NOW()
  `);

  // Seed common threat patterns
  console.log("⚠️ Seeding threat patterns...");

  const threatPatterns = [
    { category: "Urgency Language", pattern: "immediately", count: 15 },
    { category: "Urgency Language", pattern: "action required", count: 12 },
    { category: "Urgency Language", pattern: "within 24 hours", count: 10 },
    {
      category: "Credential Harvesting",
      pattern: "verify your account",
      count: 18,
    },
    {
      category: "Credential Harvesting",
      pattern: "update your password",
      count: 14,
    },
    { category: "Credential Harvesting", pattern: "mpesa pin", count: 22 },
    { category: "Domain Spoofing", pattern: "safaricom", count: 20 },
    { category: "Domain Spoofing", pattern: "equity bank", count: 16 },
    { category: "Domain Spoofing", pattern: "kcb", count: 11 },
    { category: "Suspicious URL", pattern: "bit.ly", count: 25 },
    { category: "Suspicious URL", pattern: ".tk domain", count: 8 },
    {
      category: "Threatening Language",
      pattern: "account suspended",
      count: 13,
    },
    { category: "Threatening Language", pattern: "legal action", count: 7 },
  ];

  for (const pattern of threatPatterns) {
    await pool.query(
      `INSERT INTO threat_patterns (pattern_category, pattern_text, occurrence_count) VALUES ($1, $2, $3)`,
      [pattern.category, pattern.pattern, pattern.count],
    );
  }

  console.log("✅ Database seeded successfully");
};

const seed = async () => {
  try {
    console.log("🔄 Starting database seeding...");
    await seedData();
    process.exit(0);
  } catch (error) {
    console.error("❌ Seeding failed:", error);
    process.exit(1);
  }
};

seed();
