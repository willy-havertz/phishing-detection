import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import pool from "./db/connection.js";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;
const ML_SERVICE_URL = process.env.ML_SERVICE_URL || "http://localhost:8001";

// Middleware
app.use(cors());
app.use(express.json());

// Request logging
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// ==================== ROUTES ====================

// Health check
app.get("/health", (req, res) => {
  res.json({ status: "healthy", service: "ThreatLens API Gateway" });
});

// Analyze content - proxies to ML service and saves to DB
app.post("/api/scan", async (req, res) => {
  try {
    const { content, content_type = "email" } = req.body;

    if (!content || content.trim() === "") {
      return res.status(400).json({ error: "Content is required" });
    }

    // Call ML service
    const mlResponse = await fetch(`${ML_SERVICE_URL}/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content, content_type }),
    });

    if (!mlResponse.ok) {
      throw new Error("ML service unavailable");
    }

    const analysis = await mlResponse.json();

    // Save to database
    const result = await pool.query(
      `INSERT INTO scans (content, content_type, classification, confidence_score, risk_level, threat_indicators, explanation, recommendations, ip_address, user_agent)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       RETURNING id, created_at`,
      [
        content,
        content_type,
        analysis.classification,
        analysis.confidence_score,
        analysis.risk_level,
        JSON.stringify(analysis.threat_indicators),
        analysis.explanation,
        JSON.stringify(analysis.recommendations),
        req.ip,
        req.get("User-Agent"),
      ],
    );

    // Update threat patterns
    for (const indicator of analysis.threat_indicators) {
      await pool.query(
        `INSERT INTO threat_patterns (pattern_category, pattern_text, occurrence_count, last_seen)
         VALUES ($1, $2, 1, NOW())
         ON CONFLICT DO NOTHING`,
        [indicator.category, indicator.matched_text || indicator.description],
      );
    }

    res.json({
      id: result.rows[0].id,
      created_at: result.rows[0].created_at,
      ...analysis,
    });
  } catch (error) {
    console.error("Scan error:", error);
    res.status(500).json({ error: "Analysis failed", message: error.message });
  }
});

// Get scan history
app.get("/api/history", async (req, res) => {
  try {
    const { limit = 20, offset = 0, classification, content_type } = req.query;

    let query =
      "SELECT id, content_type, classification, confidence_score, risk_level, explanation, created_at FROM scans";
    const params = [];
    const conditions = [];

    if (classification) {
      params.push(classification);
      conditions.push(`classification = $${params.length}`);
    }

    if (content_type) {
      params.push(content_type);
      conditions.push(`content_type = $${params.length}`);
    }

    if (conditions.length > 0) {
      query += " WHERE " + conditions.join(" AND ");
    }

    query += " ORDER BY created_at DESC";

    params.push(parseInt(limit));
    query += ` LIMIT $${params.length}`;

    params.push(parseInt(offset));
    query += ` OFFSET $${params.length}`;

    const result = await pool.query(query, params);

    // Get total count
    let countQuery = "SELECT COUNT(*) FROM scans";
    if (conditions.length > 0) {
      countQuery += " WHERE " + conditions.join(" AND ");
    }
    const countResult = await pool.query(
      countQuery,
      params.slice(0, conditions.length),
    );

    res.json({
      scans: result.rows,
      total: parseInt(countResult.rows[0].count),
      limit: parseInt(limit),
      offset: parseInt(offset),
    });
  } catch (error) {
    console.error("History error:", error);
    res.status(500).json({ error: "Failed to fetch history" });
  }
});

// Get single scan details
app.get("/api/scan/:id", async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query("SELECT * FROM scans WHERE id = $1", [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Scan not found" });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error("Scan fetch error:", error);
    res.status(500).json({ error: "Failed to fetch scan" });
  }
});

// Get dashboard statistics
app.get("/api/stats", async (req, res) => {
  try {
    // Overall stats
    const overallStats = await pool.query(`
      SELECT 
        COUNT(*) as total_scans,
        COUNT(*) FILTER (WHERE classification = 'phishing') as phishing_count,
        COUNT(*) FILTER (WHERE classification = 'suspicious') as suspicious_count,
        COUNT(*) FILTER (WHERE classification = 'safe') as safe_count,
        COUNT(*) FILTER (WHERE content_type = 'email') as email_count,
        COUNT(*) FILTER (WHERE content_type = 'sms') as sms_count,
        COUNT(*) FILTER (WHERE content_type = 'url') as url_count,
        ROUND(AVG(confidence_score)::numeric, 2) as avg_confidence
      FROM scans
    `);

    // Daily stats for last 30 days
    const dailyStats = await pool.query(`
      SELECT 
        DATE(created_at) as date,
        COUNT(*) as total,
        COUNT(*) FILTER (WHERE classification = 'phishing') as phishing,
        COUNT(*) FILTER (WHERE classification = 'suspicious') as suspicious,
        COUNT(*) FILTER (WHERE classification = 'safe') as safe
      FROM scans
      WHERE created_at >= NOW() - INTERVAL '30 days'
      GROUP BY DATE(created_at)
      ORDER BY date ASC
    `);

    // Top threat patterns
    const threatPatterns = await pool.query(`
      SELECT pattern_category, pattern_text, occurrence_count
      FROM threat_patterns
      ORDER BY occurrence_count DESC
      LIMIT 10
    `);

    // Recent high-risk scans
    const recentThreats = await pool.query(`
      SELECT id, content_type, classification, risk_level, explanation, created_at
      FROM scans
      WHERE classification IN ('phishing', 'suspicious')
      ORDER BY created_at DESC
      LIMIT 5
    `);

    res.json({
      overview: overallStats.rows[0],
      daily_trends: dailyStats.rows,
      top_patterns: threatPatterns.rows,
      recent_threats: recentThreats.rows,
    });
  } catch (error) {
    console.error("Stats error:", error);
    res.status(500).json({ error: "Failed to fetch statistics" });
  }
});

// Get threat patterns
app.get("/api/patterns", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT pattern_category, pattern_text, occurrence_count, last_seen
      FROM threat_patterns
      ORDER BY occurrence_count DESC
      LIMIT 20
    `);

    // Group by category
    const grouped = result.rows.reduce((acc, row) => {
      if (!acc[row.pattern_category]) {
        acc[row.pattern_category] = [];
      }
      acc[row.pattern_category].push({
        text: row.pattern_text,
        count: row.occurrence_count,
        last_seen: row.last_seen,
      });
      return acc;
    }, {});

    res.json(grouped);
  } catch (error) {
    console.error("Patterns error:", error);
    res.status(500).json({ error: "Failed to fetch patterns" });
  }
});

// ML service health check
app.get("/api/ml/health", async (req, res) => {
  try {
    const response = await fetch(`${ML_SERVICE_URL}/health`);
    const data = await response.json();
    res.json({ ml_service: "connected", ...data });
  } catch (error) {
    res.status(503).json({ ml_service: "disconnected", error: error.message });
  }
});

// Educational content - phishing patterns
app.get("/api/education/patterns", async (req, res) => {
  res.json({
    urgency_tactics: [
      "Immediate action required",
      "Your account will be suspended",
      "Act within 24 hours",
      "Final warning",
      "Security alert",
    ],
    credential_harvesting: [
      "Verify your account",
      "Update your password",
      "Confirm your identity",
      "Enter your M-Pesa PIN",
      "Banking details required",
    ],
    common_impersonations: [
      "Banks (Equity, KCB, Co-op, Standard Chartered)",
      "Mobile money (M-Pesa, Airtel Money)",
      "Government agencies (KRA, NTSA)",
      "E-commerce (Jumia, Amazon)",
      "Social media (Facebook, WhatsApp)",
    ],
    red_flags: [
      "Misspelled domain names (g00gle.com instead of google.com)",
      "URL shorteners (bit.ly, tinyurl)",
      "IP addresses instead of domain names",
      "Suspicious TLDs (.tk, .ml, .xyz)",
      "Generic greetings (Dear Customer)",
      "Grammar and spelling errors",
      "Requests for sensitive information via email/SMS",
    ],
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`
  ╔═══════════════════════════════════════════════════════════╗
  ║                                                           ║
  ║   🛡️  ThreatLens API Gateway                              ║
  ║                                                           ║
  ║   Server running on port ${PORT}                            ║
  ║   ML Service: ${ML_SERVICE_URL}                    ║
  ║                                                           ║
  ╚═══════════════════════════════════════════════════════════╝
  `);
});
