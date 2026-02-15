import pool from "./connection.js";

const createTables = async () => {
  const queries = `
    -- Scans table to store all analysis history
    CREATE TABLE IF NOT EXISTS scans (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      content TEXT NOT NULL,
      content_type VARCHAR(20) NOT NULL DEFAULT 'email',
      classification VARCHAR(20) NOT NULL,
      confidence_score DECIMAL(3,2) NOT NULL,
      risk_level VARCHAR(20) NOT NULL,
      threat_indicators JSONB DEFAULT '[]',
      explanation TEXT,
      recommendations JSONB DEFAULT '[]',
      ip_address VARCHAR(45),
      user_agent TEXT,
      created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    );

    -- Create index for faster queries
    CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_scans_classification ON scans(classification);
    CREATE INDEX IF NOT EXISTS idx_scans_content_type ON scans(content_type);

    -- Stats aggregation table (updated periodically or via triggers)
    CREATE TABLE IF NOT EXISTS stats_daily (
      id SERIAL PRIMARY KEY,
      date DATE NOT NULL UNIQUE,
      total_scans INTEGER DEFAULT 0,
      phishing_count INTEGER DEFAULT 0,
      suspicious_count INTEGER DEFAULT 0,
      safe_count INTEGER DEFAULT 0,
      email_count INTEGER DEFAULT 0,
      sms_count INTEGER DEFAULT 0,
      url_count INTEGER DEFAULT 0,
      created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
      updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    );

    -- Common threat patterns detected
    CREATE TABLE IF NOT EXISTS threat_patterns (
      id SERIAL PRIMARY KEY,
      pattern_category VARCHAR(100) NOT NULL,
      pattern_text TEXT NOT NULL,
      occurrence_count INTEGER DEFAULT 1,
      last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
      created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_threat_patterns_category ON threat_patterns(pattern_category);
  `;

  try {
    await pool.query(queries);
    console.log("✅ Database tables created successfully");
  } catch (error) {
    console.error("❌ Error creating tables:", error);
    throw error;
  }
};

const migrate = async () => {
  try {
    console.log("🔄 Running database migrations...");
    await createTables();
    console.log("✅ Migrations completed");
    process.exit(0);
  } catch (error) {
    console.error("❌ Migration failed:", error);
    process.exit(1);
  }
};

migrate();
