import { useState, useEffect } from "react";

// API URL - uses environment variable in production, proxy in development
const API_URL = import.meta.env.VITE_API_URL || "/api";

function Education() {
  const [patterns, setPatterns] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchPatterns();
  }, []);

  const fetchPatterns = async () => {
    try {
      const response = await fetch(`${API_URL}/patterns`);
      if (response.ok) {
        const data = await response.json();
        setPatterns(data);
      }
    } catch (err) {
      console.error("Failed to fetch patterns:", err);
    } finally {
      setLoading(false);
    }
  };

  const educationalContent = {
    urgency: {
      title: "⚡ Urgency Tactics",
      description:
        "Phishers create a false sense of urgency to pressure victims into acting without thinking.",
      examples: patterns?.urgency_tactics || [
        "Immediate action required",
        "Your account will be suspended",
        "Act within 24 hours",
        "Final warning",
        "Security alert",
      ],
    },
    credential: {
      title: "🔐 Credential Harvesting",
      description:
        "Legitimate organizations will NEVER ask for sensitive information via email or SMS.",
      examples: patterns?.credential_harvesting || [
        "Verify your account",
        "Update your password",
        "Confirm your identity",
        "Enter your M-Pesa PIN",
        "Banking details required",
      ],
    },
    impersonation: {
      title: "🎭 Common Impersonations",
      description:
        "Phishers often impersonate trusted organizations to gain your confidence.",
      examples: patterns?.common_impersonations || [
        "Banks (Equity, KCB, Co-op, Standard Chartered)",
        "Mobile money (M-Pesa, Airtel Money)",
        "Government agencies (KRA, NTSA)",
        "E-commerce (Jumia, Amazon)",
        "Social media (Facebook, WhatsApp)",
      ],
    },
    redFlags: {
      title: "🚩 Red Flags to Watch",
      description: "Key indicators that a message might be a phishing attempt.",
      examples: patterns?.red_flags || [
        "Misspelled domain names (g00gle.com instead of google.com)",
        "URL shorteners (bit.ly, tinyurl)",
        "IP addresses instead of domain names",
        "Suspicious TLDs (.tk, .ml, .xyz)",
        "Generic greetings (Dear Customer)",
        "Grammar and spelling errors",
        "Requests for sensitive information via email/SMS",
      ],
    },
  };

  const kenyaSpecific = [
    {
      icon: "📱",
      title: "M-Pesa Scams",
      description:
        "Safaricom will NEVER ask for your M-Pesa PIN. Do not share it with anyone, even if they claim to be from Safaricom.",
      tips: [
        "Never share your M-Pesa PIN",
        "Safaricom doesn't call asking for PINs",
        "Verify any M-Pesa issues via *234#",
        "Report scam numbers to 0722 000 000",
      ],
    },
    {
      icon: "🏦",
      title: "Banking Fraud",
      description:
        "Banks in Kenya will never ask you to provide your full banking details via SMS or email.",
      tips: [
        "Call your bank directly using the number on your card",
        "Don't click links in messages claiming to be from your bank",
        "Check URLs carefully - is it the real bank domain?",
        "Enable transaction alerts on your accounts",
      ],
    },
    {
      icon: "📧",
      title: "Email Phishing",
      description:
        "Phishing emails often impersonate universities, employers, or government agencies.",
      tips: [
        "Check the sender's email address carefully",
        "Hover over links before clicking to see the real URL",
        "Be suspicious of attachments from unknown senders",
        "When in doubt, contact IT support",
      ],
    },
  ];

  const protectionSteps = [
    {
      step: 1,
      action: "Stop",
      description: "Don't click links or download attachments immediately",
    },
    {
      step: 2,
      action: "Think",
      description:
        "Does this request make sense? Would the organization really contact you this way?",
    },
    {
      step: 3,
      action: "Verify",
      description:
        "Contact the organization directly through official channels",
    },
    {
      step: 4,
      action: "Report",
      description:
        "Report suspicious messages to your IT team or the impersonated organization",
    },
  ];

  if (loading) {
    return (
      <div className="loading">
        <div className="spinner"></div>
      </div>
    );
  }

  return (
    <div>
      <h1 style={{ marginBottom: "0.5rem" }}>📚 Learn About Phishing</h1>
      <p style={{ color: "#6B736B", marginBottom: "2rem" }}>
        Understanding phishing tactics is your first line of defense against
        cyber threats.
      </p>

      {/* What is Phishing */}
      <div className="chart-section" style={{ marginBottom: "2rem" }}>
        <h2
          style={{
            display: "flex",
            alignItems: "center",
            gap: "0.5rem",
            marginBottom: "1rem",
          }}
        >
          🎣 What is Phishing?
        </h2>
        <p style={{ fontSize: "1.1rem", lineHeight: "1.8" }}>
          <strong>Phishing</strong> is a type of cyber attack where criminals
          attempt to steal sensitive information (like passwords, credit card
          numbers, or personal data) by disguising themselves as trustworthy
          entities. They typically use email, SMS (known as "smishing"), or fake
          websites to trick victims.
        </p>
        <div
          style={{
            marginTop: "1.5rem",
            padding: "1rem",
            background: "#FEF3C7",
            borderRadius: "10px",
            borderLeft: "4px solid #F59E0B",
          }}
        >
          <strong>⚠️ In Kenya:</strong> Phishing attacks targeting M-Pesa, bank
          accounts, and government services are increasingly common. Always
          verify before sharing any personal or financial information.
        </div>
      </div>

      {/* Phishing Tactics */}
      <h2 style={{ marginBottom: "1rem" }}>🎯 Common Phishing Tactics</h2>
      <div className="education-grid" style={{ marginBottom: "2rem" }}>
        {Object.values(educationalContent).map((category, index) => (
          <div className="education-card" key={index}>
            <h3>{category.title}</h3>
            <p
              style={{
                color: "#6B736B",
                marginBottom: "1rem",
                fontSize: "0.9rem",
              }}
            >
              {category.description}
            </p>
            <ul className="pattern-list">
              {category.examples.map((example, i) => (
                <li key={i}>
                  <span style={{ color: "#EF4444" }}>•</span>
                  {example}
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>

      {/* Kenya Specific */}
      <h2 style={{ marginBottom: "1rem" }}>🇰🇪 Kenya-Specific Threats</h2>
      <div className="education-grid" style={{ marginBottom: "2rem" }}>
        {kenyaSpecific.map((item, index) => (
          <div className="education-card" key={index}>
            <h3>
              {item.icon} {item.title}
            </h3>
            <p
              style={{
                color: "#6B736B",
                marginBottom: "1rem",
                fontSize: "0.9rem",
              }}
            >
              {item.description}
            </p>
            <ul className="pattern-list">
              {item.tips.map((tip, i) => (
                <li key={i}>
                  <span style={{ color: "#10B981" }}>✓</span>
                  {tip}
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>

      {/* Protection Steps */}
      <div className="chart-section" style={{ marginBottom: "2rem" }}>
        <h2 style={{ marginBottom: "1.5rem" }}>🛡️ How to Protect Yourself</h2>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
            gap: "1rem",
          }}
        >
          {protectionSteps.map((item) => (
            <div
              key={item.step}
              style={{
                padding: "1.5rem",
                background: "linear-gradient(135deg, #ACC8A2 0%, #8FB584 100%)",
                borderRadius: "12px",
                textAlign: "center",
              }}
            >
              <div
                style={{
                  fontSize: "2rem",
                  fontWeight: "700",
                  color: "#1A2517",
                  marginBottom: "0.5rem",
                }}
              >
                {item.step}
              </div>
              <div
                style={{
                  fontWeight: "600",
                  fontSize: "1.25rem",
                  marginBottom: "0.5rem",
                }}
              >
                {item.action}
              </div>
              <p style={{ fontSize: "0.875rem", color: "#1A2517" }}>
                {item.description}
              </p>
            </div>
          ))}
        </div>
      </div>

      {/* Quick Reference */}
      <div
        className="chart-section"
        style={{
          background: "linear-gradient(135deg, #1A2517 0%, #2A3A26 100%)",
          color: "white",
        }}
      >
        <h2 style={{ marginBottom: "1rem", color: "#ACC8A2" }}>
          📋 Quick Reference Card
        </h2>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(250px, 1fr))",
            gap: "1.5rem",
          }}
        >
          <div>
            <h4 style={{ color: "#EF4444", marginBottom: "0.5rem" }}>
              🚨 NEVER Do This
            </h4>
            <ul style={{ paddingLeft: "1.25rem", lineHeight: "1.8" }}>
              <li>Share passwords via email/SMS</li>
              <li>Click links from unknown senders</li>
              <li>Download unexpected attachments</li>
              <li>Share M-Pesa/Bank PINs</li>
              <li>Rush into action under pressure</li>
            </ul>
          </div>
          <div>
            <h4 style={{ color: "#10B981", marginBottom: "0.5rem" }}>
              ✅ ALWAYS Do This
            </h4>
            <ul style={{ paddingLeft: "1.25rem", lineHeight: "1.8" }}>
              <li>Verify sender identity</li>
              <li>Type URLs directly in browser</li>
              <li>Contact organizations via official channels</li>
              <li>Report suspicious messages</li>
              <li>Use strong, unique passwords</li>
            </ul>
          </div>
          <div>
            <h4 style={{ color: "#F59E0B", marginBottom: "0.5rem" }}>
              📞 Report To
            </h4>
            <ul style={{ paddingLeft: "1.25rem", lineHeight: "1.8" }}>
              <li>Safaricom: 0722 000 000</li>
              <li>Your bank's fraud hotline</li>
              <li>University IT department</li>
              <li>Kenya Police: 999 or 112</li>
              <li>CA Kenya: ca.go.ke</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Education;
