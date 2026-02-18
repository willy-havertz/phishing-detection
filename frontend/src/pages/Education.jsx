import { useState, useEffect } from "react";

const API_URL = import.meta.env.VITE_API_URL || "/api";

function Education() {
  const [patterns, setPatterns] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeQuiz, setActiveQuiz] = useState(null);
  const [quizAnswer, setQuizAnswer] = useState(null);

  useEffect(() => { fetchPatterns(); }, []);

  const fetchPatterns = async () => {
    try {
      const response = await fetch(`${API_URL}/patterns`);
      if (response.ok) { const data = await response.json(); setPatterns(data); }
    } catch (err) { console.error("Failed to fetch patterns:", err); }
    finally { setLoading(false); }
  };

  const educationalContent = {
    urgency: {
      title: "Urgency Tactics",
      icon: "fas fa-bolt",
      description: "Scammers create fake urgency to pressure you into acting without thinking. They want you to panic.",
      whatToDo: "Take a breath. Legitimate organizations give you time. If it feels rushed, it's probably a scam.",
      examples: patterns?.urgency_tactics || ["Immediate action required", "Your account will be suspended", "Act within 24 hours", "Final warning", "Security alert"],
    },
    credential: {
      title: "Credential Harvesting",
      icon: "fas fa-key",
      description: "Scammers try to trick you into giving away passwords, PINs, or personal details by pretending to be trusted services.",
      whatToDo: "Never share passwords or PINs via email, SMS, or phone. Real companies never ask for this.",
      examples: patterns?.credential_harvesting || ["Verify your account", "Update your password", "Confirm your identity", "Enter your M-Pesa PIN", "Banking details required"],
    },
    impersonation: {
      title: "Brand Impersonation",
      icon: "fas fa-user-secret",
      description: "Scammers pretend to be from trusted organizations like banks, phone companies, or government agencies.",
      whatToDo: "Always verify by contacting the organization directly through their official website or phone number.",
      examples: patterns?.common_impersonations || ["Banks (Equity, KCB, Co-op)", "M-Pesa / Safaricom", "Government (KRA, NTSA)", "E-commerce (Jumia, Amazon)", "Social media (Facebook, WhatsApp)"],
    },
    redFlags: {
      title: "Red Flags to Watch",
      icon: "fas fa-flag",
      description: "Key warning signs that a message or website might be a phishing attempt.",
      whatToDo: "If you spot any of these signs, don't interact with the message. Use Phish Guard to scan it instead!",
      examples: patterns?.red_flags || ["Misspelled domain names", "URL shorteners (bit.ly)", "IP addresses instead of domains", "Generic greetings (Dear Customer)", "Grammar errors", "Requests for sensitive info"],
    },
  };

  const kenyaSpecific = [
    { icon: "fas fa-mobile-alt", title: "M-Pesa Scams", description: "Safaricom will NEVER call or text asking for your M-Pesa PIN. No one from Safaricom needs your PIN — ever.", tips: ["Never share your M-Pesa PIN with anyone", "Verify M-Pesa issues by dialing *234#", "Report scam numbers to 0722 000 000", "Don't respond to \"reversal\" requests from strangers"] },
    { icon: "fas fa-university", title: "Banking Fraud", description: "Banks in Kenya will never ask for your full account details, passwords, or OTPs via SMS or email.", tips: ["Call your bank using the number on your card", "Never click links claiming to be from your bank", "Check URLs carefully — is it the real domain?", "Enable transaction alerts on all accounts"] },
    { icon: "fas fa-envelope", title: "Email Phishing", description: "Phishing emails often impersonate universities, employers, KRA, or delivery services.", tips: ["Check the sender's email address carefully", "Hover over links to see where they really go", "Be suspicious of unexpected attachments", "When in doubt, contact IT support or the sender directly"] },
  ];

  const quizzes = [
    { id: 1, question: "You receive an SMS: 'Your M-Pesa account has been blocked. Send PIN to 0712345678 to unblock.' What should you do?", options: ["Send your PIN immediately", "Call the number to ask", "Ignore it — Safaricom never asks for PINs via SMS", "Forward it to friends to warn them"], correct: 2 },
    { id: 2, question: "An email from 'support@equitybnk.co.ke' asks you to verify your account. What's suspicious?", options: ["The email has a subject line", "The domain is misspelled (equitybnk vs equitybank)", "It mentions your account", "It has a greeting"], correct: 1 },
    { id: 3, question: "A link reads 'http://192.168.1.100/kra-refund/claim.php'. Is this safe?", options: ["Yes, it mentions KRA", "Yes, it uses HTTP", "No — real websites don't use IP addresses", "Maybe, I should click to find out"], correct: 2 },
  ];

  const protectionSteps = [
    { step: 1, action: "Stop", icon: "fas fa-hand-paper", description: "Don't click links or download attachments immediately. Take a moment." },
    { step: 2, action: "Think", icon: "fas fa-brain", description: "Does this make sense? Would the organization really contact you this way?" },
    { step: 3, action: "Verify", icon: "fas fa-search", description: "Contact the organization directly through official channels to confirm." },
    { step: 4, action: "Report", icon: "fas fa-bullhorn", description: "Report suspicious messages to your IT team, bank, or the impersonated organization." },
  ];

  if (loading) return <div className="loading"><div className="spinner"></div></div>;

  return (
    <div className="education-page">
      <div className="page-header">
        <div>
          <h1 className="page-title"><i className="fas fa-graduation-cap" style={{ marginRight: '15px' }}></i> Learn to Spot Scams</h1>
          <p className="page-subtitle">Understanding phishing tactics is your first line of defense. Knowledge is power!</p>
        </div>
      </div>

      {/* What is Phishing */}
      <section className="edu-intro">
        <div className="edu-intro-icon">
          <i className="fas fa-fish"></i>
        </div>
        <div className="edu-intro-content">
          <h2>What is Phishing?</h2>
          <p><strong>Phishing</strong> is when criminals try to steal your personal information (passwords, bank details, M-Pesa PINs) by pretending to be someone you trust — like your bank, Safaricom, or a government agency.</p>
          <p>They use emails, SMS messages, and fake websites to trick you. <strong>Anyone can be a target.</strong></p>
        </div>
        <div className="edu-intro-alert">
          <strong><i className="fas fa-exclamation-triangle" style={{ marginRight: '8px' }}></i> In Kenya:</strong> Phishing attacks targeting M-Pesa, bank accounts, and KRA are increasingly common. Always verify before sharing any personal or financial information.
        </div>
      </section>

      {/* Protection Steps */}
      <section className="edu-section">
        <h2 className="edu-section-title"><i className="fas fa-shield-alt" style={{ marginRight: '10px', color: 'var(--primary)' }}></i> The 4-Step Protection Rule</h2>
        <p className="edu-section-desc">Follow these 4 simple steps whenever you receive a suspicious message:</p>
        <div className="protection-grid">
          {protectionSteps.map((item) => (
            <div key={item.step} className="protection-step">
              <div className="protection-icon">
                <i className={item.icon}></i>
              </div>
              <div className="protection-num">Step {item.step}</div>
              <h3 className="protection-action">{item.action}</h3>
              <p className="protection-desc">{item.description}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Phishing Tactics */}
      <section className="edu-section">
        <h2 className="edu-section-title"><i className="fas fa-bullseye" style={{ marginRight: '10px', color: 'var(--primary)' }}></i> Common Scam Tactics</h2>
        <p className="edu-section-desc">Scammers use these techniques to trick you. Learn to recognize them:</p>
        <div className="tactics-grid">
          {Object.values(educationalContent).map((category, index) => (
            <div className="tactic-card" key={index}>
              <div className="tactic-header">
                <span className="tactic-icon">
                  <i className={category.icon}></i>
                </span>
                <h3>{category.title}</h3>
              </div>
              <p className="tactic-desc">{category.description}</p>
              <div className="tactic-tip">
                <strong><i className="fas fa-lightbulb" style={{ marginRight: '5px' }}></i> What to do:</strong> {category.whatToDo}
              </div>
              <div className="tactic-examples">
                <h4>Watch out for:</h4>
                <ul>
                  {category.examples.map((example, i) => (
                    <li key={i}><span className="example-dot">•</span> {example}</li>
                  ))}
                </ul>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Kenya Specific */}
      <section className="edu-section">
        <h2 className="edu-section-title"><i className="fas fa-map-marker-alt" style={{ marginRight: '10px', color: 'var(--primary)' }}></i> Kenya-Specific Threats</h2>
        <p className="edu-section-desc">These scams specifically target Kenyans. Be extra careful with:</p>
        <div className="kenya-grid">
          {kenyaSpecific.map((item, index) => (
            <div className="kenya-card" key={index}>
              <div className="kenya-header">
                <span className="kenya-icon">
                  <i className={item.icon}></i>
                </span>
                <h3>{item.title}</h3>
              </div>
              <p className="kenya-desc">{item.description}</p>
              <div className="kenya-tips">
                {item.tips.map((tip, i) => (
                  <div key={i} className="kenya-tip"><span className="tip-check">✓</span> {tip}</div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Quiz Section */}
      <section className="edu-section">
        <h2 className="edu-section-title"><i className="fas fa-brain" style={{ marginRight: '10px', color: 'var(--primary)' }}></i> Test Your Knowledge</h2>
        <p className="edu-section-desc">Can you spot the scam? Try these quick quizzes:</p>
        <div className="quiz-grid">
          {quizzes.map((quiz) => (
            <div key={quiz.id} className="quiz-card">
              <div className="quiz-num">Question {quiz.id}</div>
              <p className="quiz-question">{quiz.question}</p>
              <div className="quiz-options">
                {quiz.options.map((option, i) => {
                  const isSelected = activeQuiz === quiz.id && quizAnswer === i;
                  const isCorrect = activeQuiz === quiz.id && quizAnswer !== null && i === quiz.correct;
                  const isWrong = isSelected && i !== quiz.correct;
                  return (
                    <button
                      key={i}
                      className={`quiz-option ${isCorrect ? "correct" : ""} ${isWrong ? "wrong" : ""} ${isSelected ? "selected" : ""}`}
                      onClick={() => { setActiveQuiz(quiz.id); setQuizAnswer(i); }}
                      disabled={activeQuiz === quiz.id && quizAnswer !== null}
                    >
                      <span className="quiz-letter">{String.fromCharCode(65 + i)}</span>
                      {option}
                    </button>
                  );
                })}
              </div>
              {activeQuiz === quiz.id && quizAnswer !== null && (
                <div className={`quiz-result ${quizAnswer === quiz.correct ? "quiz-correct" : "quiz-wrong"}`}>
                  {quizAnswer === quiz.correct ? <><i className="fas fa-check-circle" style={{ marginRight: '5px' }}></i> Correct! Well done!</> : <><i className="fas fa-times-circle" style={{ marginRight: '5px' }}></i> Not quite. The correct answer is: {quiz.options[quiz.correct]}</>}
                </div>
              )}
            </div>
          ))}
        </div>
      </section>

      {/* Quick Reference */}
      <section className="quick-ref">
        <h2 className="quick-ref-title"><i className="fas fa-clipboard-list" style={{ marginRight: '10px' }}></i> Quick Reference Card</h2>
        <div className="quick-ref-grid">
          <div className="quick-ref-col">
            <h4 className="ref-heading ref-danger"><i className="fas fa-times-circle" style={{ marginRight: '8px' }}></i> NEVER Do This</h4>
            <ul className="ref-list">
              <li>Share passwords via email/SMS</li>
              <li>Click links from unknown senders</li>
              <li>Download unexpected attachments</li>
              <li>Share M-Pesa/Bank PINs</li>
              <li>Rush into action under pressure</li>
            </ul>
          </div>
          <div className="quick-ref-col">
            <h4 className="ref-heading ref-safe"><i className="fas fa-check-circle" style={{ marginRight: '8px' }}></i> ALWAYS Do This</h4>
            <ul className="ref-list">
              <li>Verify sender identity</li>
              <li>Type URLs directly in browser</li>
              <li>Contact organizations officially</li>
              <li>Report suspicious messages</li>
              <li>Use strong, unique passwords</li>
            </ul>
          </div>
          <div className="quick-ref-col">
            <h4 className="ref-heading ref-warn"><i className="fas fa-phone-alt" style={{ marginRight: '8px' }}></i> Report To</h4>
            <ul className="ref-list">
              <li>Safaricom: 0722 000 000</li>
              <li>Your bank&apos;s fraud hotline</li>
              <li>University IT department</li>
              <li>Kenya Police: 999 or 112</li>
              <li>CA Kenya: ca.go.ke</li>
            </ul>
          </div>
        </div>
      </section>
    </div>
  );
}

export default Education;
