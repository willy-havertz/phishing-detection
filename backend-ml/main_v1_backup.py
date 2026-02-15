"""
AI Phishing Detection ML Service
Heuristic-based phishing classifier with explainability
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import re
from urllib.parse import urlparse

app = FastAPI(
    title="PhishGuard ML Service",
    description="AI-powered phishing detection API",
    version="1.0.0"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==================== PHISHING DETECTION RULES ====================

# Urgency keywords commonly used in phishing
URGENCY_KEYWORDS = [
    "urgent", "immediately", "action required", "act now", "expire",
    "suspended", "verify now", "confirm your", "update your account",
    "within 24 hours", "within 48 hours", "limited time", "final warning",
    "last chance", "account locked", "security alert", "unauthorized",
    "suspicious activity", "verify your identity", "confirm your identity"
]

# Credential harvesting phrases
CREDENTIAL_PHRASES = [
    "enter your password", "confirm your password", "update your password",
    "verify your account", "login credentials", "banking details",
    "credit card", "social security", "pin number", "cvv", "expiration date",
    "account number", "routing number", "mpesa pin", "m-pesa", "safaricom",
    "airtel money", "bank account", "atm pin", "otp", "one time password"
]

# Threatening language
THREAT_PHRASES = [
    "will be suspended", "will be terminated", "legal action",
    "prosecuted", "arrested", "fine", "penalty", "blocked",
    "disabled", "closed", "deleted", "frozen"
]

# Suspicious sender patterns
SUSPICIOUS_SENDER_PATTERNS = [
    r"@.*\d{3,}\.com",  # Random numbers in domain
    r"noreply.*@(?!google|microsoft|apple|amazon)",  # Fake noreply
    r"support@(?!google|microsoft|apple|amazon|safaricom)",  # Fake support
    r"security@(?!google|microsoft|apple|amazon)",  # Fake security
]

# Known phishing domain patterns
SUSPICIOUS_URL_PATTERNS = [
    r"bit\.ly|tinyurl|t\.co|goo\.gl",  # URL shorteners
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # IP addresses
    r"login.*\.(xyz|tk|ml|ga|cf|gq)",  # Suspicious TLDs
    r"(paypal|amazon|apple|google|microsoft|safaricom|mpesa).*\.(xyz|tk|ml|ga|cf|gq|info)",
    r"verify.*account",
    r"update.*password",
    r"secure.*login",
]

# Legitimate domains whitelist
LEGITIMATE_DOMAINS = [
    "google.com", "microsoft.com", "apple.com", "amazon.com",
    "safaricom.co.ke", "equity.co.ke", "kcbgroup.com", "co-opbank.co.ke",
    "standardmedia.co.ke", "nation.africa", "github.com", "linkedin.com"
]

# ==================== MODELS ====================

class AnalysisRequest(BaseModel):
    content: str
    content_type: str = "email"  # email, sms, url

class ThreatIndicator(BaseModel):
    category: str
    description: str
    severity: str  # low, medium, high
    matched_text: Optional[str] = None

class AnalysisResponse(BaseModel):
    classification: str  # safe, suspicious, phishing
    confidence_score: float  # 0.0 to 1.0
    risk_level: str  # low, medium, high, critical
    threat_indicators: List[ThreatIndicator]
    explanation: str
    recommendations: List[str]

# ==================== ANALYSIS FUNCTIONS ====================

def extract_urls(text: str) -> List[str]:
    """Extract URLs from text"""
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    return re.findall(url_pattern, text, re.IGNORECASE)

def check_urgency(text: str) -> List[ThreatIndicator]:
    """Check for urgency language"""
    indicators = []
    text_lower = text.lower()
    
    for keyword in URGENCY_KEYWORDS:
        if keyword in text_lower:
            indicators.append(ThreatIndicator(
                category="Urgency Language",
                description=f"Contains urgent/pressure language: '{keyword}'",
                severity="medium",
                matched_text=keyword
            ))
    
    return indicators

def check_credential_harvesting(text: str) -> List[ThreatIndicator]:
    """Check for credential harvesting attempts"""
    indicators = []
    text_lower = text.lower()
    
    for phrase in CREDENTIAL_PHRASES:
        if phrase in text_lower:
            indicators.append(ThreatIndicator(
                category="Credential Harvesting",
                description=f"Requests sensitive information: '{phrase}'",
                severity="high",
                matched_text=phrase
            ))
    
    return indicators

def check_threats(text: str) -> List[ThreatIndicator]:
    """Check for threatening language"""
    indicators = []
    text_lower = text.lower()
    
    for phrase in THREAT_PHRASES:
        if phrase in text_lower:
            indicators.append(ThreatIndicator(
                category="Threatening Language",
                description=f"Contains threatening language: '{phrase}'",
                severity="high",
                matched_text=phrase
            ))
    
    return indicators

def check_urls(text: str) -> List[ThreatIndicator]:
    """Check URLs for suspicious patterns"""
    indicators = []
    urls = extract_urls(text)
    
    for url in urls:
        # Check against suspicious patterns
        for pattern in SUSPICIOUS_URL_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                indicators.append(ThreatIndicator(
                    category="Suspicious URL",
                    description=f"URL matches known phishing pattern",
                    severity="high",
                    matched_text=url[:100]
                ))
                break
        
        # Check for domain spoofing
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Check for lookalike domains
            for legit in LEGITIMATE_DOMAINS:
                legit_name = legit.split('.')[0]
                if legit_name in domain and legit not in domain:
                    indicators.append(ThreatIndicator(
                        category="Domain Spoofing",
                        description=f"Possible spoofed domain mimicking {legit}",
                        severity="high",
                        matched_text=domain
                    ))
                    break
        except:
            pass
    
    return indicators

def check_grammar_issues(text: str) -> List[ThreatIndicator]:
    """Check for common grammar issues in phishing"""
    indicators = []
    
    # Common phishing grammar patterns
    patterns = [
        (r"dear\s+(customer|user|member|valued)", "Generic greeting"),
        (r"click\s+here\s+to\s+(verify|update|confirm)", "Generic call to action"),
        (r"(kindly|please)\s+do\s+the\s+needful", "Unusual phrasing"),
    ]
    
    for pattern, description in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            match = re.search(pattern, text, re.IGNORECASE)
            indicators.append(ThreatIndicator(
                category="Suspicious Phrasing",
                description=description,
                severity="low",
                matched_text=match.group(0) if match else None
            ))
    
    return indicators

def analyze_content(content: str, content_type: str) -> AnalysisResponse:
    """Main analysis function"""
    
    all_indicators = []
    
    # Run all checks
    all_indicators.extend(check_urgency(content))
    all_indicators.extend(check_credential_harvesting(content))
    all_indicators.extend(check_threats(content))
    all_indicators.extend(check_urls(content))
    all_indicators.extend(check_grammar_issues(content))
    
    # Calculate score
    high_severity = sum(1 for i in all_indicators if i.severity == "high")
    medium_severity = sum(1 for i in all_indicators if i.severity == "medium")
    low_severity = sum(1 for i in all_indicators if i.severity == "low")
    
    # Weighted score calculation
    score = min(1.0, (high_severity * 0.3 + medium_severity * 0.15 + low_severity * 0.05))
    
    # Determine classification
    if score >= 0.6:
        classification = "phishing"
        risk_level = "critical" if score >= 0.8 else "high"
    elif score >= 0.3:
        classification = "suspicious"
        risk_level = "medium"
    else:
        classification = "safe"
        risk_level = "low"
    
    # Generate explanation
    if classification == "phishing":
        explanation = f"This {content_type} shows strong indicators of a phishing attempt. Found {len(all_indicators)} threat indicators including credential harvesting attempts and suspicious URLs."
    elif classification == "suspicious":
        explanation = f"This {content_type} contains some suspicious elements that warrant caution. Found {len(all_indicators)} potential threat indicators."
    else:
        explanation = f"This {content_type} appears to be legitimate. No significant threat indicators detected."
    
    # Generate recommendations
    recommendations = []
    if classification == "phishing":
        recommendations = [
            "Do NOT click any links in this message",
            "Do NOT provide any personal or financial information",
            "Report this message to your IT security team",
            "Delete this message immediately",
            "If you've already clicked links, change your passwords immediately"
        ]
    elif classification == "suspicious":
        recommendations = [
            "Verify the sender through official channels before responding",
            "Do not click links - type URLs directly in your browser",
            "Be cautious about providing any personal information",
            "Contact the supposed sender through known contact methods"
        ]
    else:
        recommendations = [
            "Always verify sender identity for financial requests",
            "Keep your security software updated",
            "Report any suspicious messages to your IT team"
        ]
    
    return AnalysisResponse(
        classification=classification,
        confidence_score=round(score, 2),
        risk_level=risk_level,
        threat_indicators=all_indicators[:10],  # Limit to top 10
        explanation=explanation,
        recommendations=recommendations
    )

# ==================== API ENDPOINTS ====================

@app.get("/")
async def root():
    return {
        "service": "PhishGuard ML Service",
        "version": "1.0.0",
        "status": "operational"
    }

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

@app.post("/analyze", response_model=AnalysisResponse)
async def analyze(request: AnalysisRequest):
    """Analyze content for phishing indicators"""
    return analyze_content(request.content, request.content_type)

@app.get("/patterns")
async def get_patterns():
    """Get list of detected patterns for educational purposes"""
    return {
        "urgency_keywords": URGENCY_KEYWORDS,
        "credential_phrases": CREDENTIAL_PHRASES[:10],
        "threat_phrases": THREAT_PHRASES,
        "suspicious_url_patterns": [
            "URL shorteners (bit.ly, tinyurl, etc.)",
            "IP addresses instead of domains",
            "Suspicious TLDs (.xyz, .tk, .ml, etc.)",
            "Brand name + suspicious TLD"
        ]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
