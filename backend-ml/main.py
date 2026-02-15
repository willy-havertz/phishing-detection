"""
AI Phishing Detection ML Service - Enhanced Version
Advanced heuristic + pattern-based phishing classifier with high accuracy
"""

import os
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict
import re
import math
import time
import html
from urllib.parse import urlparse, unquote
from collections import Counter, defaultdict
import hashlib
from functools import wraps

# ==================== SECURITY CONFIGURATION ====================

# Environment-based configuration for deployment
# Set FRONTEND_URL environment variable when deploying
# Example: FRONTEND_URL=https://your-app.vercel.app,https://your-app.netlify.app

def get_allowed_origins():
    """Get allowed origins from environment or use defaults"""
    env_origins = os.environ.get("FRONTEND_URL", "")
    
    # Default development origins
    dev_origins = [
        "http://localhost:5173",
        "http://localhost:5174",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5174",
    ]
    
    # Add production origins from environment
    if env_origins:
        prod_origins = [url.strip() for url in env_origins.split(",") if url.strip()]
        return dev_origins + prod_origins
    
    return dev_origins

def get_allowed_hosts():
    """Get allowed hosts from environment or use defaults"""
    env_hosts = os.environ.get("ALLOWED_HOSTS", "")
    
    # Default hosts
    default_hosts = ["localhost", "127.0.0.1", "*.localhost"]
    
    if env_hosts:
        prod_hosts = [h.strip() for h in env_hosts.split(",") if h.strip()]
        return default_hosts + prod_hosts
    
    return default_hosts

ALLOWED_ORIGINS = get_allowed_origins()
ALLOWED_HOSTS = get_allowed_hosts()

# Rate limiting configuration
RATE_LIMIT_REQUESTS = int(os.environ.get("RATE_LIMIT", "30"))
RATE_LIMIT_WINDOW = 60  # seconds
MAX_CONTENT_LENGTH = 50000  # 50KB max content
MAX_URL_LENGTH = 2048

# Production mode check
IS_PRODUCTION = os.environ.get("PRODUCTION", "false").lower() == "true"

# In-memory rate limiter (use Redis in production)
rate_limit_store: Dict[str, List[float]] = defaultdict(list)

app = FastAPI(
    title="PhishGuard ML Service",
    description="AI-powered phishing detection API with enhanced accuracy",
    version="2.0.0",
    docs_url=None if IS_PRODUCTION else "/docs",
    redoc_url=None
)

# ==================== SECURITY MIDDLEWARE ====================

# CORS - Environment-based configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Accept"],
    max_age=600,
)

# Trusted hosts - environment-based
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=ALLOWED_HOSTS
)

@app.middleware("http")
async def security_headers(request: Request, call_next):
    """Add security headers to all responses"""
    response = await call_next(request)
    
    # Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    
    # CSP for API responses
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    
    return response

@app.middleware("http")
async def rate_limiter(request: Request, call_next):
    """Simple rate limiting middleware"""
    # Get client IP
    client_ip = request.client.host if request.client else "unknown"
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()
    
    current_time = time.time()
    window_start = current_time - RATE_LIMIT_WINDOW
    
    # Clean old requests
    rate_limit_store[client_ip] = [
        t for t in rate_limit_store[client_ip] if t > window_start
    ]
    
    # Check rate limit
    if len(rate_limit_store[client_ip]) >= RATE_LIMIT_REQUESTS:
        return JSONResponse(
            status_code=429,
            content={
                "error": "Rate limit exceeded",
                "detail": f"Maximum {RATE_LIMIT_REQUESTS} requests per {RATE_LIMIT_WINDOW} seconds",
                "retry_after": RATE_LIMIT_WINDOW
            },
            headers={"Retry-After": str(RATE_LIMIT_WINDOW)}
        )
    
    # Record this request
    rate_limit_store[client_ip].append(current_time)
    
    response = await call_next(request)
    
    # Add rate limit headers
    remaining = RATE_LIMIT_REQUESTS - len(rate_limit_store[client_ip])
    response.headers["X-RateLimit-Limit"] = str(RATE_LIMIT_REQUESTS)
    response.headers["X-RateLimit-Remaining"] = str(remaining)
    response.headers["X-RateLimit-Reset"] = str(int(window_start + RATE_LIMIT_WINDOW))
    
    return response

# ==================== INPUT SANITIZATION ====================

def sanitize_input(text: str) -> str:
    """Sanitize user input to prevent injection attacks"""
    if not text:
        return ""
    
    # Remove null bytes
    text = text.replace('\x00', '')
    
    # Limit length
    text = text[:MAX_CONTENT_LENGTH]
    
    # Remove control characters (except newlines and tabs)
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
    
    return text

def validate_url(url: str) -> str:
    """Validate and sanitize URL input"""
    if not url:
        return ""
    
    url = url.strip()[:MAX_URL_LENGTH]
    
    # Basic URL validation
    if not re.match(r'^https?://|^www\.', url, re.IGNORECASE):
        # If just a domain, add http
        if re.match(r'^[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}', url):
            url = 'http://' + url
    
    return url

# ==================== ENHANCED PHISHING DETECTION RULES ====================

# Urgency keywords with severity weights
URGENCY_PATTERNS = {
    "critical": [
        "immediately", "right now", "within 1 hour", "urgent action required",
        "account will be closed", "permanent suspension", "final notice"
    ],
    "high": [
        "urgent", "act now", "expires today", "within 24 hours", "within 48 hours",
        "limited time", "last chance", "don't delay", "time sensitive",
        "respond immediately", "action needed", "verify now"
    ],
    "medium": [
        "soon", "quickly", "asap", "important", "attention required",
        "please respond", "awaiting your response", "pending action"
    ]
}

# Kenya-specific phishing targets
KENYA_TARGETS = {
    "mpesa": ["mpesa", "m-pesa", "m pesa", "safaricom money", "lipa na mpesa", "paybill", "till number", "send money"],
    "banks": ["equity bank", "kcb", "cooperative bank", "co-op bank", "ncba", "stanbic", "absa", "standard chartered", 
              "family bank", "dtb", "i&m bank", "barclays", "diamond trust"],
    "telcos": ["safaricom", "airtel", "telkom kenya", "faiba"],
    "government": ["kra", "kenya revenue", "ntsa", "ecitizen", "huduma", "nhif", "nssf", "immigration"],
    "mobile_money": ["airtel money", "t-kash", "equitel", "mshwari", "fuliza", "kcb mpesa"]
}

# Credential harvesting - categorized by severity
CREDENTIAL_PATTERNS = {
    "critical": [
        r"enter\s+(your\s+)?pin", r"mpesa\s+pin", r"atm\s+pin", r"secret\s+pin",
        r"enter\s+cvv", r"card\s+number", r"bank\s+account\s+number",
        r"(send|share|provide)\s+(your\s+)?(pin|password|otp)",
        r"social\s+security", r"id\s+number", r"passport\s+number"
    ],
    "high": [
        r"enter\s+(your\s+)?password", r"confirm\s+(your\s+)?password", 
        r"login\s+credentials", r"banking\s+details", r"verification\s+code",
        r"one\s+time\s+password", r"otp", r"secret\s+code", r"security\s+code",
        r"mother'?s?\s+maiden", r"date\s+of\s+birth", r"full\s+name"
    ],
    "medium": [
        r"verify\s+(your\s+)?account", r"confirm\s+(your\s+)?identity",
        r"update\s+(your\s+)?(account|details|information)",
        r"personal\s+information", r"contact\s+details"
    ]
}

# Threatening language patterns
THREAT_PATTERNS = {
    "critical": [
        r"account\s+(will\s+be\s+)?(permanently\s+)?(suspended|terminated|blocked|closed)",
        r"legal\s+action", r"(will\s+be\s+)?prosecuted", r"arrest\s+warrant",
        r"police\s+report", r"fraud\s+investigation"
    ],
    "high": [
        r"(will\s+be\s+)?(blocked|disabled|frozen|restricted)",
        r"(will\s+)?lose\s+access", r"funds?\s+(will\s+be\s+)?lost",
        r"service\s+(will\s+be\s+)?discontinued", r"penalty", r"fine"
    ],
    "medium": [
        r"unauthorized\s+access", r"suspicious\s+activity", r"security\s+breach",
        r"compromised", r"at\s+risk"
    ]
}

# Suspicious TLDs commonly used in phishing
SUSPICIOUS_TLDS = [
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".club", ".work", 
    ".click", ".link", ".info", ".online", ".site", ".website", ".space",
    ".pw", ".cc", ".ws", ".buzz", ".cam", ".icu", ".vip", ".loan"
]

# Legitimate domains whitelist (extended)
LEGITIMATE_DOMAINS = {
    "global": [
        "google.com", "gmail.com", "microsoft.com", "outlook.com", "apple.com", 
        "amazon.com", "facebook.com", "twitter.com", "linkedin.com", "github.com",
        "paypal.com", "stripe.com", "netflix.com", "spotify.com"
    ],
    "kenya": [
        "safaricom.co.ke", "mpesa.co.ke", "equity.co.ke", "equitybankgroup.com",
        "kcbgroup.com", "co-opbank.co.ke", "standardchartered.co.ke", "stanbicbank.co.ke",
        "absa.co.ke", "ncbagroup.com", "familybank.co.ke", "dtbafrica.com",
        "imbank.com", "kra.go.ke", "ecitizen.go.ke", "ntsa.go.ke", "nhif.or.ke",
        "nssf.or.ke", "nation.africa", "standardmedia.co.ke", "citizen.digital"
    ]
}

# URL shortener services
URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "shorte.st", "bc.vc", "j.mp", "v.gd", "rb.gy", "cutt.ly"
]

# Homograph characters (lookalikes)
HOMOGRAPH_MAP = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x',  # Cyrillic
    'і': 'i', 'ѕ': 's', 'ј': 'j', 'һ': 'h', 'ԁ': 'd', 'ɡ': 'g',  # Various
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '8': 'b',  # Numbers
    '@': 'a', '$': 's', '!': 'i',  # Symbols
}

# Common brand typosquatting targets
BRAND_TARGETS = [
    "safaricom", "mpesa", "equity", "kcb", "google", "facebook", "microsoft",
    "apple", "amazon", "paypal", "netflix", "whatsapp", "instagram", "twitter"
]

# ==================== MODELS ====================

class AnalysisRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=MAX_CONTENT_LENGTH)
    content_type: str = Field(default="email", pattern="^(email|sms|url)$")
    
    @validator('content')
    def sanitize_content(cls, v):
        return sanitize_input(v)
    
    @validator('content_type')
    def validate_content_type(cls, v):
        allowed = ['email', 'sms', 'url']
        if v.lower() not in allowed:
            raise ValueError(f'content_type must be one of: {allowed}')
        return v.lower()

class ThreatIndicator(BaseModel):
    category: str
    description: str
    severity: str  # low, medium, high, critical
    matched_text: Optional[str] = None
    confidence: float = 1.0

class AnalysisResponse(BaseModel):
    classification: str
    confidence_score: float
    risk_level: str
    threat_indicators: List[ThreatIndicator]
    explanation: str
    recommendations: List[str]
    analysis_details: Optional[Dict] = None

# ==================== ADVANCED ANALYSIS FUNCTIONS ====================

def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of text to detect random strings"""
    if not text:
        return 0.0
    freq = Counter(text.lower())
    length = len(text)
    entropy = -sum((count/length) * math.log2(count/length) for count in freq.values())
    return entropy

def detect_homograph_attack(domain: str) -> Optional[str]:
    """Detect homograph/lookalike character attacks"""
    normalized = domain.lower()
    original = normalized
    
    for fake, real in HOMOGRAPH_MAP.items():
        normalized = normalized.replace(fake, real)
    
    if normalized != original:
        return f"Contains lookalike characters: {original} -> {normalized}"
    return None

def detect_typosquatting(domain: str) -> Optional[str]:
    """Detect typosquatting attempts"""
    domain_lower = domain.lower().split('.')[0]
    
    for brand in BRAND_TARGETS:
        # Check for common typo patterns
        if brand == domain_lower:
            continue
            
        # Missing character
        for i in range(len(brand)):
            if brand[:i] + brand[i+1:] == domain_lower:
                return f"Possible typosquatting of '{brand}' (missing character)"
        
        # Swapped characters
        for i in range(len(brand) - 1):
            swapped = brand[:i] + brand[i+1] + brand[i] + brand[i+2:]
            if swapped == domain_lower:
                return f"Possible typosquatting of '{brand}' (swapped characters)"
        
        # Added character
        for i in range(len(domain_lower)):
            if domain_lower[:i] + domain_lower[i+1:] == brand:
                return f"Possible typosquatting of '{brand}' (extra character)"
        
        # Character substitution (common mistakes)
        substitutions = [('o', '0'), ('l', '1'), ('i', '1'), ('s', '5'), ('a', '4')]
        for orig, sub in substitutions:
            if brand.replace(orig, sub) == domain_lower or brand.replace(sub, orig) == domain_lower:
                return f"Possible typosquatting of '{brand}' (character substitution)"
                
        # Brand name with suspicious additions
        if brand in domain_lower and domain_lower != brand:
            suspicious_additions = ['secure', 'login', 'verify', 'update', 'account', 'support', 'help', 'service']
            for addition in suspicious_additions:
                if addition in domain_lower:
                    return f"Suspicious domain combining '{brand}' with '{addition}'"
    
    return None

def extract_urls(text: str) -> List[str]:
    """Extract URLs from text with better pattern matching"""
    patterns = [
        r'https?://[^\s<>"\'{}|\\^`\[\]]+',
        r'www\.[^\s<>"\'{}|\\^`\[\]]+',
        r'[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:/[^\s<>"\']*)?'
    ]
    urls = []
    for pattern in patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        urls.extend(matches)
    return list(set(urls))

def analyze_url_advanced(url: str) -> List[ThreatIndicator]:
    """Advanced URL analysis"""
    indicators = []
    
    try:
        # Normalize URL
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = unquote(parsed.path.lower())
        
        # Check for IP address
        if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
            indicators.append(ThreatIndicator(
                category="Suspicious URL",
                description="URL uses IP address instead of domain name",
                severity="high",
                matched_text=domain,
                confidence=0.9
            ))
        
        # Check for URL shorteners
        for shortener in URL_SHORTENERS:
            if shortener in domain:
                indicators.append(ThreatIndicator(
                    category="URL Shortener",
                    description=f"Shortened URL detected ({shortener}) - destination unknown",
                    severity="medium",
                    matched_text=url[:80],
                    confidence=0.7
                ))
                break
        
        # Check for suspicious TLDs
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                indicators.append(ThreatIndicator(
                    category="Suspicious TLD",
                    description=f"Domain uses suspicious TLD: {tld}",
                    severity="high",
                    matched_text=domain,
                    confidence=0.85
                ))
                break
        
        # Check for homograph attacks
        homograph = detect_homograph_attack(domain)
        if homograph:
            indicators.append(ThreatIndicator(
                category="Homograph Attack",
                description=homograph,
                severity="critical",
                matched_text=domain,
                confidence=0.95
            ))
        
        # Check for typosquatting
        typosquat = detect_typosquatting(domain)
        if typosquat:
            indicators.append(ThreatIndicator(
                category="Typosquatting",
                description=typosquat,
                severity="critical",
                matched_text=domain,
                confidence=0.9
            ))
        
        # Check for brand impersonation in subdomain
        for brand in BRAND_TARGETS:
            if brand in domain:
                # Get base domain
                parts = domain.split('.')
                if len(parts) >= 2:
                    base = parts[-2] + '.' + parts[-1]
                    # Check if brand is in subdomain but not in base domain
                    if brand not in base and brand in domain:
                        indicators.append(ThreatIndicator(
                            category="Domain Spoofing",
                            description=f"Brand '{brand}' used in subdomain to appear legitimate",
                            severity="high",
                            matched_text=domain,
                            confidence=0.85
                        ))
        
        # Check for suspicious path patterns
        suspicious_paths = [
            (r'/login', "Login page in URL"),
            (r'/verify', "Verification page"),
            (r'/secure', "Claims to be secure"),
            (r'/account', "Account-related path"),
            (r'/update', "Update-related path"),
            (r'/confirm', "Confirmation path"),
            (r'/\.php\?', "PHP with parameters"),
            (r'/wp-admin', "WordPress admin path"),
            (r'/\.exe|\.scr|\.bat', "Executable file"),
        ]
        
        for pattern, desc in suspicious_paths:
            if re.search(pattern, path, re.IGNORECASE):
                indicators.append(ThreatIndicator(
                    category="Suspicious Path",
                    description=desc,
                    severity="medium",
                    matched_text=path[:50],
                    confidence=0.6
                ))
        
        # Check URL entropy (random strings often indicate phishing)
        if len(domain) > 15:
            entropy = calculate_entropy(domain.replace('.', ''))
            if entropy > 3.5:
                indicators.append(ThreatIndicator(
                    category="Suspicious Domain",
                    description="Domain appears randomly generated",
                    severity="medium",
                    matched_text=domain,
                    confidence=0.7
                ))
        
        # Check for excessive subdomains
        subdomain_count = domain.count('.') - 1
        if subdomain_count >= 3:
            indicators.append(ThreatIndicator(
                category="Suspicious Structure",
                description=f"Excessive subdomains ({subdomain_count + 1} levels)",
                severity="medium",
                matched_text=domain,
                confidence=0.65
            ))
        
        # Check against legitimate domains (potential spoofing)
        all_legit = LEGITIMATE_DOMAINS["global"] + LEGITIMATE_DOMAINS["kenya"]
        for legit in all_legit:
            legit_name = legit.split('.')[0]
            if legit_name in domain and legit not in domain:
                indicators.append(ThreatIndicator(
                    category="Domain Spoofing",
                    description=f"Possible spoofed domain mimicking {legit}",
                    severity="critical",
                    matched_text=domain,
                    confidence=0.9
                ))
                break
                
    except Exception as e:
        pass
    
    return indicators

def check_kenya_targets(text: str) -> List[ThreatIndicator]:
    """Check for Kenya-specific phishing targets"""
    indicators = []
    text_lower = text.lower()
    
    for category, keywords in KENYA_TARGETS.items():
        for keyword in keywords:
            if keyword in text_lower:
                # Check if combined with credential request
                credential_request = any(
                    re.search(pattern, text_lower) 
                    for patterns in CREDENTIAL_PATTERNS.values() 
                    for pattern in patterns
                )
                
                severity = "critical" if credential_request else "medium"
                
                indicators.append(ThreatIndicator(
                    category=f"Kenya Target ({category.title()})",
                    description=f"References '{keyword}'" + 
                               (" with credential request" if credential_request else ""),
                    severity=severity,
                    matched_text=keyword,
                    confidence=0.8 if credential_request else 0.5
                ))
                break  # One per category
    
    return indicators

def check_urgency_advanced(text: str) -> List[ThreatIndicator]:
    """Enhanced urgency detection with severity levels"""
    indicators = []
    text_lower = text.lower()
    
    for severity, patterns in URGENCY_PATTERNS.items():
        for pattern in patterns:
            if pattern in text_lower:
                indicators.append(ThreatIndicator(
                    category="Urgency Language",
                    description=f"Creates pressure with: '{pattern}'",
                    severity=severity,
                    matched_text=pattern,
                    confidence=0.85 if severity == "critical" else 0.7
                ))
    
    # Check for countdown/time pressure
    time_patterns = [
        (r'\d+\s*(hours?|minutes?|mins?)\s*(left|remaining)', "Time countdown"),
        (r'expires?\s+(in\s+)?\d+', "Expiration time"),
        (r'deadline\s*:?\s*\d+', "Deadline mentioned")
    ]
    
    for pattern, desc in time_patterns:
        match = re.search(pattern, text_lower)
        if match:
            indicators.append(ThreatIndicator(
                category="Time Pressure",
                description=desc,
                severity="high",
                matched_text=match.group(0),
                confidence=0.8
            ))
    
    return indicators

def check_credential_patterns(text: str) -> List[ThreatIndicator]:
    """Enhanced credential harvesting detection"""
    indicators = []
    text_lower = text.lower()
    
    for severity, patterns in CREDENTIAL_PATTERNS.items():
        for pattern in patterns:
            match = re.search(pattern, text_lower)
            if match:
                indicators.append(ThreatIndicator(
                    category="Credential Harvesting",
                    description=f"Requests sensitive data: '{match.group(0)}'",
                    severity=severity,
                    matched_text=match.group(0),
                    confidence=0.95 if severity == "critical" else 0.85
                ))
    
    return indicators

def check_threat_patterns(text: str) -> List[ThreatIndicator]:
    """Enhanced threat detection"""
    indicators = []
    text_lower = text.lower()
    
    for severity, patterns in THREAT_PATTERNS.items():
        for pattern in patterns:
            match = re.search(pattern, text_lower)
            if match:
                indicators.append(ThreatIndicator(
                    category="Threatening Language",
                    description=f"Threatens: '{match.group(0)}'",
                    severity=severity,
                    matched_text=match.group(0),
                    confidence=0.9 if severity == "critical" else 0.75
                ))
    
    return indicators

def check_suspicious_patterns(text: str, content_type: str) -> List[ThreatIndicator]:
    """Check for general suspicious patterns"""
    indicators = []
    text_lower = text.lower()
    
    # Generic greetings (sign of mass phishing)
    generic_greetings = [
        (r"dear\s+(customer|user|member|valued\s+customer|account\s+holder|client)", "Generic greeting"),
        (r"(hello|hi)\s+(there|user|customer)", "Impersonal greeting"),
    ]
    
    for pattern, desc in generic_greetings:
        if re.search(pattern, text_lower):
            indicators.append(ThreatIndicator(
                category="Suspicious Phrasing",
                description=desc,
                severity="low",
                matched_text=re.search(pattern, text_lower).group(0),
                confidence=0.5
            ))
    
    # Call to action patterns
    cta_patterns = [
        (r"click\s+(here|below|this\s+link)\s+to", "Direct click instruction"),
        (r"(tap|press)\s+(here|the\s+link|button)", "Direct action instruction"),
        (r"follow\s+this\s+link", "Link following instruction"),
    ]
    
    for pattern, desc in cta_patterns:
        if re.search(pattern, text_lower):
            indicators.append(ThreatIndicator(
                category="Suspicious CTA",
                description=desc,
                severity="medium",
                matched_text=re.search(pattern, text_lower).group(0),
                confidence=0.6
            ))
    
    # SMS-specific patterns
    if content_type == "sms":
        sms_patterns = [
            (r"(reply|send)\s+(with\s+)?(your\s+)?(\d+|pin|code)", "SMS reply with code request"),
            (r"call\s+(this\s+)?number\s*:?\s*\d+", "Call back scam indicator"),
            (r"(won|winner|prize|lottery|jackpot)", "Prize scam indicator"),
            (r"(free|bonus|reward|gift)\s+(mpesa|money|cash|ksh)", "Free money scam"),
        ]
        
        for pattern, desc in sms_patterns:
            match = re.search(pattern, text_lower)
            if match:
                indicators.append(ThreatIndicator(
                    category="SMS Scam Pattern",
                    description=desc,
                    severity="high",
                    matched_text=match.group(0),
                    confidence=0.85
                ))
    
    # Email-specific patterns
    if content_type == "email":
        # Check for reply-to mismatch hint
        if "reply to" in text_lower and "@" in text_lower:
            indicators.append(ThreatIndicator(
                category="Email Pattern",
                description="Contains explicit reply-to instruction",
                severity="low",
                matched_text="reply to",
                confidence=0.4
            ))
    
    # Money/financial patterns
    money_patterns = [
        (r"(transfer|send|deposit)\s+(ksh|kes|usd|\$|shillings?)\s*[\d,]+", "Money transfer request"),
        (r"(receive|claim|get)\s+(ksh|kes|usd|\$|shillings?)\s*[\d,]+", "Money claim bait"),
        (r"(fee|charge|payment)\s+of\s+(ksh|kes|\$)?\s*[\d,]+", "Fee payment request"),
    ]
    
    for pattern, desc in money_patterns:
        match = re.search(pattern, text_lower)
        if match:
            indicators.append(ThreatIndicator(
                category="Financial Request",
                description=desc,
                severity="high",
                matched_text=match.group(0),
                confidence=0.8
            ))
    
    return indicators

def check_link_text_mismatch(text: str) -> List[ThreatIndicator]:
    """Detect when link text doesn't match actual URL"""
    indicators = []
    
    # Pattern: [visible text](actual url) or <a href="url">text</a>
    markdown_pattern = r'\[([^\]]+)\]\(([^)]+)\)'
    html_pattern = r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>([^<]+)</a>'
    
    for pattern in [markdown_pattern]:
        matches = re.findall(pattern, text, re.IGNORECASE)
        for match in matches:
            visible_text = match[0].lower()
            actual_url = match[1].lower()
            
            # Check if visible text looks like a URL but differs from actual
            if re.match(r'https?://', visible_text) or 'www.' in visible_text:
                if visible_text not in actual_url and actual_url not in visible_text:
                    indicators.append(ThreatIndicator(
                        category="Link Mismatch",
                        description="Displayed URL differs from actual destination",
                        severity="critical",
                        matched_text=f"Shows: {visible_text[:30]}... Links to: {actual_url[:30]}...",
                        confidence=0.95
                    ))
    
    return indicators

def calculate_risk_score(indicators: List[ThreatIndicator]) -> tuple:
    """Calculate weighted risk score based on indicators"""
    if not indicators:
        return 0.0, "safe", "low"
    
    # Severity weights
    weights = {
        "critical": 0.35,
        "high": 0.25,
        "medium": 0.12,
        "low": 0.05
    }
    
    # Calculate weighted score
    total_score = 0.0
    for indicator in indicators:
        weight = weights.get(indicator.severity, 0.05)
        total_score += weight * indicator.confidence
    
    # Normalize score (cap at 1.0)
    score = min(1.0, total_score)
    
    # Boost score for critical + credential combination
    has_critical = any(i.severity == "critical" for i in indicators)
    has_credential = any("credential" in i.category.lower() for i in indicators)
    
    if has_critical and has_credential:
        score = min(1.0, score * 1.3)
    
    # Determine classification and risk level
    if score >= 0.5:
        classification = "phishing"
        risk_level = "critical" if score >= 0.75 else "high"
    elif score >= 0.25:
        classification = "suspicious"
        risk_level = "medium"
    else:
        classification = "safe"
        risk_level = "low"
    
    return round(score, 3), classification, risk_level

def generate_explanation(indicators: List[ThreatIndicator], classification: str, content_type: str) -> str:
    """Generate detailed explanation"""
    if not indicators:
        return f"This {content_type} appears to be legitimate. No phishing indicators were detected."
    
    # Count by severity
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    categories = set()
    
    for ind in indicators:
        severity_counts[ind.severity] = severity_counts.get(ind.severity, 0) + 1
        categories.add(ind.category.split(" (")[0])
    
    if classification == "phishing":
        explanation = f"⚠️ PHISHING DETECTED: This {content_type} shows {len(indicators)} threat indicators. "
        if severity_counts["critical"] > 0:
            explanation += f"Found {severity_counts['critical']} critical issue(s). "
        explanation += f"Detected patterns: {', '.join(list(categories)[:4])}."
        
    elif classification == "suspicious":
        explanation = f"⚡ SUSPICIOUS: This {content_type} contains {len(indicators)} warning signs. "
        explanation += f"Detected: {', '.join(list(categories)[:3])}. Proceed with caution."
        
    else:
        explanation = f"✅ LOW RISK: This {content_type} has minor concerns ({len(indicators)} indicator(s)). "
        explanation += "Exercise normal caution."
    
    return explanation

def generate_recommendations(classification: str, indicators: List[ThreatIndicator]) -> List[str]:
    """Generate context-aware recommendations"""
    recommendations = []
    
    categories = set(i.category.split(" (")[0] for i in indicators)
    
    if classification == "phishing":
        recommendations = [
            "🚫 DO NOT click any links in this message",
            "🚫 DO NOT share any personal information or PINs",
            "🗑️ Delete this message immediately",
            "📱 If claiming to be M-Pesa/Bank, verify via official *334# or app",
        ]
        
        if any("credential" in c.lower() for c in categories):
            recommendations.append("🔒 If you shared any details, change your passwords NOW")
        
        if any("mpesa" in c.lower() or "kenya" in c.lower() for c in categories):
            recommendations.append("📞 Contact Safaricom (100) or your bank directly to verify")
            
        recommendations.append("🚨 Report this to your bank's fraud desk")
        
    elif classification == "suspicious":
        recommendations = [
            "⚠️ Do not click links - verify sender through official channels",
            "📞 Call the official number (not from this message) to verify",
            "🔍 Check the sender's email/number carefully",
            "⏸️ Take your time - legitimate organizations don't create urgency",
        ]
        
    else:
        recommendations = [
            "Always verify sender identity for financial requests",
            "Don't share PINs or OTPs - banks never ask for these",
            "Use official apps and *USSD codes for transactions",
            "Report suspicious messages to 333 (Safaricom)",
        ]
    
    return recommendations[:6]

# ==================== MAIN ANALYSIS FUNCTION ====================

def analyze_content(content: str, content_type: str) -> AnalysisResponse:
    """Comprehensive content analysis"""
    
    all_indicators = []
    
    # Run all detection modules
    all_indicators.extend(check_urgency_advanced(content))
    all_indicators.extend(check_credential_patterns(content))
    all_indicators.extend(check_threat_patterns(content))
    all_indicators.extend(check_kenya_targets(content))
    all_indicators.extend(check_suspicious_patterns(content, content_type))
    all_indicators.extend(check_link_text_mismatch(content))
    
    # URL analysis
    urls = extract_urls(content)
    for url in urls[:5]:  # Limit URL checks
        all_indicators.extend(analyze_url_advanced(url))
    
    # If content_type is URL itself, analyze it
    if content_type == "url":
        all_indicators.extend(analyze_url_advanced(content))
    
    # Remove duplicates (by category + matched_text)
    seen = set()
    unique_indicators = []
    for ind in all_indicators:
        key = (ind.category, ind.matched_text)
        if key not in seen:
            seen.add(key)
            unique_indicators.append(ind)
    
    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    unique_indicators.sort(key=lambda x: (severity_order.get(x.severity, 4), -x.confidence))
    
    # Calculate score
    score, classification, risk_level = calculate_risk_score(unique_indicators)
    
    # Generate outputs
    explanation = generate_explanation(unique_indicators, classification, content_type)
    recommendations = generate_recommendations(classification, unique_indicators)
    
    # Analysis details
    analysis_details = {
        "urls_found": len(urls),
        "total_indicators": len(unique_indicators),
        "severity_breakdown": {
            "critical": sum(1 for i in unique_indicators if i.severity == "critical"),
            "high": sum(1 for i in unique_indicators if i.severity == "high"),
            "medium": sum(1 for i in unique_indicators if i.severity == "medium"),
            "low": sum(1 for i in unique_indicators if i.severity == "low")
        },
        "content_length": len(content),
        "analysis_version": "2.0"
    }
    
    return AnalysisResponse(
        classification=classification,
        confidence_score=score,
        risk_level=risk_level,
        threat_indicators=unique_indicators[:15],
        explanation=explanation,
        recommendations=recommendations,
        analysis_details=analysis_details
    )

# ==================== API ENDPOINTS ====================

@app.get("/")
async def root():
    return {
        "service": "PhishGuard ML Service",
        "version": "2.0.0",
        "status": "operational",
        "features": [
            "Advanced URL analysis",
            "Homograph attack detection",
            "Typosquatting detection",
            "Kenya-specific patterns",
            "Multi-severity scoring"
        ]
    }

@app.get("/health")
async def health_check():
    return {"status": "healthy", "version": "2.0.0"}

@app.post("/analyze", response_model=AnalysisResponse)
async def analyze(request: AnalysisRequest):
    """Analyze content for phishing indicators with enhanced accuracy"""
    # Additional runtime sanitization
    content = sanitize_input(request.content)
    content_type = request.content_type.lower()
    
    # Validate content is not empty after sanitization
    if not content.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Content cannot be empty"
        )
    
    return analyze_content(content, content_type)

@app.get("/patterns")
async def get_patterns():
    """Get list of detected patterns for educational purposes"""
    return {
        "urgency_keywords": URGENCY_PATTERNS["critical"] + URGENCY_PATTERNS["high"][:5],
        "credential_phrases": ["PIN", "OTP", "Password", "Bank details", "M-Pesa PIN"],
        "threat_phrases": THREAT_PATTERNS["critical"][:5],
        "kenya_targets": list(KENYA_TARGETS.keys()),
        "suspicious_tlds": SUSPICIOUS_TLDS[:10],
        "detection_capabilities": [
            "Homograph/lookalike character detection",
            "Typosquatting detection",
            "Domain spoofing detection",
            "URL shortener detection",
            "Kenya-specific scam patterns",
            "Financial request detection",
            "Time pressure detection"
        ]
    }

@app.get("/stats")
async def get_stats():
    """Get detection system statistics"""
    return {
        "total_patterns": {
            "urgency": sum(len(v) for v in URGENCY_PATTERNS.values()),
            "credentials": sum(len(v) for v in CREDENTIAL_PATTERNS.values()),
            "threats": sum(len(v) for v in THREAT_PATTERNS.values()),
            "kenya_targets": sum(len(v) for v in KENYA_TARGETS.values()),
            "brand_targets": len(BRAND_TARGETS),
            "suspicious_tlds": len(SUSPICIOUS_TLDS)
        },
        "legitimate_domains": {
            "global": len(LEGITIMATE_DOMAINS["global"]),
            "kenya": len(LEGITIMATE_DOMAINS["kenya"])
        },
        "version": "2.0.0"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
