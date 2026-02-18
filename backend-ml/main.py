"""
Phish Guard ML Service - Machine Learning Phishing & Smishing Detection
Real ML models with lexical features, SSL status, domain age analysis
"""

import os
import ssl
import socket
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Tuple, Any
import re
import math
import csv
import time
import html
from urllib.parse import urlparse, unquote
from collections import Counter, defaultdict
import hashlib
from functools import wraps
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from datetime import datetime
import logging

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

logger = logging.getLogger("threatlens")

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
    title="Phish Guard ML Service",
    description="Machine Learning phishing & smishing detection with lexical analysis, SSL validation, and domain age checking",
    version="3.0.0",
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
        "account will be closed", "permanent suspension", "final notice",
        "will be terminated", "will be deactivated", "must be verified",
        "your account will be", "failure to comply", "immediate action"
    ],
    "high": [
        "urgent", "act now", "expires today", "within 24 hours", "within 48 hours",
        "limited time", "last chance", "don't delay", "time sensitive",
        "respond immediately", "action needed", "verify now",
        "about to expire", "will expire", "is about to", "action required",
        "secure your account", "verify your", "confirm your", "update your",
        "alert", "warning", "detected", "unauthorized",
        "suspended", "suspended within", "unless you"
    ],
    "medium": [
        "soon", "quickly", "asap", "important", "attention required",
        "please respond", "awaiting your response", "pending action",
        "needs attention", "needs your attention", "security notice",
        "unusual activity", "new login", "unknown device",
        "limited-time", "limited time offer", "offer expires",
        "don't miss", "miss out", "once in a lifetime",
        "exclusive offer", "exclusive opportunity"
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
        r"(send|share|provide|submit|give)\s+(your\s+|us\s+)?(pin|password|otp|details|credentials)",
        r"social\s+security", r"id\s+number", r"passport\s+number",
        r"credit\s+card", r"debit\s+card", r"card\s+details",
        r"(submit|provide|send)\s+(your\s+)?details"
    ],
    "high": [
        r"enter\s+(your\s+)?password", r"confirm\s+(your\s+)?password",
        r"update\s+(your\s+)?password", r"reset\s+(your\s+)?password",
        r"login\s+credentials", r"banking\s+details", r"verification\s+code",
        r"one\s+time\s+password", r"otp", r"secret\s+code", r"security\s+code",
        r"mother'?s?\s+maiden", r"date\s+of\s+birth", r"full\s+name",
        r"payment\s+(details|information|method)", r"update\s+(your\s+)?payment",
        r"billing\s+(details|information|address)",
        r"(confirm|verify)\s+(your\s+)?(identity|details|information|payment)",
        r"confirm\s+payment", r"verify\s+your\s+details"
    ],
    "medium": [
        r"verify\s+(your\s+)?account", r"confirm\s+(your\s+)?identity",
        r"update\s+(your\s+)?(account|details|information)",
        r"personal\s+information", r"contact\s+details",
        r"verify\s+your", r"confirm\s+your", r"update\s+your",
        r"review.*invoice", r"open.*document", r"attached.*invoice",
        r"unclaimed", r"claim\s+(your|now|this)"
    ]
}

# Threatening language patterns
THREAT_PATTERNS = {
    "critical": [
        r"account\s+(will\s+be\s+)?(permanently\s+)?(suspended|terminated|blocked|closed|deactivated|locked)",
        r"will\s+be\s+suspended", r"will\s+be\s+closed", r"will\s+be\s+terminated",
        r"legal\s+action", r"(will\s+be\s+)?prosecuted", r"arrest\s+warrant",
        r"police\s+report", r"fraud\s+investigation",
        r"permanently\s+(delete|remove|block|suspend)"
    ],
    "high": [
        r"(will\s+be\s+)?(blocked|disabled|frozen|restricted|locked)",
        r"(will\s+)?lose\s+access", r"funds?\s+(will\s+be\s+)?lost",
        r"service\s+(will\s+be\s+)?discontinued", r"penalty", r"fine",
        r"subscription.{0,20}(expire|cancel|end)",
        r"(expire|expir|cancel).{0,15}(account|subscription|service|access)",
        r"about\s+to\s+expire", r"has\s+been\s+compromised",
        r"detected.{0,30}(suspicious|unusual|unauthorized)",
        r"(suspicious|unusual|unauthorized).{0,30}(activity|access|login|transaction)",
        r"on\s+hold"
    ],
    "medium": [
        r"unauthorized\s+access", r"suspicious\s+activity", r"security\s+breach",
        r"compromised", r"at\s+risk", r"security\s+needs\s+attention",
        r"someone\s+may\s+have", r"new\s+login", r"unknown\s+device",
        r"unusual\s+sign.?in"
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

# ==================== ML FEATURE EXTRACTION ====================

class LexicalFeatureExtractor:
    """Extract lexical features from URLs for ML classification"""
    
    @staticmethod
    def extract_url_features(url: str) -> Dict[str, float]:
        """Extract numerical features from a URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        try:
            parsed = urlparse(url)
        except Exception:
            return LexicalFeatureExtractor._empty_url_features()
        
        domain = parsed.netloc.lower()
        path = parsed.path or ""
        query = parsed.query or ""
        
        # Remove port from domain
        domain_no_port = domain.split(':')[0] if ':' in domain else domain
        
        features = {
            # Length features
            "url_length": len(url),
            "domain_length": len(domain_no_port),
            "path_length": len(path),
            "query_length": len(query),
            
            # Count features
            "num_dots": domain_no_port.count('.'),
            "num_hyphens": domain_no_port.count('-'),
            "num_underscores": url.count('_'),
            "num_slashes": path.count('/'),
            "num_digits_domain": sum(c.isdigit() for c in domain_no_port),
            "num_digits_url": sum(c.isdigit() for c in url),
            "num_special_chars": sum(not c.isalnum() and c not in './-_:' for c in url),
            "num_params": query.count('&') + (1 if query else 0),
            "num_fragments": 1 if parsed.fragment else 0,
            
            # Ratio features
            "digit_ratio_domain": sum(c.isdigit() for c in domain_no_port) / max(len(domain_no_port), 1),
            "digit_ratio_url": sum(c.isdigit() for c in url) / max(len(url), 1),
            "special_char_ratio": sum(not c.isalnum() for c in url) / max(len(url), 1),
            
            # Structural features
            "subdomain_count": max(0, domain_no_port.count('.') - 1),
            "has_ip_address": 1.0 if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain_no_port) else 0.0,
            "has_https": 1.0 if parsed.scheme == 'https' else 0.0,
            "has_port": 1.0 if ':' in domain and not domain.startswith('[') else 0.0,
            "has_at_symbol": 1.0 if '@' in url else 0.0,
            "has_double_slash_redirect": 1.0 if '//' in path else 0.0,
            
            # TLD features
            "suspicious_tld": 1.0 if any(domain_no_port.endswith(tld) for tld in SUSPICIOUS_TLDS) else 0.0,
            "tld_length": len(domain_no_port.split('.')[-1]) if '.' in domain_no_port else 0,
            
            # Entropy
            "domain_entropy": LexicalFeatureExtractor._entropy(domain_no_port.replace('.', '')),
            "url_entropy": LexicalFeatureExtractor._entropy(url),
            "path_entropy": LexicalFeatureExtractor._entropy(path),
            
            # Brand similarity
            "contains_brand_name": 1.0 if any(b in domain_no_port for b in BRAND_TARGETS) else 0.0,
            "brand_in_subdomain": LexicalFeatureExtractor._brand_in_subdomain(domain_no_port),
            
            # Suspicious keywords in path
            "login_in_path": 1.0 if 'login' in path.lower() else 0.0,
            "verify_in_path": 1.0 if 'verify' in path.lower() else 0.0,
            "secure_in_path": 1.0 if 'secure' in path.lower() else 0.0,
            "account_in_path": 1.0 if 'account' in path.lower() else 0.0,
            "update_in_path": 1.0 if 'update' in path.lower() else 0.0,
            
            # URL shortener
            "is_shortened": 1.0 if any(s in domain for s in URL_SHORTENERS) else 0.0,
        }
        
        return features
    
    @staticmethod
    def _entropy(text: str) -> float:
        if not text:
            return 0.0
        freq = Counter(text.lower())
        length = len(text)
        return -sum((c / length) * math.log2(c / length) for c in freq.values())
    
    @staticmethod
    def _brand_in_subdomain(domain: str) -> float:
        parts = domain.split('.')
        if len(parts) < 3:
            return 0.0
        subdomain = '.'.join(parts[:-2])
        return 1.0 if any(b in subdomain for b in BRAND_TARGETS) else 0.0
    
    @staticmethod
    def _empty_url_features() -> Dict[str, float]:
        return {k: 0.0 for k in [
            "url_length", "domain_length", "path_length", "query_length",
            "num_dots", "num_hyphens", "num_underscores", "num_slashes",
            "num_digits_domain", "num_digits_url", "num_special_chars",
            "num_params", "num_fragments", "digit_ratio_domain", "digit_ratio_url",
            "special_char_ratio", "subdomain_count", "has_ip_address", "has_https",
            "has_port", "has_at_symbol", "has_double_slash_redirect",
            "suspicious_tld", "tld_length", "domain_entropy", "url_entropy",
            "path_entropy", "contains_brand_name", "brand_in_subdomain",
            "login_in_path", "verify_in_path", "secure_in_path",
            "account_in_path", "update_in_path", "is_shortened"
        ]}


class TextFeatureExtractor:
    """Extract NLP features from SMS/email text for ML classification"""
    
    URGENCY_WORDS = [
        "urgent", "immediately", "now", "hurry", "quick", "fast", "asap",
        "limited", "expires", "deadline", "suspend", "block", "close",
        "terminate", "final", "last", "warning", "alert", "expire",
        "detected", "unauthorized", "compromised", "locked", "restricted",
        "disabled", "frozen", "deactivated", "attention", "important",
        "action", "required", "verify", "confirm", "update", "secure"
    ]
    
    CREDENTIAL_WORDS = [
        "pin", "password", "otp", "code", "verify", "confirm", "login",
        "credential", "account", "bank", "cvv", "ssn", "identity",
        "payment", "billing", "card", "details", "information",
        "submit", "provide", "share", "enter", "click", "link",
        "invoice", "document", "attached", "review", "receipt"
    ]
    
    THREAT_WORDS = [
        "suspend", "block", "close", "terminate", "prosecute", "arrest",
        "legal", "penalty", "fine", "fraud", "unauthorized", "breach",
        "compromise", "lock", "disable", "freeze", "restrict", "expire",
        "cancel", "delete", "lost", "risk", "hold", "deactivate"
    ]
    
    REWARD_WORDS = [
        "win", "won", "winner", "prize", "lottery", "jackpot", "free",
        "bonus", "reward", "gift", "congratulations", "lucky", "selected",
        "claim", "unclaimed", "refund", "cashback", "voucher", "coupon"
    ]
    
    @staticmethod
    def extract_text_features(text: str, content_type: str = "email") -> Dict[str, float]:
        """Extract numerical features from text content"""
        text_lower = text.lower()
        words = re.findall(r'\b\w+\b', text_lower)
        sentences = re.split(r'[.!?]+', text)
        sentences = [s.strip() for s in sentences if s.strip()]
        
        features = {
            # Length features
            "text_length": len(text),
            "word_count": len(words),
            "unique_word_count": len(set(words)),
            "avg_word_length": np.mean([len(w) for w in words]) if words else 0,
            "max_word_length": max([len(w) for w in words]) if words else 0,
            "sentence_count": len(sentences),
            "avg_sentence_length": np.mean([len(s.split()) for s in sentences]) if sentences else 0,
            
            # Character features
            "caps_ratio": sum(1 for c in text if c.isupper()) / max(len(text), 1),
            "digit_ratio": sum(1 for c in text if c.isdigit()) / max(len(text), 1),
            "special_char_ratio": sum(1 for c in text if not c.isalnum() and not c.isspace()) / max(len(text), 1),
            "whitespace_ratio": sum(1 for c in text if c.isspace()) / max(len(text), 1),
            
            # Punctuation features
            "exclamation_count": text.count('!'),
            "question_mark_count": text.count('?'),
            "ellipsis_count": text.count('...'),
            "dollar_sign_count": text.count('$') + text_lower.count('ksh') + text_lower.count('kes'),
            
            # Keyword density features
            "urgency_word_count": sum(1 for w in words if w in TextFeatureExtractor.URGENCY_WORDS),
            "credential_word_count": sum(1 for w in words if w in TextFeatureExtractor.CREDENTIAL_WORDS),
            "threat_word_count": sum(1 for w in words if w in TextFeatureExtractor.THREAT_WORDS),
            "reward_word_count": sum(1 for w in words if w in TextFeatureExtractor.REWARD_WORDS),
            
            "urgency_density": sum(1 for w in words if w in TextFeatureExtractor.URGENCY_WORDS) / max(len(words), 1),
            "credential_density": sum(1 for w in words if w in TextFeatureExtractor.CREDENTIAL_WORDS) / max(len(words), 1),
            "threat_density": sum(1 for w in words if w in TextFeatureExtractor.THREAT_WORDS) / max(len(words), 1),
            "reward_density": sum(1 for w in words if w in TextFeatureExtractor.REWARD_WORDS) / max(len(words), 1),
            
            # URL features in text
            "url_count": len(re.findall(r'https?://\S+|www\.\S+', text)),
            "has_ip_url": 1.0 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', text) else 0.0,
            
            # Contact features
            "phone_number_count": len(re.findall(r'(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}', text)),
            "email_address_count": len(re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text)),
            
            # Structural features
            "has_greeting": 1.0 if re.search(r'\b(dear|hello|hi|hey)\b', text_lower) else 0.0,
            "has_generic_greeting": 1.0 if re.search(r'dear\s+(customer|user|member|valued|sir|madam)', text_lower) else 0.0,
            "has_signature": 1.0 if re.search(r'(regards|sincerely|thank you|best wishes)', text_lower) else 0.0,
            "has_click_instruction": 1.0 if re.search(r'click\s+(here|below|this|the\s+link)', text_lower) else 0.0,
            
            # Text entropy
            "text_entropy": TextFeatureExtractor._entropy(text_lower),
            "word_entropy": TextFeatureExtractor._entropy(' '.join(words)),
            
            # Vocabulary richness
            "vocabulary_richness": len(set(words)) / max(len(words), 1),
            
            # Content type indicator
            "is_sms": 1.0 if content_type == "sms" else 0.0,
            "is_email": 1.0 if content_type == "email" else 0.0,
        }
        
        return features
    
    @staticmethod
    def _entropy(text: str) -> float:
        if not text:
            return 0.0
        freq = Counter(text)
        length = len(text)
        return -sum((c / length) * math.log2(c / length) for c in freq.values())


class SSLChecker:
    """Check SSL/TLS certificate status of domains"""
    
    @staticmethod
    def check_ssl(url: str, timeout: int = 3) -> Dict[str, any]:
        """Check SSL certificate status for a URL"""
        result = {
            "has_ssl": False,
            "ssl_valid": False,
            "ssl_issuer": None,
            "ssl_expiry_days": None,
            "ssl_version": None,
            "ssl_score": 0.0  # 0 = no SSL, 0.5 = SSL but issues, 1.0 = valid SSL
        }
        
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            parsed = urlparse(url)
            hostname = parsed.netloc.split(':')[0]
            port = 443
            
            if not hostname:
                return result
            
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    result["has_ssl"] = True
                    result["ssl_valid"] = True
                    result["ssl_version"] = ssock.version()
                    
                    # Extract issuer
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    result["ssl_issuer"] = issuer.get('organizationName', 'Unknown')
                    
                    # Check expiry
                    not_after = cert.get('notAfter', '')
                    if not_after:
                        expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        days_left = (expiry - datetime.utcnow()).days
                        result["ssl_expiry_days"] = days_left
                        
                        if days_left > 30:
                            result["ssl_score"] = 1.0
                        elif days_left > 0:
                            result["ssl_score"] = 0.7
                        else:
                            result["ssl_score"] = 0.2
                            result["ssl_valid"] = False
                    else:
                        result["ssl_score"] = 0.8
                        
        except ssl.SSLCertVerificationError:
            result["has_ssl"] = True
            result["ssl_valid"] = False
            result["ssl_score"] = 0.2
        except (socket.timeout, socket.error, OSError):
            # Could not connect - might be HTTP only
            result["ssl_score"] = 0.0
        except Exception as e:
            logger.debug(f"SSL check error: {e}")
            result["ssl_score"] = 0.0
        
        return result


class DomainAgeChecker:
    """Check domain registration age"""
    
    @staticmethod
    def check_domain_age(url: str) -> Dict[str, any]:
        """Check domain age via WHOIS lookup"""
        result = {
            "domain_age_days": None,
            "registration_date": None,
            "registrar": None,
            "domain_age_score": 0.5  # Default neutral score
        }
        
        if not WHOIS_AVAILABLE:
            return result
        
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            parsed = urlparse(url)
            domain = parsed.netloc.split(':')[0]
            
            if not domain or re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
                result["domain_age_score"] = 0.1  # IP addresses are suspicious
                return result
            
            # Get root domain
            parts = domain.split('.')
            if len(parts) > 2:
                domain = '.'.join(parts[-2:])
            
            w = whois.whois(domain)
            
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if creation_date:
                if isinstance(creation_date, str):
                    creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
                
                age_days = (datetime.utcnow() - creation_date).days
                result["domain_age_days"] = age_days
                result["registration_date"] = creation_date.strftime('%Y-%m-%d')
                
                # Score based on age
                if age_days > 365 * 2:  # > 2 years
                    result["domain_age_score"] = 1.0
                elif age_days > 365:  # > 1 year
                    result["domain_age_score"] = 0.8
                elif age_days > 180:  # > 6 months
                    result["domain_age_score"] = 0.6
                elif age_days > 30:  # > 1 month
                    result["domain_age_score"] = 0.3
                else:  # Very new domain
                    result["domain_age_score"] = 0.1
            
            if w.registrar:
                result["registrar"] = str(w.registrar)
                
        except Exception as e:
            logger.debug(f"WHOIS lookup error: {e}")
        
        return result


class PhishingMLModel:
    """Machine Learning model for phishing detection using Random Forest + Gradient Boosting ensemble"""
    
    def __init__(self):
        self.url_model = None
        self.text_model = None
        self.url_scaler = StandardScaler()
        self.text_scaler = StandardScaler()
        self.url_feature_names = []
        self.text_feature_names = []
        self._train_models()
    
    def _train_models(self):
        """Train models on synthetic data derived from known phishing patterns"""
        self._train_url_model()
        self._train_text_model()
        logger.info("ML models trained successfully")
    
    def _train_url_model(self):
        """Train URL classification model using real phishing URL dataset"""
        dataset_path = os.path.join(os.path.dirname(__file__), "datasets", "phishing_urls.csv")
        
        legit_features = []
        phish_features = []
        
        try:
            with open(dataset_path, "r") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    url = row["url"].strip()
                    label = row["label"].strip().lower()
                    
                    try:
                        features = LexicalFeatureExtractor.extract_url_features(url)
                        if label == "legitimate":
                            legit_features.append(features)
                        elif label == "phishing":
                            phish_features.append(features)
                    except Exception:
                        continue
            
            logger.info(f"URL dataset loaded: {len(legit_features)} legitimate, {len(phish_features)} phishing URLs")
        except FileNotFoundError:
            logger.warning(f"URL dataset not found at {dataset_path}, falling back to synthetic data")
            self._train_url_model_synthetic()
            return
        
        if len(legit_features) < 10 or len(phish_features) < 10:
            logger.warning("Insufficient URL dataset samples, falling back to synthetic data")
            self._train_url_model_synthetic()
            return
        
        self.url_feature_names = sorted(legit_features[0].keys())
        
        X_legit = np.array([[f.get(k, 0.0) for k in self.url_feature_names] for f in legit_features])
        X_phish = np.array([[f.get(k, 0.0) for k in self.url_feature_names] for f in phish_features])
        
        X = np.vstack([X_legit, X_phish])
        y = np.array([0] * len(legit_features) + [1] * len(phish_features))
        
        # Shuffle
        np.random.seed(42)
        indices = np.random.permutation(len(X))
        X, y = X[indices], y[indices]
        
        # Scale
        X_scaled = self.url_scaler.fit_transform(X)
        
        # Train Random Forest
        self.url_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            min_samples_split=5,
            random_state=42,
            n_jobs=-1
        )
        self.url_model.fit(X_scaled, y)
        logger.info(f"URL model trained on {len(X)} real samples")
    
    def _train_url_model_synthetic(self):
        """Fallback: Train URL model with synthetic data if dataset unavailable"""
        np.random.seed(42)
        n_legit = 500
        n_phish = 500
        
        # Generate synthetic legitimate URL features
        legit_features = []
        for _ in range(n_legit):
            f = {
                "url_length": np.random.normal(45, 15),
                "domain_length": np.random.normal(12, 4),
                "path_length": np.random.normal(15, 10),
                "query_length": np.random.normal(5, 8),
                "num_dots": np.random.choice([1, 2, 3], p=[0.5, 0.35, 0.15]),
                "num_hyphens": np.random.choice([0, 1], p=[0.8, 0.2]),
                "num_underscores": 0,
                "num_slashes": np.random.choice([1, 2, 3], p=[0.4, 0.4, 0.2]),
                "num_digits_domain": np.random.choice([0, 1, 2], p=[0.7, 0.2, 0.1]),
                "num_digits_url": np.random.poisson(2),
                "num_special_chars": np.random.choice([0, 1, 2], p=[0.6, 0.3, 0.1]),
                "num_params": np.random.choice([0, 1, 2], p=[0.5, 0.35, 0.15]),
                "num_fragments": np.random.choice([0, 1], p=[0.85, 0.15]),
                "digit_ratio_domain": np.random.uniform(0, 0.1),
                "digit_ratio_url": np.random.uniform(0, 0.15),
                "special_char_ratio": np.random.uniform(0.05, 0.15),
                "subdomain_count": np.random.choice([0, 1], p=[0.6, 0.4]),
                "has_ip_address": 0,
                "has_https": np.random.choice([0, 1], p=[0.15, 0.85]),
                "has_port": 0,
                "has_at_symbol": 0,
                "has_double_slash_redirect": 0,
                "suspicious_tld": 0,
                "tld_length": np.random.choice([2, 3, 4], p=[0.3, 0.5, 0.2]),
                "domain_entropy": np.random.normal(3.0, 0.5),
                "url_entropy": np.random.normal(3.8, 0.4),
                "path_entropy": np.random.normal(3.2, 0.6),
                "contains_brand_name": np.random.choice([0, 1], p=[0.7, 0.3]),
                "brand_in_subdomain": 0,
                "login_in_path": np.random.choice([0, 1], p=[0.9, 0.1]),
                "verify_in_path": 0,
                "secure_in_path": 0,
                "account_in_path": np.random.choice([0, 1], p=[0.85, 0.15]),
                "update_in_path": 0,
                "is_shortened": 0,
            }
            legit_features.append(f)
        
        # Generate synthetic phishing URL features
        phish_features = []
        for _ in range(n_phish):
            f = {
                "url_length": np.random.normal(80, 25),
                "domain_length": np.random.normal(22, 8),
                "path_length": np.random.normal(30, 15),
                "query_length": np.random.normal(15, 12),
                "num_dots": np.random.choice([2, 3, 4, 5], p=[0.2, 0.3, 0.3, 0.2]),
                "num_hyphens": np.random.choice([0, 1, 2, 3], p=[0.2, 0.3, 0.3, 0.2]),
                "num_underscores": np.random.choice([0, 1, 2], p=[0.5, 0.3, 0.2]),
                "num_slashes": np.random.choice([2, 3, 4, 5], p=[0.2, 0.3, 0.3, 0.2]),
                "num_digits_domain": np.random.choice([0, 1, 2, 3, 4], p=[0.1, 0.2, 0.3, 0.25, 0.15]),
                "num_digits_url": np.random.poisson(5),
                "num_special_chars": np.random.choice([1, 2, 3, 4], p=[0.2, 0.3, 0.3, 0.2]),
                "num_params": np.random.choice([0, 1, 2, 3], p=[0.2, 0.3, 0.3, 0.2]),
                "num_fragments": np.random.choice([0, 1], p=[0.6, 0.4]),
                "digit_ratio_domain": np.random.uniform(0.05, 0.35),
                "digit_ratio_url": np.random.uniform(0.1, 0.3),
                "special_char_ratio": np.random.uniform(0.1, 0.3),
                "subdomain_count": np.random.choice([1, 2, 3, 4], p=[0.2, 0.3, 0.3, 0.2]),
                "has_ip_address": np.random.choice([0, 1], p=[0.7, 0.3]),
                "has_https": np.random.choice([0, 1], p=[0.6, 0.4]),
                "has_port": np.random.choice([0, 1], p=[0.85, 0.15]),
                "has_at_symbol": np.random.choice([0, 1], p=[0.9, 0.1]),
                "has_double_slash_redirect": np.random.choice([0, 1], p=[0.8, 0.2]),
                "suspicious_tld": np.random.choice([0, 1], p=[0.4, 0.6]),
                "tld_length": np.random.choice([2, 3, 4, 5], p=[0.1, 0.3, 0.3, 0.3]),
                "domain_entropy": np.random.normal(3.8, 0.6),
                "url_entropy": np.random.normal(4.3, 0.4),
                "path_entropy": np.random.normal(3.8, 0.5),
                "contains_brand_name": np.random.choice([0, 1], p=[0.3, 0.7]),
                "brand_in_subdomain": np.random.choice([0, 1], p=[0.5, 0.5]),
                "login_in_path": np.random.choice([0, 1], p=[0.4, 0.6]),
                "verify_in_path": np.random.choice([0, 1], p=[0.5, 0.5]),
                "secure_in_path": np.random.choice([0, 1], p=[0.6, 0.4]),
                "account_in_path": np.random.choice([0, 1], p=[0.5, 0.5]),
                "update_in_path": np.random.choice([0, 1], p=[0.6, 0.4]),
                "is_shortened": np.random.choice([0, 1], p=[0.7, 0.3]),
            }
            phish_features.append(f)
        
        self.url_feature_names = sorted(legit_features[0].keys())
        
        X_legit = np.array([[f[k] for k in self.url_feature_names] for f in legit_features])
        X_phish = np.array([[f[k] for k in self.url_feature_names] for f in phish_features])
        
        X = np.vstack([X_legit, X_phish])
        y = np.array([0] * n_legit + [1] * n_phish)
        
        # Shuffle
        indices = np.random.permutation(len(X))
        X, y = X[indices], y[indices]
        
        # Scale
        X_scaled = self.url_scaler.fit_transform(X)
        
        # Train Random Forest
        self.url_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            min_samples_split=5,
            random_state=42,
            n_jobs=-1
        )
        self.url_model.fit(X_scaled, y)
    
    def _train_text_model(self):
        """Train text classification model using real SMS Spam Collection dataset"""
        dataset_path = os.path.join(os.path.dirname(__file__), "datasets", "sms_spam.csv")
        
        legit_features = []
        phish_features = []
        
        try:
            with open(dataset_path, "r", encoding="utf-8") as f:
                reader = csv.reader(f, delimiter="\t")
                for row in reader:
                    if len(row) < 2:
                        continue
                    label = row[0].strip().lower()
                    text = row[1].strip()
                    
                    if len(text) < 5:
                        continue
                    
                    try:
                        # Determine content type — SMS for short, email-like for longer
                        content_type = "sms" if len(text) < 300 else "email"
                        features = TextFeatureExtractor.extract_text_features(text, content_type)
                        
                        if label == "ham":
                            legit_features.append(features)
                        elif label == "spam":
                            phish_features.append(features)
                    except Exception:
                        continue
            
            logger.info(f"Text dataset loaded: {len(legit_features)} legitimate, {len(phish_features)} spam/phishing messages")
        except FileNotFoundError:
            logger.warning(f"Text dataset not found at {dataset_path}, falling back to synthetic data")
            self._train_text_model_synthetic()
            return
        
        if len(legit_features) < 10 or len(phish_features) < 10:
            logger.warning("Insufficient text dataset samples, falling back to synthetic data")
            self._train_text_model_synthetic()
            return
        
        self.text_feature_names = sorted(legit_features[0].keys())
        
        X_legit = np.array([[f.get(k, 0.0) for k in self.text_feature_names] for f in legit_features])
        X_phish = np.array([[f.get(k, 0.0) for k in self.text_feature_names] for f in phish_features])
        
        X = np.vstack([X_legit, X_phish])
        y = np.array([0] * len(legit_features) + [1] * len(phish_features))
        
        # Shuffle
        np.random.seed(42)
        indices = np.random.permutation(len(X))
        X, y = X[indices], y[indices]
        
        # Scale
        X_scaled = self.text_scaler.fit_transform(X)
        
        # Train Gradient Boosting
        self.text_model = GradientBoostingClassifier(
            n_estimators=150,
            max_depth=6,
            learning_rate=0.1,
            random_state=42
        )
        self.text_model.fit(X_scaled, y)
        logger.info(f"Text model trained on {len(X)} real samples")
    
    def _train_text_model_synthetic(self):
        """Fallback: Train text model with synthetic data if dataset unavailable"""
        np.random.seed(42)
        n_legit = 800
        n_phish = 800
        
        # Generate synthetic legitimate text features — clearly benign characteristics
        legit_features = []
        for _ in range(n_legit):
            f = {
                "text_length": np.random.normal(350, 150),
                "word_count": np.random.normal(55, 25),
                "unique_word_count": np.random.normal(45, 20),
                "avg_word_length": np.random.normal(4.8, 0.8),
                "max_word_length": np.random.normal(9, 2),
                "sentence_count": np.random.normal(6, 3),
                "avg_sentence_length": np.random.normal(12, 3),
                "caps_ratio": np.random.uniform(0.01, 0.06),
                "digit_ratio": np.random.uniform(0, 0.03),
                "special_char_ratio": np.random.uniform(0.01, 0.05),
                "whitespace_ratio": np.random.uniform(0.16, 0.22),
                "exclamation_count": np.random.choice([0, 1], p=[0.85, 0.15]),
                "question_mark_count": np.random.choice([0, 1, 2], p=[0.5, 0.35, 0.15]),
                "ellipsis_count": 0,
                "dollar_sign_count": 0,
                "urgency_word_count": np.random.choice([0, 1], p=[0.9, 0.1]),
                "credential_word_count": np.random.choice([0, 1], p=[0.92, 0.08]),
                "threat_word_count": 0,
                "reward_word_count": 0,
                "urgency_density": np.random.uniform(0, 0.01),
                "credential_density": np.random.uniform(0, 0.01),
                "threat_density": 0,
                "reward_density": 0,
                "url_count": np.random.choice([0, 1], p=[0.7, 0.3]),
                "has_ip_url": 0,
                "phone_number_count": np.random.choice([0, 1], p=[0.8, 0.2]),
                "email_address_count": np.random.choice([0, 1], p=[0.5, 0.5]),
                "has_greeting": np.random.choice([0, 1], p=[0.2, 0.8]),
                "has_generic_greeting": 0,
                "has_signature": np.random.choice([0, 1], p=[0.2, 0.8]),
                "has_click_instruction": 0,
                "text_entropy": np.random.normal(4.2, 0.2),
                "word_entropy": np.random.normal(4.5, 0.2),
                "vocabulary_richness": np.random.uniform(0.75, 0.95),
                "is_sms": np.random.choice([0, 1], p=[0.6, 0.4]),
                "is_email": np.random.choice([0, 1], p=[0.4, 0.6]),
            }
            legit_features.append(f)
        
        # Generate synthetic phishing text features — strongly phishy characteristics
        phish_features = []
        for _ in range(n_phish):
            f = {
                "text_length": np.random.normal(180, 80),
                "word_count": np.random.normal(30, 12),
                "unique_word_count": np.random.normal(22, 9),
                "avg_word_length": np.random.normal(5.8, 1.0),
                "max_word_length": np.random.normal(13, 3),
                "sentence_count": np.random.normal(3, 1.5),
                "avg_sentence_length": np.random.normal(9, 3),
                "caps_ratio": np.random.uniform(0.08, 0.30),
                "digit_ratio": np.random.uniform(0.04, 0.18),
                "special_char_ratio": np.random.uniform(0.06, 0.18),
                "whitespace_ratio": np.random.uniform(0.10, 0.18),
                "exclamation_count": np.random.choice([1, 2, 3, 4], p=[0.25, 0.30, 0.25, 0.20]),
                "question_mark_count": np.random.choice([0, 1], p=[0.7, 0.3]),
                "ellipsis_count": np.random.choice([0, 1], p=[0.6, 0.4]),
                "dollar_sign_count": np.random.choice([0, 1, 2], p=[0.4, 0.35, 0.25]),
                "urgency_word_count": np.random.choice([2, 3, 4, 5, 6], p=[0.15, 0.25, 0.30, 0.20, 0.10]),
                "credential_word_count": np.random.choice([1, 2, 3, 4], p=[0.20, 0.30, 0.30, 0.20]),
                "threat_word_count": np.random.choice([1, 2, 3], p=[0.30, 0.40, 0.30]),
                "reward_word_count": np.random.choice([0, 1, 2], p=[0.45, 0.35, 0.20]),
                "urgency_density": np.random.uniform(0.05, 0.22),
                "credential_density": np.random.uniform(0.04, 0.15),
                "threat_density": np.random.uniform(0.02, 0.12),
                "reward_density": np.random.uniform(0, 0.08),
                "url_count": np.random.choice([1, 2, 3], p=[0.50, 0.35, 0.15]),
                "has_ip_url": np.random.choice([0, 1], p=[0.65, 0.35]),
                "phone_number_count": np.random.choice([0, 1], p=[0.45, 0.55]),
                "email_address_count": np.random.choice([0, 1], p=[0.75, 0.25]),
                "has_greeting": np.random.choice([0, 1], p=[0.55, 0.45]),
                "has_generic_greeting": np.random.choice([0, 1], p=[0.30, 0.70]),
                "has_signature": np.random.choice([0, 1], p=[0.70, 0.30]),
                "has_click_instruction": np.random.choice([0, 1], p=[0.20, 0.80]),
                "text_entropy": np.random.normal(3.5, 0.3),
                "word_entropy": np.random.normal(3.7, 0.3),
                "vocabulary_richness": np.random.uniform(0.40, 0.72),
                "is_sms": np.random.choice([0, 1], p=[0.4, 0.6]),
                "is_email": np.random.choice([0, 1], p=[0.6, 0.4]),
            }
            phish_features.append(f)
        
        self.text_feature_names = sorted(legit_features[0].keys())
        
        X_legit = np.array([[f[k] for k in self.text_feature_names] for f in legit_features])
        X_phish = np.array([[f[k] for k in self.text_feature_names] for f in phish_features])
        
        X = np.vstack([X_legit, X_phish])
        y = np.array([0] * n_legit + [1] * n_phish)
        
        indices = np.random.permutation(len(X))
        X, y = X[indices], y[indices]
        
        X_scaled = self.text_scaler.fit_transform(X)
        
        self.text_model = GradientBoostingClassifier(
            n_estimators=100,
            max_depth=6,
            learning_rate=0.1,
            random_state=42
        )
        self.text_model.fit(X_scaled, y)
    
    def predict_url(self, url_features: Dict[str, float]) -> Tuple[float, str]:
        """Predict phishing probability for URL"""
        feature_vector = np.array([[url_features.get(k, 0.0) for k in self.url_feature_names]])
        feature_vector_scaled = self.url_scaler.transform(feature_vector)
        
        proba = self.url_model.predict_proba(feature_vector_scaled)[0]
        phishing_prob = float(proba[1])
        
        # Get feature importances for this prediction
        importances = dict(zip(self.url_feature_names, self.url_model.feature_importances_))
        top_features = sorted(importances.items(), key=lambda x: x[1], reverse=True)[:5]
        
        return phishing_prob, top_features
    
    def predict_text(self, text_features: Dict[str, float]) -> Tuple[float, str]:
        """Predict phishing probability for text"""
        feature_vector = np.array([[text_features.get(k, 0.0) for k in self.text_feature_names]])
        feature_vector_scaled = self.text_scaler.transform(feature_vector)
        
        proba = self.text_model.predict_proba(feature_vector_scaled)[0]
        phishing_prob = float(proba[1])
        
        importances = dict(zip(self.text_feature_names, self.text_model.feature_importances_))
        top_features = sorted(importances.items(), key=lambda x: x[1], reverse=True)[:5]
        
        return phishing_prob, top_features


# Initialize ML model on startup
logger.info("Training ML models...")
ml_model = PhishingMLModel()
logger.info("ML models ready.")

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

class MLFeatures(BaseModel):
    """ML-extracted features returned to frontend"""
    model_config = {"protected_namespaces": ()}
    
    lexical_features: Optional[Dict[str, float]] = None
    text_features: Optional[Dict[str, float]] = None
    ssl_status: Optional[Dict] = None
    domain_age: Optional[Dict] = None
    ml_phishing_probability: float = 0.0
    top_ml_features: Optional[List[Dict[str, Any]]] = None
    model_used: str = "ensemble"

class AnalysisResponse(BaseModel):
    classification: str
    confidence_score: float
    risk_level: str
    threat_indicators: List[ThreatIndicator]
    explanation: str
    recommendations: List[str]
    analysis_details: Optional[Dict] = None
    ml_features: Optional[MLFeatures] = None

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
    unique = list(set(urls))
    # Remove partial URLs that are substrings of longer extracted URLs
    # This prevents e.g. 'www.google' being extracted alongside 'www.google.com/path'
    filtered = [u for u in unique if not any(u != other and u in other for other in unique)]
    return filtered if filtered else unique

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
        
        # First check if this IS a legitimate domain (exact match or www. prefix)
        is_actually_legit = False
        for legit in all_legit:
            if domain == legit or domain == "www." + legit or domain.endswith("." + legit):
                is_actually_legit = True
                break
        
        if not is_actually_legit:
            for legit in all_legit:
                legit_name = legit.split('.')[0]
                if len(legit_name) >= 4 and legit_name in domain and legit not in domain:
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
        (r"click\s+(here|below|this\s+link|the\s+link|the\s+button|now)\s*(to|and|now)?", "Direct click instruction", "high"),
        (r"click\s+now", "Direct click-now instruction", "high"),
        (r"(tap|press)\s+(here|the\s+link|button|below|now)", "Direct action instruction", "high"),
        (r"(start|begin|join|register|enroll|apply)\s+(now|today|here|immediately)", "Direct action instruction", "high"),
        (r"follow\s+this\s+link", "Link following instruction", "medium"),
        (r"(open|view|see|check)\s+(the\s+)?(attached|attachment|document|file|invoice|pdf)", "Attachment open instruction", "high"),
        (r"(download|install)\s+(the\s+)?(attached|attachment|file|update|app|software)", "Download instruction", "high"),
        (r"login\s+(here|now|below|to\s+your|at|via)", "Login instruction", "high"),
        (r"sign\s+in\s+(here|now|below|to\s+your|at|via|immediately)", "Sign-in instruction", "high"),
        (r"(update|verify|confirm)\s+(your|the)\s+(account|details|information|identity|payment)", "Verification instruction", "high"),
        (r"(use|visit|go\s+to)\s+(this|the)\s+(link|url|page|portal|site)", "Visit link instruction", "medium"),
        (r"(act|respond|reply)\s+(now|immediately|quickly|fast|urgently|asap)", "Urgency action instruction", "high"),
        (r"(complete|fill\s+out|submit)\s+(the\s+)?(form|verification|details|survey)", "Form submission instruction", "high"),
    ]
    
    for pattern, desc, sev in cta_patterns:
        if re.search(pattern, text_lower):
            indicators.append(ThreatIndicator(
                category="Suspicious CTA",
                description=desc,
                severity=sev,
                matched_text=re.search(pattern, text_lower).group(0),
                confidence=0.8 if sev == "high" else 0.6
            ))
    
    # Impersonation patterns
    impersonation_patterns = [
        (r"(this\s+is\s+(the\s+)?|from\s+(the\s+)?)(security|fraud|support|technical|it|admin|compliance)\s+(team|department|division|unit|desk|center)", "Authority impersonation", "high"),
        (r"(official|authorized|legitimate)\s+(notification|communication|message|notice|email|alert)", "Fake authority claim", "high"),
        (r"(we\s+have\s+detected|we\s+noticed|we\s+found)\s+(unusual|suspicious|unauthorized|fraudulent)", "Fake detection alert", "critical"),
        (r"(your\s+account\s+(has|was|is))\s+(recently\s+)?(accessed|logged|used|compromised|hacked|breached)", "Fake account compromise alert", "critical"),
        (r"(automated|system|security)\s+(message|notification|alert|warning|scan|check)\s+(detected|found|identified)", "Fake automated alert", "high"),
    ]
    
    for pattern, desc, sev in impersonation_patterns:
        match = re.search(pattern, text_lower)
        if match:
            indicators.append(ThreatIndicator(
                category="Impersonation",
                description=desc,
                severity=sev,
                matched_text=match.group(0),
                confidence=0.85 if sev == "critical" else 0.75
            ))
    
    # Invoice / document scam patterns
    invoice_patterns = [
        (r"(attached|enclosed|included)\s+(is\s+)?(your\s+)?(invoice|receipt|bill|statement|document|contract)", "Fake invoice/document attachment", "high"),
        (r"(please\s+)?(review|check|see|find)\s+(the\s+)?(attached|enclosed)\s+(invoice|document|file|receipt|pdf)", "Document review scam", "high"),
        (r"(invoice|receipt|bill|statement|payment|order)\s*#?\s*\d+", "Invoice number reference", "medium"),
        (r"(outstanding|overdue|unpaid|pending)\s+(invoice|bill|payment|balance|amount)", "Urgency about payment", "high"),
        (r"(payment\s+is\s+)?(due|overdue|past\s+due|required)", "Payment due urgency", "high"),
    ]
    
    for pattern, desc, sev in invoice_patterns:
        match = re.search(pattern, text_lower)
        if match:
            indicators.append(ThreatIndicator(
                category="Invoice Scam",
                description=desc,
                severity=sev,
                matched_text=match.group(0),
                confidence=0.80 if sev == "high" else 0.60
            ))
    
    # Subscription / renewal scam patterns
    subscription_patterns = [
        (r"(your\s+)?(subscription|membership|license|plan|service)\s+(has\s+)?(expired|expiring|about\s+to\s+expire|been\s+cancelled|will\s+be\s+cancelled)", "Subscription expiry scam", "high"),
        (r"(renew|reactivate|restore|resubscribe)\s+(your\s+)?(subscription|membership|account|service|license|plan)", "Renewal pressure scam", "high"),
        (r"(auto.?renewal|recurring\s+payment|billing\s+cycle)\s+(failed|declined|could\s+not|unsuccessful)", "Fake billing failure", "high"),
        (r"(your\s+)?(netflix|spotify|amazon|apple|microsoft|google|paypal|bank)\s+(account|subscription|membership|service)", "Brand name impersonation", "high"),
    ]
    
    for pattern, desc, sev in subscription_patterns:
        match = re.search(pattern, text_lower)
        if match:
            indicators.append(ThreatIndicator(
                category="Subscription Scam",
                description=desc,
                severity=sev,
                matched_text=match.group(0),
                confidence=0.80
            ))
    
    # Device / login alert scam patterns
    device_alert_patterns = [
        (r"(new|unknown|unrecognized|unauthorized)\s+(device|login|sign.?in|access)\s+(detected|attempt|from|on|at)", "Fake device login alert", "high"),
        (r"(someone|a\s+user|an?\s+unauthorized)\s+(just\s+)?(logged|signed|accessed|tried)", "Fake unauthorized access alert", "critical"),
        (r"(if\s+this\s+was\s*n.?t\s+you|if\s+you\s+did\s*n.?t\s+(do|make|initiate|authorize))", "Wasn't-you social engineering", "high"),
        (r"(new\s+)?(login|sign.?in)\s+(from|at|in)\s+[a-z]+\s*,?\s*[a-z]*", "Location-based login scare", "medium"),
    ]
    
    for pattern, desc, sev in device_alert_patterns:
        match = re.search(pattern, text_lower)
        if match:
            indicators.append(ThreatIndicator(
                category="Fake Alert",
                description=desc,
                severity=sev,
                matched_text=match.group(0),
                confidence=0.80
            ))
    
    # Delivery / shipping scam patterns
    delivery_patterns = [
        (r"(your\s+)?(package|parcel|shipment|delivery|order)\s+(has\s+been\s+)?(delayed|held|on\s+hold|could\s+not|failed|returned)", "Delivery scam", "high"),
        (r"(delivery|shipping)\s+(fee|charge|cost|payment)\s+(of\s+)?(ksh|kes|usd|\$)?\s*[\d,]*", "Delivery fee scam", "high"),
        (r"(track|schedule|confirm|reschedule)\s+(your\s+)?(delivery|package|parcel|shipment|order)", "Fake tracking instruction", "medium"),
    ]
    
    for pattern, desc, sev in delivery_patterns:
        match = re.search(pattern, text_lower)
        if match:
            indicators.append(ThreatIndicator(
                category="Delivery Scam",
                description=desc,
                severity=sev,
                matched_text=match.group(0),
                confidence=0.80
            ))
    
    # Tax/refund scam patterns
    tax_patterns = [
        (r"(tax\s+)?(refund|rebate|return|credit)\s+(of\s+)?(ksh|kes|usd|\$)?\s*[\d,]*", "Tax refund scam", "high"),
        (r"(kra|irs|hmrc|tax\s+authority|revenue)\s+(has\s+)?(determined|approved|selected|flagged)", "Tax authority impersonation", "critical"),
        (r"(file|claim|submit|process)\s+(your\s+)?(tax|refund|rebate|return)", "Tax claim instruction", "high"),
        (r"(government|official)\s+(grant|benefit|stimulus|relief|payment)", "Government scam", "high"),
    ]
    
    for pattern, desc, sev in tax_patterns:
        match = re.search(pattern, text_lower)
        if match:
            indicators.append(ThreatIndicator(
                category="Tax/Refund Scam",
                description=desc,
                severity=sev,
                matched_text=match.group(0),
                confidence=0.85 if sev == "critical" else 0.75
            ))
    
    # SMS-specific patterns
    if content_type == "sms":
        sms_patterns = [
            (r"(reply|send)\s+(with\s+)?(your\s+)?(\d+|pin|code)", "SMS reply with code request"),
            (r"call\s+(this\s+)?number\s*:?\s*\d+", "Call back scam indicator"),
            (r"(won|winner|prize|lottery|jackpot)", "Prize scam indicator"),
            (r"(free|bonus|reward|gift)\s+(mpesa|money|cash|ksh)", "Free money scam"),
            (r"(congrat|you\s+have\s+been\s+selected|you\s+are\s+a\s+winner)", "Prize scam indicator"),
            (r"(send\s+to|forward\s+to|share\s+with)\s+\d+\s+(people|friends|contacts)", "Chain message scam"),
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
        email_patterns = [
            (r"reply\s+to", "Contains explicit reply-to instruction", "low", 0.4),
            (r"do\s+not\s+(share|forward|reply)", "Anti-sharing instruction (social engineering)", "medium", 0.6),
            (r"(confidential|private|sensitive)\s+(message|email|communication|notice)", "Fake confidentiality claim", "medium", 0.65),
            (r"(failure\s+to|if\s+you\s+(fail|do\s+not|don.?t))\s+(comply|respond|verify|act|update)", "Threat of consequence", "high", 0.80),
            (r"(within|in)\s+(\d+\s+)?(hours?|minutes?|days?)\s+(or\s+)?(your\s+)?(account|access|service)", "Time-limited threat", "high", 0.80),
        ]
        
        for pattern, desc, sev, conf in email_patterns:
            match = re.search(pattern, text_lower)
            if match:
                indicators.append(ThreatIndicator(
                    category="Email Pattern",
                    description=desc,
                    severity=sev,
                    matched_text=match.group(0),
                    confidence=conf
                ))
    
    # Money/financial patterns
    money_patterns = [
        (r"(transfer|send|deposit)\s+(ksh|kes|usd|\$|shillings?)\s*[\d,]+", "Money transfer request"),
        (r"(receive|claim|get)\s+(ksh|kes|usd|\$|shillings?)\s*[\d,]+", "Money claim bait"),
        (r"(fee|charge|payment)\s+of\s+(ksh|kes|\$)?\s*[\d,]+", "Fee payment request"),
        (r"(pay|send|transfer)\s+(a\s+)?(small\s+)?(fee|amount|charge|processing)", "Fee advance scam"),
        (r"(credit\s+card|debit\s+card|bank\s+card|card)\s+(number|details|information|expir)", "Card information request"),
        (r"(wire|bank)\s+transfer", "Wire transfer request"),
        (r"(bitcoin|crypto|cryptocurrency|btc|eth|usdt)\s+(wallet|address|payment|transfer)", "Cryptocurrency scam"),
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
    
    # Investment / Prize / Reward scam patterns
    reward_patterns = [
        (r"(congratulations|congrats)\s*!?", "Prize/reward bait", "high", 0.80),
        (r"(you\s+(have\s+been|are|were)\s+)?(selected|chosen|picked)\s+(for|as|to)", "Selection scam", "high", 0.80),
        (r"(exclusive|special|unique|rare)\s+(offer|opportunity|deal|promotion|invitation|program)", "Exclusive offer bait", "high", 0.75),
        (r"(invest|deposit|put\s+in)\s+(\$|usd|ksh)?\s*[\d,]+\s*(and|to)\s+(earn|make|get|receive|profit)", "Investment scam", "critical", 0.90),
        (r"(earn|make|get|receive|win|profit)\s+(\$|usd|ksh)?\s*[\d,]+\s*(in|within|per)\s*(\d+\s*)?(day|week|month|hour)", "Unrealistic returns promise", "critical", 0.90),
        (r"(guaranteed|100%|risk.?free|no\s+risk)\s+(return|profit|income|earning|investment)", "Guaranteed returns scam", "critical", 0.90),
        (r"limited.?time\s+(offer|opportunity|deal|promotion)", "Limited-time pressure", "high", 0.75),
        (r"(don.?t|do\s+not)\s+miss\s+(out|this)", "FOMO pressure", "high", 0.75),
        (r"(life.?changing|once\s+in\s+a\s+lifetime|incredible|amazing)\s+(opportunity|offer|deal|chance)", "Exaggerated opportunity claim", "high", 0.75),
        (r"(bitcoin|crypto|forex|trading)\s+(investment|opportunity|profit|earning|income)", "Crypto/forex investment scam", "critical", 0.85),
        (r"(won|winner|winning)\s+.{0,20}(\$|usd|ksh|prize|reward|lottery|jackpot)", "Lottery/prize scam", "critical", 0.90),
        (r"(free|bonus|gift|complimentary)\s+.{0,15}(money|cash|iphone|laptop|car|travel|trip|vacation)", "Free prize scam", "high", 0.80),
    ]
    
    for pattern, desc, sev, conf in reward_patterns:
        match = re.search(pattern, text_lower)
        if match:
            indicators.append(ThreatIndicator(
                category="Reward/Investment Scam",
                description=desc,
                severity=sev,
                matched_text=match.group(0),
                confidence=conf
            ))
    
    # Spelling/grammar red flags common in phishing
    grammar_patterns = [
        (r"(kindly|please\s+kindly|do\s+the\s+needful)", "Typical phishing phrasing", "medium", 0.55),
        (r"(your\s+account\s+will\s+be\s+(close|suspend|terminate|block|deactivat))", "Account threat with grammar issue", "high", 0.80),
        (r"(we\s+are\s+(sorry|pleased)\s+to\s+(inform|notify)\s+you)", "Formal notification phrasing (common in scams)", "medium", 0.50),
    ]
    
    for pattern, desc, sev, conf in grammar_patterns:
        match = re.search(pattern, text_lower)
        if match:
            indicators.append(ThreatIndicator(
                category="Phrasing",
                description=desc,
                severity=sev,
                matched_text=match.group(0),
                confidence=conf
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
    """Calculate weighted risk score based on indicators — aggressive scoring to catch all phishing"""
    if not indicators:
        return 0.0, "safe", "low"
    
    # Severity weights — significantly increased for accuracy
    weights = {
        "critical": 0.45,
        "high": 0.30,
        "medium": 0.18,
        "low": 0.08
    }
    
    # Calculate weighted score
    total_score = 0.0
    for indicator in indicators:
        weight = weights.get(indicator.severity, 0.08)
        total_score += weight * indicator.confidence
    
    # Normalize score (cap at 1.0)
    score = min(1.0, total_score)
    
    # Boost score for critical + credential combination
    has_critical = any(i.severity == "critical" for i in indicators)
    has_credential = any("credential" in i.category.lower() for i in indicators)
    has_threat = any("threat" in i.category.lower() for i in indicators)
    has_urgency = any("urgency" in i.category.lower() or "time" in i.category.lower() for i in indicators)
    has_url_issue = any(i.category in ["Suspicious URL", "Suspicious TLD", "Domain Spoofing", "SSL/TLS", "URL Shortener"] for i in indicators)
    
    # Strong boosting rules for common phishing combinations
    if has_critical and has_credential:
        score = min(1.0, score * 1.5)
    
    if has_credential and has_urgency:
        score = min(1.0, score * 1.4)
    
    if has_threat and has_credential:
        score = min(1.0, score * 1.4)
    
    if has_credential and has_url_issue:
        score = min(1.0, score * 1.3)
    
    if has_urgency and has_url_issue:
        score = min(1.0, score * 1.3)
    
    # If 3+ high/critical indicators, it's almost certainly phishing
    high_critical_count = sum(1 for i in indicators if i.severity in ("critical", "high"))
    if high_critical_count >= 3:
        score = max(score, 0.7)
    elif high_critical_count >= 2:
        score = max(score, 0.5)
    
    # If ANY critical indicator exists, minimum score floor
    if has_critical:
        score = max(score, 0.45)
    
    # Determine classification and risk level — lower thresholds to catch more
    if score >= 0.40:
        classification = "phishing"
        risk_level = "critical" if score >= 0.70 else "high"
    elif score >= 0.20:
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
    """Comprehensive content analysis with ML models"""
    
    all_indicators = []
    ml_features_data = MLFeatures()
    
    # Run all heuristic detection modules
    all_indicators.extend(check_urgency_advanced(content))
    all_indicators.extend(check_credential_patterns(content))
    all_indicators.extend(check_threat_patterns(content))
    all_indicators.extend(check_kenya_targets(content))
    all_indicators.extend(check_suspicious_patterns(content, content_type))
    all_indicators.extend(check_link_text_mismatch(content))
    
    # ===== ML FEATURE EXTRACTION & PREDICTION =====
    ml_phishing_prob = 0.0
    top_features_list = []
    
    # URL analysis (for all types - extract URLs from text too)
    urls = extract_urls(content)
    for url in urls[:5]:
        all_indicators.extend(analyze_url_advanced(url))
    
    if content_type == "url":
        all_indicators.extend(analyze_url_advanced(content))
        
        # ML: Extract lexical features
        lexical = LexicalFeatureExtractor.extract_url_features(content)
        ml_features_data.lexical_features = {k: round(v, 4) for k, v in lexical.items()}
        
        # ML: Predict
        ml_phishing_prob, top_feats = ml_model.predict_url(lexical)
        top_features_list = [{"feature": f, "importance": round(imp, 4)} for f, imp in top_feats]
        
        # SSL Check
        ssl_result = SSLChecker.check_ssl(content)
        ml_features_data.ssl_status = ssl_result
        
        if not ssl_result["has_ssl"]:
            all_indicators.append(ThreatIndicator(
                category="SSL/TLS",
                description="No SSL certificate detected - connection is not encrypted",
                severity="high",
                matched_text="HTTP (no HTTPS)",
                confidence=0.85
            ))
        elif not ssl_result["ssl_valid"]:
            all_indicators.append(ThreatIndicator(
                category="SSL/TLS",
                description="SSL certificate is invalid or expired",
                severity="critical",
                matched_text="Invalid SSL",
                confidence=0.9
            ))
        elif ssl_result.get("ssl_expiry_days") is not None and ssl_result["ssl_expiry_days"] < 30:
            all_indicators.append(ThreatIndicator(
                category="SSL/TLS",
                description=f"SSL certificate expires in {ssl_result['ssl_expiry_days']} days",
                severity="medium",
                matched_text=f"Expires in {ssl_result['ssl_expiry_days']}d",
                confidence=0.6
            ))
        
        # Domain Age Check
        domain_age = DomainAgeChecker.check_domain_age(content)
        ml_features_data.domain_age = domain_age
        
        if domain_age["domain_age_days"] is not None:
            if domain_age["domain_age_days"] < 30:
                all_indicators.append(ThreatIndicator(
                    category="Domain Age",
                    description=f"Domain registered only {domain_age['domain_age_days']} days ago - very new",
                    severity="critical",
                    matched_text=f"Registered: {domain_age.get('registration_date', 'Unknown')}",
                    confidence=0.9
                ))
            elif domain_age["domain_age_days"] < 180:
                all_indicators.append(ThreatIndicator(
                    category="Domain Age",
                    description=f"Domain is only {domain_age['domain_age_days']} days old",
                    severity="high",
                    matched_text=f"Registered: {domain_age.get('registration_date', 'Unknown')}",
                    confidence=0.75
                ))
    
    else:
        # Text content (SMS/email)
        text_features = TextFeatureExtractor.extract_text_features(content, content_type)
        ml_features_data.text_features = {k: round(v, 4) for k, v in text_features.items()}
        
        # ML: Predict
        ml_phishing_prob, top_feats = ml_model.predict_text(text_features)
        top_features_list = [{"feature": f, "importance": round(imp, 4)} for f, imp in top_feats]
        
        # Also check SSL and domain age for any URLs found in text
        for url in urls[:2]:
            ssl_result = SSLChecker.check_ssl(url)
            if not ssl_result["has_ssl"]:
                all_indicators.append(ThreatIndicator(
                    category="SSL/TLS",
                    description=f"Link has no SSL: {url[:50]}",
                    severity="medium",
                    matched_text=url[:60],
                    confidence=0.7
                ))
            
            domain_age = DomainAgeChecker.check_domain_age(url)
            if domain_age["domain_age_days"] is not None and domain_age["domain_age_days"] < 30:
                all_indicators.append(ThreatIndicator(
                    category="Domain Age",
                    description=f"Linked domain registered {domain_age['domain_age_days']} days ago",
                    severity="high",
                    matched_text=url[:60],
                    confidence=0.85
                ))
    
    ml_features_data.ml_phishing_probability = round(ml_phishing_prob, 4)
    ml_features_data.top_ml_features = top_features_list
    ml_features_data.model_used = "RandomForest" if content_type == "url" else "GradientBoosting"
    
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
    
    # Calculate combined score (heuristic + ML)
    heuristic_score, _, _ = calculate_risk_score(unique_indicators)
    
    # Ensemble: combine heuristic and ML intelligently
    # Key insight: if heuristic finds no threats but ML says phishing,
    # the content is likely safe (ML may overfit on stylistic features)
    total_indicators = len(unique_indicators)
    critical_count = sum(1 for i in unique_indicators if i.severity == "critical")
    high_count = sum(1 for i in unique_indicators if i.severity == "high")
    medium_count = sum(1 for i in unique_indicators if i.severity == "medium")
    total_serious = critical_count + high_count
    
    if total_indicators == 0:
        # No heuristic indicators: ML alone, but dampened significantly
        # This prevents false positives from ML on legitimate content
        combined_score = ml_phishing_prob * 0.3
    elif total_serious == 0 and medium_count <= 1:
        # Only low/1 medium indicators: blend conservatively, trust heuristic more
        combined_score = (0.7 * heuristic_score) + (0.3 * ml_phishing_prob)
    else:
        # Heuristic found real threats: use max to ensure nothing is missed
        base_score = max(heuristic_score, ml_phishing_prob)
        avg_score = (0.55 * heuristic_score) + (0.45 * ml_phishing_prob)
        combined_score = max(base_score, avg_score)
    
    combined_score = min(1.0, combined_score)
    
    # Safety boost: if heuristic detected many indicators, ensure high score
    if total_serious >= 3 or critical_count >= 2:
        combined_score = max(combined_score, 0.85)
    elif total_serious >= 2 or critical_count >= 1:
        combined_score = max(combined_score, 0.65)
    elif high_count >= 1 and medium_count >= 2:
        combined_score = max(combined_score, 0.55)
    elif total_serious >= 1 and medium_count >= 1:
        combined_score = max(combined_score, 0.45)
    elif medium_count >= 3:
        combined_score = max(combined_score, 0.40)
    
    combined_score = min(1.0, combined_score)
    
    # Determine classification from combined score — lowered thresholds
    if combined_score >= 0.40:
        classification = "phishing"
        risk_level = "critical" if combined_score >= 0.70 else "high"
    elif combined_score >= 0.20:
        classification = "suspicious"
        risk_level = "medium"
    else:
        classification = "safe"
        risk_level = "low"
    
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
        "analysis_version": "3.0",
        "heuristic_score": round(heuristic_score, 4),
        "ml_score": round(ml_phishing_prob, 4),
        "combined_score": round(combined_score, 4),
        "model_type": "RandomForest" if content_type == "url" else "GradientBoosting",
        "features_extracted": len(ml_features_data.lexical_features or ml_features_data.text_features or {})
    }
    
    return AnalysisResponse(
        classification=classification,
        confidence_score=round(combined_score, 3),
        risk_level=risk_level,
        threat_indicators=unique_indicators[:15],
        explanation=explanation,
        recommendations=recommendations,
        analysis_details=analysis_details,
        ml_features=ml_features_data
    )

# ==================== API ENDPOINTS ====================

@app.get("/")
async def root():
    return {
        "service": "ThreatLens ML Service",
        "version": "3.0.0",
        "status": "operational",
        "features": [
            "Random Forest URL classifier",
            "Gradient Boosting text classifier",
            "Lexical feature extraction (35+ features)",
            "SSL/TLS certificate validation",
            "Domain age analysis (WHOIS)",
            "NLP text feature analysis (35+ features)",
            "Homograph attack detection",
            "Typosquatting detection",
            "Kenya-specific patterns",
            "Ensemble scoring (heuristic + ML)"
        ]
    }

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "version": "3.0.0",
        "ml_models_loaded": ml_model.url_model is not None and ml_model.text_model is not None,
        "whois_available": WHOIS_AVAILABLE
    }

@app.post("/analyze", response_model=AnalysisResponse)
async def analyze(request: AnalysisRequest):
    """Analyze content for phishing indicators using ML models + heuristics"""
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
        "ml_models": {
            "url_model": "RandomForestClassifier (100 estimators)",
            "text_model": "GradientBoostingClassifier (100 estimators)",
            "url_features": len(ml_model.url_feature_names),
            "text_features": len(ml_model.text_feature_names),
            "ensemble_weights": {"heuristic": 0.4, "ml": 0.6}
        },
        "capabilities": {
            "ssl_checking": True,
            "domain_age_checking": WHOIS_AVAILABLE,
            "lexical_analysis": True,
            "nlp_text_analysis": True
        },
        "version": "3.0.0"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
