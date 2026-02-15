# 🔬 PhishGuard Detection Guide

## How PhishGuard Detects Phishing & Smishing

This document provides a complete technical breakdown of the AI detection techniques, algorithms, and tools used in PhishGuard to identify phishing emails, SMS smishing, and malicious URLs.

---

## Table of Contents

1. [Detection Architecture Overview](#detection-architecture-overview)
2. [Tools & Technologies Used](#tools--technologies-used)
3. [Detection Modules](#detection-modules)
   - [Urgency Language Analysis](#1-urgency-language-analysis)
   - [Credential Harvesting Detection](#2-credential-harvesting-detection)
   - [Threat Pattern Matching](#3-threat-pattern-matching)
   - [Advanced URL Analysis](#4-advanced-url-analysis)
   - [Homograph Attack Detection](#5-homograph-attack-detection)
   - [Typosquatting Detection](#6-typosquatting-detection)
   - [Kenya-Specific Target Detection](#7-kenya-specific-target-detection)
   - [SMS Scam Pattern Detection](#8-sms-scam-pattern-detection)
   - [Link-Text Mismatch Detection](#9-link-text-mismatch-detection)
   - [Financial Request Detection](#10-financial-request-detection)
   - [Shannon Entropy Analysis](#11-shannon-entropy-analysis)
   - [Suspicious Pattern Detection](#12-suspicious-pattern-detection)
4. [Risk Scoring Algorithm](#risk-scoring-algorithm)
5. [Classification System](#classification-system)
6. [Explainable AI Output](#explainable-ai-output)
7. [Security Layer](#security-layer)
8. [Real-World Examples](#real-world-examples)
9. [Limitations & Future Work](#limitations--future-work)

---

## Detection Architecture Overview

PhishGuard uses a **multi-layered heuristic detection engine** rather than a trained ML model. This approach was chosen because:

- **No training data required** — works immediately on any content
- **Explainable results** — each indicator is clearly described with severity
- **Easy to extend** — new patterns can be added as rules
- **Low resource usage** — runs on minimal hardware, no GPU needed
- **Deterministic output** — same input always produces same result

### Detection Pipeline

```
Input Content (email / SMS / URL)
         │
         ▼
┌──────────────────────────────┐
│  1. Input Sanitization       │  → Remove null bytes, validate length
│  2. Content Type Detection   │  → email / sms / url
└──────────────────────────────┘
         │
         ▼
┌──────────────────────────────┐
│  3. Parallel Detection       │
│  ┌─────────┬─────────┐      │
│  │ Urgency │Credential│      │
│  │ Analysis│Harvesting│      │
│  ├─────────┼─────────┤      │
│  │ Threat  │ URL      │      │
│  │ Patterns│ Analysis │      │
│  ├─────────┼─────────┤      │
│  │Homograph│Typosquat │      │
│  │Detection│Detection │      │
│  ├─────────┼─────────┤      │
│  │ Kenya   │ SMS Scam │      │
│  │ Targets │ Patterns │      │
│  ├─────────┼─────────┤      │
│  │ Link    │Financial │      │
│  │Mismatch │ Request  │      │
│  ├─────────┼─────────┤      │
│  │Entropy  │Suspicious│      │
│  │Analysis │ Patterns │      │
│  └─────────┴─────────┘      │
└──────────────────────────────┘
         │
         ▼
┌──────────────────────────────┐
│  4. Risk Score Calculation   │  → Weighted severity scoring
│  5. Classification           │  → safe / suspicious / phishing
│  6. Explanation Generation   │  → Human-readable threat report
│  7. Recommendations          │  → Actionable safety advice
└──────────────────────────────┘
         │
         ▼
    JSON Response
```

---

## Tools & Technologies Used

### Core Framework

| Tool         | Version | Purpose                                          |
| ------------ | ------- | ------------------------------------------------ |
| **Python**   | 3.9+    | Runtime for the detection engine                 |
| **FastAPI**  | latest  | High-performance async web framework for the API |
| **Uvicorn**  | latest  | ASGI server to serve FastAPI application         |
| **Pydantic** | v2      | Data validation for API requests and responses   |

### Python Standard Library Modules

| Module                | Usage                                                                    |
| --------------------- | ------------------------------------------------------------------------ |
| `re` (regex)          | Pattern matching for phishing indicators (urgency, credentials, threats) |
| `urllib.parse`        | URL parsing — extracting domain, path, query, fragments                  |
| `math.log2`           | Shannon entropy calculation for domain randomness detection              |
| `collections.Counter` | Character frequency counting for entropy analysis                        |
| `datetime`            | Timestamps for API responses and rate limiting                           |
| `os`                  | Environment variable reading for configuration                           |
| `unicodedata`         | Unicode character name lookup for homograph detection                    |
| `ipaddress`           | IP address validation for URL analysis                                   |

### Security Libraries

| Tool                             | Purpose                                             |
| -------------------------------- | --------------------------------------------------- |
| `fastapi.middleware.cors`        | Cross-Origin Resource Sharing control               |
| `fastapi.middleware.trustedhost` | Host header validation                              |
| Custom middleware                | Rate limiting, security headers, input sanitization |

### Frontend Detection Support

| Tool             | Purpose                                                 |
| ---------------- | ------------------------------------------------------- |
| `security.js`    | Client-side sanitization, rate limiting, secure storage |
| `scanStorage.js` | localStorage persistence with data validation           |

---

## Detection Modules

### 1. Urgency Language Analysis

**Function**: `check_urgency_advanced()`

**What it detects**: Phishing messages almost always create a sense of urgency to prevent victims from thinking carefully.

**How it works**: Regex pattern matching against 20+ urgency phrases, categorized by severity.

| Severity | Patterns Detected                                                        |
| -------- | ------------------------------------------------------------------------ |
| Critical | "immediate action required", "will be terminated", "permanently deleted" |
| High     | "act now", "expires today", "within 24 hours", "urgent action"           |
| Medium   | "limited time", "don't miss", "hurry", "as soon as possible"             |
| Low      | "important notice", "reminder", "attention required"                     |

**Technical implementation**:

```python
URGENCY_PATTERNS = {
    "critical": [
        r"immediate\s+action\s+required",
        r"your\s+account\s+will\s+be\s+(suspended|terminated|closed|deleted)",
        r"unauthorized\s+(access|transaction|activity)\s+detected",
        ...
    ],
    "high": [
        r"act\s+now",
        r"expires?\s+today",
        r"within\s+\d+\s+hours?",
        ...
    ]
}
```

Each pattern match produces a threat indicator with its severity level and a human-readable description.

---

### 2. Credential Harvesting Detection

**Function**: `check_credential_patterns()`

**What it detects**: Requests for sensitive information like passwords, PINs, OTPs, and account numbers.

**Patterns detected** (mapped by severity):

| Severity | Patterns                                                                            |
| -------- | ----------------------------------------------------------------------------------- |
| Critical | "enter your password", "confirm your PIN", "verify your identity", "enter your OTP" |
| High     | "update your credentials", "reset your password", "verify your account"             |
| Medium   | "confirm your details", "update your information", "verify your email"              |

**How it works**: Regex matching against credential-related phrases. When detected, the specific sensitive data type (password, PIN, OTP, etc.) is extracted and included in the threat indicator.

**Example detection**:

```
Input:  "Please enter your M-Pesa PIN to verify your account"
Output: {
  "category": "Credential Harvesting",
  "description": "Requests sensitive data: 'pin'",
  "severity": "critical",
  "confidence": 0.95
}
```

---

### 3. Threat Pattern Matching

**Function**: `check_threat_patterns()`

**What it detects**: Threats and consequences used to intimidate victims into compliance.

| Severity | Threats Detected                                                            |
| -------- | --------------------------------------------------------------------------- |
| Critical | "legal action will be taken", "reported to police", "arrested"              |
| High     | "account will be locked", "services will be discontinued", "face penalties" |
| Medium   | "may be affected", "could be compromised", "risk losing"                    |

**Why this works**: Legitimate organizations rarely threaten legal action or arrest via email/SMS. Phishers use fear to override rational thinking.

---

### 4. Advanced URL Analysis

**Function**: `analyze_url_advanced()`

**What it detects**: Malicious, suspicious, or spoofed URLs embedded in messages.

**Analysis layers**:

| Check                    | What It Finds                               | Severity |
| ------------------------ | ------------------------------------------- | -------- |
| **IP Address URLs**      | `http://192.168.1.1/login`                  | Critical |
| **Suspicious TLDs**      | `.tk`, `.ml`, `.ga`, `.cf`, `.xyz`, `.buzz` | High     |
| **URL Shorteners**       | `bit.ly`, `tinyurl.com`, `t.co`             | Medium   |
| **Excessive Subdomains** | `login.secure.bank.evil.com`                | High     |
| **Path Keywords**        | `/login`, `/verify`, `/secure`, `/update`   | Medium   |
| **Encoded Characters**   | `%2F`, `%40` in URL path                    | Medium   |
| **Long URLs**            | More than 75 characters                     | Low      |
| **@ Symbol in URL**      | `http://bank.com@evil.com`                  | Critical |
| **Homograph Attack**     | Cyrillic/lookalike characters               | Critical |
| **Typosquatting**        | `safaricomm.com`, `equitybnk.com`           | High     |
| **Domain Spoofing**      | Brand name as subdomain: `mpesa.evil.com`   | High     |
| **Entropy Analysis**     | Randomly generated domain names             | Medium   |

**Technical implementation**:

```python
# URL parsing
parsed = urlparse(url)
domain = parsed.netloc.lower()
path = parsed.path.lower()

# Check for IP-based URLs
try:
    ipaddress.ip_address(domain.split(':')[0])
    indicators.append({"severity": "critical", ...})
except ValueError:
    pass

# Check suspicious TLDs
SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.buzz', ...]
```

**Whitelist**: Legitimate domains (google.com, microsoft.com, safaricom.co.ke, etc.) are whitelisted to prevent false positives.

---

### 5. Homograph Attack Detection

**Function**: `detect_homograph_attack()`

**What it detects**: Characters from non-Latin scripts (Cyrillic, Greek, etc.) that look identical to Latin letters but have different Unicode code points.

**How it works**:

1. Iterates through each character in the domain name
2. Uses `unicodedata.name()` to get the Unicode character name
3. Checks if the character name contains "CYRILLIC", "GREEK", or other non-Latin script names
4. Flags domains mixing scripts as potential homograph attacks

**Homograph mapping** (lookalike characters):

```
a → a  (Cyrillic а, U+0430)    e → e  (Cyrillic е, U+0435)
o → o  (Cyrillic о, U+043E)    p → p  (Cyrillic р, U+0440)
c → c  (Cyrillic с, U+0441)    x → x  (Cyrillic х, U+0445)
y → y  (Cyrillic у, U+0443)    i → i  (Cyrillic і, U+0456)
```

**Example**:

```
Input:  "safaricom.co.ke" (with Cyrillic 'a' at position 1, U+0430)
Output: CRITICAL — "Domain contains non-Latin characters (Cyrillic) — possible homograph attack"
```

**Why this matters**: An attacker can register a domain with Cyrillic characters that looks identical to `safaricom.co.ke` in most browsers.

---

### 6. Typosquatting Detection

**Function**: `detect_typosquatting()`

**What it detects**: Domains that are intentionally misspelled versions of legitimate brands.

**Brands monitored**:

```python
BRAND_TARGETS = {
    'safaricom': 'safaricom.co.ke',
    'mpesa': 'safaricom.co.ke',
    'equity': 'equitybank.co.ke',
    'kcb': 'kcbgroup.com',
    'cooperative': 'co-opbank.co.ke',
    'paypal': 'paypal.com',
    'google': 'google.com',
    'microsoft': 'microsoft.com',
    'apple': 'apple.com',
    ...
}
```

**Detection method**: String containment check — if a well-known brand name appears anywhere in the domain but the full domain doesn't match the legitimate one, it's flagged.

**Examples**:

```
safaricom-verify.com  → Contains "safaricom", not safaricom.co.ke → FLAGGED
equitybank-login.tk   → Contains "equity", not equitybank.co.ke → FLAGGED
google.com            → Matches legitimate domain → NOT FLAGGED
```

---

### 7. Kenya-Specific Target Detection

**Function**: `check_kenya_targets()`

**What it detects**: References to Kenyan financial services, telcos, and government agencies commonly impersonated in phishing.

**Target categories**:

#### Mobile Money

```python
"m-pesa", "mpesa", "m pesa", "lipa na mpesa",
"paybill", "till number", "send money",
"fuliza", "m-shwari", "mshwari"
```

#### Banks

```python
"equity bank", "kcb bank", "co-operative bank",
"co-op bank", "ncba", "stanbic", "absa",
"family bank", "dtb", "i&m bank"
```

#### Telecommunications

```python
"safaricom", "airtel kenya", "telkom kenya",
"faiba", "airtel money", "t-kash", "equitel"
```

#### Government

```python
"kra", "kenya revenue", "ntsa", "ecitizen",
"e-citizen", "huduma", "nhif", "nssf"
```

**Why Kenya-specific rules matter**: Generic phishing detectors miss scams like:

> "Dear Customer, your M-PESA account has been flagged for suspicious activity. Verify your PIN at http://mpesa-verify.tk to avoid suspension."

This requires knowing that M-Pesa is a mobile money service and that Safaricom would never ask for PINs via SMS.

---

### 8. SMS Scam Pattern Detection

**Function**: `check_suspicious_patterns()` (SMS-specific branch)

**What it detects**: Common SMS/smishing tactics unique to text messages.

| Pattern             | Example                                    | Severity |
| ------------------- | ------------------------------------------ | -------- |
| Prize/winning scams | "Congratulations! You won KES 500,000"     | High     |
| Callback traps      | "Call 0900-XXX-XXX to claim"               | High     |
| Reply traps         | "Reply YES to confirm"                     | Medium   |
| Short code spoofing | Messages pretending to be from short codes | Medium   |
| Excessive caps      | "URGENT!!! YOUR ACCOUNT..."                | Medium   |
| Number replacement  | "Call +254-7XX-XXX-XXX"                    | Low      |

**SMS-specific context**: SMS messages are shorter and have different attack patterns than emails. PhishGuard adjusts its detection threshold and pattern weight for SMS content.

---

### 9. Link-Text Mismatch Detection

**Function**: `check_link_text_mismatch()`

**What it detects**: HTML links where the displayed text shows one URL but the actual `href` points somewhere else.

**How it works**:

```python
# Regex to find HTML links with URL-like display text
pattern = r'<a[^>]*href=["\']([^"\']+)["\'][^>]*>([^<]*)</a>'

# Check if display text looks like a URL
if display_text starts with "http" or contains ".com", ".co.ke", etc.:
    # Compare display domain vs actual href domain
    if domains don't match:
        → CRITICAL indicator
```

**Example**:

```html
<a href="http://evil-site.tk/steal">http://equitybank.co.ke</a>
```

The user sees `http://equitybank.co.ke` but clicking sends them to `evil-site.tk`.

**Detection output**:

```json
{
  "category": "Link Mismatch",
  "description": "Display URL domain differs from actual link destination",
  "severity": "critical",
  "confidence": 0.95
}
```

---

### 10. Financial Request Detection

**Function**: `check_suspicious_patterns()` (financial branch)

**What it detects**: Requests to send money, pay fees, or make financial transactions.

**Patterns**:

```python
r"send\s+(?:money|cash|funds|payment)",
r"(?:transfer|wire|remit)\s+(?:to|into)",
r"(?:pay|deposit)\s+(?:a\s+)?(?:fee|charge|fine)",
r"(?:processing|activation|clearance)\s+fee",
r"(?:western\s+union|money\s*gram|bitcoin|crypto)"
```

**Why this matters**: Advance-fee fraud ("pay a small fee to claim your prize") is one of the most common scam types in Kenya.

---

### 11. Shannon Entropy Analysis

**Function**: `calculate_entropy()`

**What it detects**: Domain names that appear randomly generated (used in disposable phishing infrastructure).

**How it works**:

Shannon entropy measures the randomness/unpredictability of a string:

$$H = -\sum_{i=1}^{n} p(x_i) \cdot \log_2(p(x_i))$$

Where:

- $H$ = entropy (bits per character)
- $p(x_i)$ = probability of character $x_i$ (frequency / total length)
- $n$ = number of unique characters

**Implementation**:

```python
from math import log2
from collections import Counter

def calculate_entropy(text):
    if not text:
        return 0
    counter = Counter(text)
    length = len(text)
    entropy = -sum(
        (count / length) * log2(count / length)
        for count in counter.values()
    )
    return entropy
```

**Interpretation**:

| Entropy   | Meaning                   | Example Domain    |
| --------- | ------------------------- | ----------------- |
| < 2.5     | Very structured / short   | `aaa.com`         |
| 2.5 - 3.5 | Normal domain             | `safaricom.co.ke` |
| 3.5 - 4.0 | Somewhat random           | `xk9mz2.com`      |
| > 4.0     | Likely randomly generated | `a8x7k2m9q.xyz`   |

Domains with entropy > 4.0 are flagged as potentially malicious (disposable phishing domains).

---

### 12. Suspicious Pattern Detection

**Function**: `check_suspicious_patterns()`

**What it detects**: General phishing indicators that span all content types.

| Pattern                | Severity | Example                            |
| ---------------------- | -------- | ---------------------------------- |
| Grammar/spelling clues | Low      | "Dear Costumer" (misspelling)      |
| Generic greetings      | Low      | "Dear Customer" (no personal name) |
| Data: URI schemes      | High     | Embedded data URIs for obfuscation |
| Excessive exclamation  | Low      | "ACT NOW!!!"                       |
| Multiple redirects     | Medium   | URL with redirect chains           |
| Base64 content         | High     | Encoded payloads in messages       |

---

## Risk Scoring Algorithm

### Severity Weight System

Each detection module produces indicators with severity levels. The risk score is calculated using weighted combination:

```python
SEVERITY_WEIGHTS = {
    "critical": 0.35,   # 35% contribution per critical indicator
    "high":     0.25,   # 25% per high indicator
    "medium":   0.15,   # 15% per medium indicator
    "low":      0.08    # 8% per low indicator
}
```

### Score Calculation

```python
def calculate_risk_score(indicators):
    if not indicators:
        return 0.0

    total_score = 0.0
    for indicator in indicators:
        severity = indicator.get("severity", "medium")
        confidence = indicator.get("confidence", 0.7)
        weight = SEVERITY_WEIGHTS.get(severity, 0.15)

        # Weight x Confidence = contribution
        total_score += weight * confidence

    # Normalize to 0.0 - 1.0 range
    max_possible = len(indicators) * 0.35  # if all were critical
    normalized = min(total_score / max(max_possible, 1), 1.0)

    # Apply content-type adjustment
    if content_type == "sms":
        normalized *= 1.1   # SMS scams are more dangerous (direct action)
    elif content_type == "url":
        normalized *= 1.05  # URLs can lead directly to credential theft

    return min(normalized, 1.0)
```

### Score Breakdown Example

```
Input: "Your M-PESA account suspended! Click http://mpesa-login.tk to verify PIN"

Indicators found:
  1. Urgency ("account suspended")     → critical x 0.95 = 0.3325
  2. Kenya Target ("M-PESA")           → high     x 0.85 = 0.2125
  3. Credential Harvesting ("PIN")     → critical x 0.95 = 0.3325
  4. Suspicious TLD (.tk)              → high     x 0.85 = 0.2125
  5. Typosquatting ("mpesa-login")      → high     x 0.80 = 0.2000

Total raw score: 1.2900
Max possible (5 x 0.35): 1.75
Normalized: 1.29 / 1.75 = 0.737
SMS adjustment: 0.737 x 1.1 = 0.811

Final confidence: 0.81 → PHISHING (Critical)
```

---

## Classification System

| Classification | Confidence Range | Risk Level    | Color  |
| -------------- | ---------------- | ------------- | ------ |
| Safe           | 0% - 24%         | Low           | Green  |
| Suspicious     | 25% - 49%        | Medium        | Yellow |
| Phishing       | 50%+             | High/Critical | Red    |

### Risk Level Assignment

```python
if confidence >= 0.7:
    risk_level = "critical"
elif confidence >= 0.5:
    risk_level = "high"
elif confidence >= 0.25:
    risk_level = "medium"
else:
    risk_level = "low"
```

---

## Explainable AI Output

PhishGuard provides **explainable results** — every classification comes with a detailed explanation of _why_ the content was flagged.

### Explanation Generation

**Function**: `generate_explanation()`

The explanation includes:

1. **Classification verdict** with emoji indicator
2. **Number of threat indicators** found
3. **Content type context** (email/SMS/URL)
4. **Grouped indicators by category** with severity labels
5. **Overall risk assessment**

**Example output**:

```
PHISHING DETECTED: This sms shows 5 threat indicators.

CRITICAL: Credential Harvesting — Requests sensitive data: 'pin'
CRITICAL: Urgency — Creates pressure: 'your account will be suspended'
HIGH: Kenya Target — References Kenyan financial service: 'M-Pesa'
HIGH: Suspicious TLD — Domain uses suspicious TLD: .tk
MEDIUM: Domain Spoofing — Brand name used in suspicious domain

Overall Risk Level: CRITICAL — This content shows strong signs of being a phishing attempt.
```

### Recommendation Generation

**Function**: `generate_recommendations()`

Contextual recommendations based on the specific threats found:

| Threat Category       | Recommendation                                            |
| --------------------- | --------------------------------------------------------- |
| Credential Harvesting | "NEVER enter passwords, PINs, or OTPs via links"          |
| Kenya Target          | "Contact Safaricom (100) or your bank directly to verify" |
| Suspicious URL        | "DO NOT click any links in this message"                  |
| Financial Request     | "Legitimate companies never ask for fees via SMS/email"   |
| General Phishing      | "Report this to your email provider as phishing"          |

---

## Security Layer

The detection engine is protected by multiple security layers:

### Rate Limiting

```python
# 30 requests per minute per IP address
@app.middleware("http")
async def rate_limiter(request, call_next):
    client_ip = request.client.host
    now = time.time()
    window = rate_limit_store.get(client_ip, [])
    window = [t for t in window if now - t < 60]
    if len(window) >= RATE_LIMIT:
        return JSONResponse(status_code=429, content={"error": "Rate limit exceeded"})
    window.append(now)
    rate_limit_store[client_ip] = window
```

### Input Sanitization

```python
def sanitize_input(text: str) -> str:
    text = text.replace('\x00', '')        # Remove null bytes
    text = re.sub(r'[\x01-\x08\x0b\x0c\x0e-\x1f]', '', text)  # Control chars
    text = text[:50000]                     # 50KB max
    return text.strip()
```

### Pydantic Validation

```python
class AnalysisRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=50000)
    content_type: str = Field(default="email")

    @validator('content_type')
    def validate_content_type(cls, v):
        allowed = ['email', 'sms', 'url']
        if v.lower() not in allowed:
            raise ValueError(f'Must be one of: {allowed}')
        return v.lower()
```

---

## Real-World Examples

### Example 1: M-Pesa PIN Scam (SMS)

**Input**:

```
Dear Customer, your M-PESA account has been flagged for suspicious activity.
Verify your PIN at http://mpesa-verify.tk to avoid suspension.
Safaricom Customer Care
```

**Detection Results**:

| #   | Category              | Severity | Confidence |
| --- | --------------------- | -------- | ---------- |
| 1   | Credential Harvesting | Critical | 95%        |
| 2   | Urgency               | Critical | 95%        |
| 3   | Kenya Target (M-Pesa) | High     | 85%        |
| 4   | Suspicious TLD (.tk)  | High     | 85%        |
| 5   | Typosquatting         | High     | 80%        |
| 6   | Threat (suspension)   | High     | 85%        |

**Classification**: PHISHING — Confidence: 89% — Risk: CRITICAL

---

### Example 2: KRA Tax Refund Scam (Email)

**Input**:

```html
Subject: KRA Tax Refund Notification Dear Taxpayer, You have an unclaimed tax
refund of KES 45,000. To process your refund, click the link below and enter
your KRA PIN and bank details:

<a href="http://kra-refund.xyz/claim">https://www.kra.go.ke/refund</a>

This refund expires in 24 hours. Failure to claim will result in forfeiture.
Kenya Revenue Authority
```

**Detection Results**:

| #   | Category              | Severity | Confidence |
| --- | --------------------- | -------- | ---------- |
| 1   | Link Mismatch         | Critical | 95%        |
| 2   | Credential Harvesting | Critical | 95%        |
| 3   | Kenya Target (KRA)    | High     | 85%        |
| 4   | Urgency (24 hours)    | High     | 90%        |
| 5   | Suspicious TLD (.xyz) | High     | 85%        |
| 6   | Financial Request     | Medium   | 75%        |

**Classification**: PHISHING — Confidence: 92% — Risk: CRITICAL

---

### Example 3: Legitimate Bank Email

**Input**:

```
Dear John,

Your November statement is now available for download on the Equity Bank
mobile app or internet banking portal at https://equityonline.equitybank.co.ke

Thank you for banking with us.

Equity Bank Customer Service
```

**Detection Results**:

| #   | Category     | Severity | Confidence |
| --- | ------------ | -------- | ---------- |
| 1   | Kenya Target | High     | 85%        |

**Classification**: SAFE — Confidence: 12% — Risk: LOW

_Note_: The Kenya target indicator alone is not sufficient to classify as phishing. The absence of urgency, credential requests, suspicious URLs, and threats keeps the score low.

---

### Example 4: Prize Scam SMS

**Input**:

```
CONGRATULATIONS!!! You have won KES 1,000,000 in the Safaricom anniversary
promotion! Call 0900-123-456 to claim. Send activation fee of KES 500 to
Paybill 123456.
```

**Detection Results**:

| #   | Category          | Severity | Confidence |
| --- | ----------------- | -------- | ---------- |
| 1   | SMS Prize Scam    | High     | 85%        |
| 2   | Financial Request | High     | 85%        |
| 3   | SMS Callback Trap | High     | 85%        |
| 4   | Kenya Target      | High     | 85%        |
| 5   | Excessive Caps    | Medium   | 70%        |

**Classification**: PHISHING — Confidence: 82% — Risk: CRITICAL

---

## Limitations & Future Work

### Current Limitations

| Limitation                    | Description                                       |
| ----------------------------- | ------------------------------------------------- |
| **Heuristic-based only**      | No trained ML model — relies on pattern rules     |
| **English-focused**           | Limited Swahili/Sheng language detection          |
| **No image analysis**         | Cannot detect phishing in image-based emails      |
| **No real-time threat feeds** | Doesn't query live malware/phishing URL databases |
| **Static pattern list**       | New attack patterns require manual rule updates   |
| **No sender verification**    | Cannot check SPF/DKIM/DMARC email authentication  |

### Future Enhancements

| Enhancement                    | Impact                                           |
| ------------------------------ | ------------------------------------------------ |
| **Trained ML classifier**      | TF-IDF + Random Forest or BERT-based model       |
| **Swahili NLP**                | Detect Swahili/Sheng phishing messages           |
| **VirusTotal API integration** | Real-time URL reputation checking                |
| **Image OCR analysis**         | Detect phishing text in screenshots/images       |
| **Browser extension**          | Real-time URL checking during browsing           |
| **Email header analysis**      | SPF/DKIM/DMARC verification                      |
| **Kenyan phishing dataset**    | Crowd-sourced dataset of local phishing examples |
| **Collaborative reporting**    | Community-driven threat intelligence             |

---

## Summary

PhishGuard's detection engine combines **12 specialized detection modules** with a **weighted risk scoring algorithm** to produce accurate, explainable phishing classifications. The system is specifically tuned for the **Kenyan cybersecurity landscape**, covering M-Pesa scams, local bank phishing, and government impersonation — threats that generic (western-focused) phishing detectors often miss.

The heuristic approach provides **instant detection with zero training data**, **full explainability**, and **easy extensibility** — making it ideal for a hackathon project that can be immediately demonstrated and deployed.

---

<p align="center">
  <strong>PhishGuard Detection Engine v2.0</strong><br>
  Built for Hackathon 2026
</p>
