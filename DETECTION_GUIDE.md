# 🔬 Phish Guard Detection Guide

## How Phish Guard Detects Phishing & Smishing

This document provides a complete technical breakdown of the AI/ML detection techniques, algorithms, and tools used in Phish Guard v3.0 to identify phishing emails, SMS smishing, and malicious URLs.

---

## Table of Contents

1. [Detection Architecture Overview](#detection-architecture-overview)
2. [Tools & Technologies Used](#tools--technologies-used)
3. [Machine Learning Models](#machine-learning-models)
   - [URL Classifier (Random Forest)](#url-classifier-random-forest)
   - [Text Classifier (Gradient Boosting)](#text-classifier-gradient-boosting)
   - [Training Datasets](#training-datasets)
4. [Feature Extraction](#feature-extraction)
   - [Lexical Feature Extractor (35 URL Features)](#lexical-feature-extractor-35-url-features)
   - [Text Feature Extractor (30+ NLP Features)](#text-feature-extractor-30-nlp-features)
5. [Infrastructure Checks](#infrastructure-checks)
   - [SSL/TLS Certificate Validation](#ssltls-certificate-validation)
   - [Domain Age Analysis (WHOIS)](#domain-age-analysis-whois)
6. [Heuristic Detection Modules](#heuristic-detection-modules)
   - [Urgency Language Analysis](#1-urgency-language-analysis)
   - [Credential Harvesting Detection](#2-credential-harvesting-detection)
   - [Threat Pattern Matching](#3-threat-pattern-matching)
   - [Advanced URL Analysis](#4-advanced-url-analysis)
   - [Homograph Attack Detection](#5-homograph-attack-detection)
   - [Typosquatting Detection](#6-typosquatting-detection)
   - [Kenya-Specific Target Detection](#7-kenya-specific-target-detection)
   - [Suspicious Pattern Detection](#8-suspicious-pattern-detection)
   - [Link-Text Mismatch Detection](#9-link-text-mismatch-detection)
   - [Financial Request Detection](#10-financial-request-detection)
   - [Shannon Entropy Analysis](#11-shannon-entropy-analysis)
7. [Ensemble Scoring Algorithm](#ensemble-scoring-algorithm)
8. [Classification System](#classification-system)
9. [Explainable AI Output](#explainable-ai-output)
10. [Security Layer](#security-layer)
11. [Real-World Examples](#real-world-examples)
12. [Limitations & Future Work](#limitations--future-work)

---

## Detection Architecture Overview

ThreatLens v3.0 uses a **hybrid ensemble architecture** combining trained machine learning classifiers with a multi-layered heuristic detection engine. This approach was chosen because:

- **Best of both worlds** — ML catches subtle statistical patterns; heuristics catch known attack signatures
- **Explainable results** — each threat indicator is clearly described with severity and confidence
- **Trained on real data** — ML models train on real phishing URL and SMS spam datasets
- **Graceful degradation** — synthetic data fallback if datasets are unavailable
- **Kenya-focused context** — detects M-Pesa, Safaricom, KRA, and local bank scam patterns
- **Infrastructure validation** — SSL/TLS and domain age checks for URLs

### Detection Pipeline

```
Input Content (email / SMS / URL)
         │
         ▼
┌──────────────────────────────────┐
│  1. Input Sanitization           │  → Null byte removal, length validation
│  2. Content Type Detection       │  → email / sms / url
└──────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  3. Parallel Detection (Two Tracks)                          │
│                                                              │
│  ╔══════════════════════════╗  ╔═══════════════════════════╗ │
│  ║  TRACK A: ML MODELS     ║  ║  TRACK B: HEURISTIC RULES ║ │
│  ║                         ║  ║                           ║ │
│  ║  URL → LexicalExtractor ║  ║  Urgency Analysis         ║ │
│  ║     → RandomForest      ║  ║  Credential Harvesting    ║ │
│  ║     → SSL Checker       ║  ║  Threat Patterns          ║ │
│  ║     → Domain Age        ║  ║  Advanced URL Analysis    ║ │
│  ║                         ║  ║  Homograph Detection      ║ │
│  ║  Text → TextExtractor   ║  ║  Typosquatting Detection  ║ │
│  ║      → GradientBoosting ║  ║  Kenya Target Detection   ║ │
│  ║                         ║  ║  Suspicious CTA Patterns  ║ │
│  ║  Output: probability    ║  ║  Link Mismatch Detection  ║ │
│  ║  + top features         ║  ║  Financial Request Det.   ║ │
│  ║                         ║  ║  Impersonation Detection  ║ │
│  ║                         ║  ║  Invoice/Delivery Scams   ║ │
│  ║                         ║  ║  Subscription Scams       ║ │
│  ║                         ║  ║  Investment/Prize Scams   ║ │
│  ║                         ║  ║  SMS/Email-specific rules ║ │
│  ╚══════════════════════════╝  ╚═══════════════════════════╝ │
└──────────────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────┐
│  4. Ensemble Score Fusion        │  → Weighted blend of ML + heuristic
│  5. Classification               │  → safe / suspicious / phishing
│  6. Explanation Generation       │  → Human-readable threat report
│  7. Recommendations              │  → Actionable Kenya-focused advice
└──────────────────────────────────┘
         │
         ▼
    JSON Response (with ML features, indicators, score breakdown)
```

---

## Tools & Technologies Used

### Core Framework

| Tool         | Version | Purpose                                          |
| ------------ | ------- | ------------------------------------------------ |
| **Python**   | 3.9+    | Runtime for the ML + detection engine            |
| **FastAPI**  | latest  | High-performance async web framework for the API |
| **Uvicorn**  | latest  | ASGI server to serve FastAPI                     |
| **Pydantic** | v2      | Data validation for API requests and responses   |

### Machine Learning Libraries

| Tool             | Version | Purpose                                                            |
| ---------------- | ------- | ------------------------------------------------------------------ |
| **scikit-learn** | 1.4.0   | RandomForestClassifier, GradientBoostingClassifier, StandardScaler |
| **numpy**        | 1.26.3  | Numerical operations, feature vector construction                  |

### Optional Dependencies

| Tool             | Purpose                                              |
| ---------------- | ---------------------------------------------------- |
| **python-whois** | WHOIS domain age lookup for newly registered domains |

### Python Standard Library Modules

| Module                | Usage                                                        |
| --------------------- | ------------------------------------------------------------ |
| `re` (regex)          | Pattern matching for phishing indicators (100+ patterns)     |
| `urllib.parse`        | URL parsing — domain, path, query, fragment extraction       |
| `math.log2`           | Shannon entropy calculation for randomness detection         |
| `collections.Counter` | Character/word frequency counting for entropy + NLP analysis |
| `csv`                 | Dataset loading for ML model training                        |
| `ssl`                 | SSL/TLS certificate validation and inspection                |
| `socket`              | Network connection for SSL certificate retrieval             |
| `datetime`            | Timestamps, certificate expiry, domain age calculations      |
| `os`                  | Environment variable reading for configuration               |
| `unicodedata`         | Unicode character name lookup for homograph detection        |
| `ipaddress`           | IP address validation for URL analysis                       |

### Security Middleware

| Tool                             | Purpose                                                  |
| -------------------------------- | -------------------------------------------------------- |
| `fastapi.middleware.cors`        | Cross-Origin Resource Sharing control                    |
| `fastapi.middleware.trustedhost` | Host header validation                                   |
| Custom `rate_limiter`            | IP-based rate limiting (30 req/min, X-RateLimit headers) |
| Custom `security_headers`        | CSP, X-Frame-Options, X-Content-Type-Options, HSTS       |

### Frontend Security

| Tool             | Purpose                                                 |
| ---------------- | ------------------------------------------------------- |
| `security.js`    | Client-side sanitization, rate limiting, secure storage |
| `scanStorage.js` | localStorage persistence with CustomEvent sync          |

---

## Machine Learning Models

ThreatLens trains two specialized ML classifiers at startup — one for URLs and one for text content (email/SMS).

### URL Classifier (Random Forest)

**Model**: `sklearn.ensemble.RandomForestClassifier`

| Parameter       | Value          |
| --------------- | -------------- |
| n_estimators    | 100            |
| max_depth       | 10             |
| random_state    | 42             |
| Feature scaling | StandardScaler |

**Training process**:

1. Loads `datasets/phishing_urls.csv` (labeled URL dataset with `url` and `label` columns)
2. Extracts 35 lexical features per URL via `LexicalFeatureExtractor`
3. Applies `StandardScaler` normalization
4. Trains RandomForestClassifier
5. Falls back to synthetic data generation (1,000 samples) if dataset is unavailable

**Prediction output**: Phishing probability (0.0–1.0) + top 5 most important features for the prediction.

```python
# Prediction flow
lexical_features = LexicalFeatureExtractor.extract_url_features(url)
feature_vector = scaler.transform([feature_values])
phishing_probability = model.predict_proba(feature_vector)[0][1]
top_features = sorted(feature_importances, reverse=True)[:5]
```

---

### Text Classifier (Gradient Boosting)

**Model**: `sklearn.ensemble.GradientBoostingClassifier`

| Parameter       | Value                                      |
| --------------- | ------------------------------------------ |
| n_estimators    | 150 (real data) / 100 (synthetic fallback) |
| max_depth       | 6                                          |
| learning_rate   | 0.1                                        |
| random_state    | 42                                         |
| Feature scaling | StandardScaler                             |

**Training process**:

1. Loads `datasets/sms_spam.csv` (UCI SMS Spam Collection — 5,574 records, tab-delimited)
2. Labels: `ham` → 0 (legitimate), `spam` → 1 (phishing)
3. Extracts 30+ NLP features per message via `TextFeatureExtractor`
4. Applies `StandardScaler` normalization
5. Trains GradientBoostingClassifier
6. Falls back to synthetic data generation (1,000 samples) if dataset is unavailable

**Prediction output**: Phishing probability (0.0–1.0) + top 5 most important features.

---

### Training Datasets

| Dataset             | Records | Format            | Source                       |
| ------------------- | ------- | ----------------- | ---------------------------- |
| `phishing_urls.csv` | 208+    | CSV (url, label)  | Labeled phishing URL dataset |
| `sms_spam.csv`      | 5,574   | TSV (label, text) | UCI SMS Spam Collection      |

**Synthetic fallback**: If datasets are unavailable, both models generate 1,000 synthetic training samples (500 legitimate + 500 phishing) with statistically modeled feature distributions. This ensures the system always has working ML models.

---

## Feature Extraction

### Lexical Feature Extractor (35 URL Features)

**Class**: `LexicalFeatureExtractor`

Extracts 35 numerical features from any URL for ML classification. No network requests required — purely structural/lexical analysis.

| Category          | Features                                                                                                                             | Count |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------ | ----- |
| **Length**        | `url_length`, `domain_length`, `path_length`, `query_length`                                                                         | 4     |
| **Counts**        | `dot_count`, `hyphen_count`, `underscore_count`, `slash_count`, `digit_count`, `special_char_count`, `param_count`, `fragment_count` | 8     |
| **Ratios**        | `digit_ratio_domain`, `digit_ratio_url`, `special_char_ratio`                                                                        | 3     |
| **Structural**    | `subdomain_count`, `has_ip_address`, `has_https`, `has_port`, `has_at_symbol`, `has_double_slash`                                    | 6     |
| **TLD**           | `suspicious_tld`, `tld_length`                                                                                                       | 2     |
| **Entropy**       | `domain_entropy`, `url_entropy`, `path_entropy`                                                                                      | 3     |
| **Brand**         | `contains_brand`, `brand_in_subdomain`                                                                                               | 2     |
| **Path Keywords** | `path_has_login`, `path_has_verify`, `path_has_secure`, `path_has_account`, `path_has_update`                                        | 5     |
| **Shortener**     | `is_shortened`                                                                                                                       | 1     |

**Entropy calculation** (Shannon entropy):

$$H(X) = -\sum_{i=1}^{n} p(x_i) \log_2 p(x_i)$$

High entropy in a domain name (> 3.5) indicates randomly generated strings, common in phishing domains.

---

### Text Feature Extractor (30+ NLP Features)

**Class**: `TextFeatureExtractor`

Extracts 30+ NLP and statistical features from email/SMS text content.

**Word lists used for keyword density**:

- **URGENCY_WORDS** (36 words): urgent, immediately, expire, deadline, suspended, ...
- **CREDENTIAL_WORDS** (29 words): password, pin, otp, login, ssn, credit card, ...
- **THREAT_WORDS** (24 words): suspend, terminate, block, unauthorized, fraud, ...
- **REWARD_WORDS** (19 words): congratulations, winner, prize, bonus, free, lottery, ...

| Category               | Features                                                                                                                                                             | Count |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----- |
| **Length**             | `text_length`, `word_count`, `unique_word_count`, `avg_word_length`, `max_word_length`, `sentence_count`, `avg_sentence_length`                                      | 7     |
| **Character Ratios**   | `caps_ratio`, `digit_ratio`, `special_char_ratio`, `whitespace_ratio`                                                                                                | 4     |
| **Punctuation**        | `exclamation_count`, `question_mark_count`, `ellipsis_count`, `dollar_sign_count`                                                                                    | 4     |
| **Keyword Density**    | `urgency_word_count`, `credential_word_count`, `threat_word_count`, `reward_word_count`, `urgency_density`, `credential_density`, `threat_density`, `reward_density` | 8     |
| **URL Indicators**     | `url_count`, `has_ip_url`                                                                                                                                            | 2     |
| **Contact Info**       | `phone_number_count`, `email_address_count`                                                                                                                          | 2     |
| **Structural**         | `has_greeting`, `has_generic_greeting`, `has_signature`, `has_click_instruction`                                                                                     | 4     |
| **Information Theory** | `text_entropy`, `word_entropy`, `vocabulary_richness`                                                                                                                | 3     |
| **Content Type**       | `is_sms`, `is_email`                                                                                                                                                 | 2     |

**Keyword density** is calculated as:

$$\text{density} = \frac{\text{keyword\_count}}{\text{total\_word\_count}}$$

High urgency/credential/threat densities are strong phishing signals.

---

## Infrastructure Checks

### SSL/TLS Certificate Validation

**Class**: `SSLChecker`

Performs real-time SSL/TLS certificate inspection by connecting to port 443.

**What it checks**:

- Whether the domain has an SSL certificate at all
- Whether the certificate is valid (not expired, trusted CA)
- Certificate issuer information
- Days until certificate expiry

**Scoring**:

| Condition                     | SSL Score | Severity Generated |
| ----------------------------- | --------- | ------------------ |
| No SSL certificate            | 0.0       | High               |
| Invalid/expired certificate   | 0.2       | Critical           |
| Certificate expires < 30 days | 0.6       | Medium             |
| Valid certificate             | 1.0       | —                  |

```python
# SSL check flow
context = ssl.create_default_context()
with socket.create_connection((domain, 443), timeout=5) as sock:
    with context.wrap_socket(sock, server_hostname=domain) as ssock:
        cert = ssock.getpeercert()
        # Extract issuer, expiry, validity
```

---

### Domain Age Analysis (WHOIS)

**Class**: `DomainAgeChecker`

Uses WHOIS lookup to determine how long a domain has been registered. Newly registered domains are a strong phishing indicator.

**Scoring**:

| Domain Age | Score | Interpretation                      |
| ---------- | ----- | ----------------------------------- |
| > 2 years  | 1.0   | Well-established, likely legitimate |
| > 1 year   | 0.8   | Established                         |
| > 6 months | 0.6   | Relatively new                      |
| > 1 month  | 0.3   | Suspicious — recently registered    |
| < 1 month  | 0.1   | Very suspicious — likely phishing   |

**Generated threat indicators**:

- Domain < 30 days old → **critical** severity
- Domain < 180 days old → **high** severity

> **Note**: Domain age checking requires the optional `python-whois` package. The system operates without it but provides richer analysis when available.

---

## Heuristic Detection Modules

ThreatLens runs 11+ rule-based detection modules in parallel, each producing typed `ThreatIndicator` objects with category, description, severity (critical/high/medium/low), matched text, and confidence score.

### 1. Urgency Language Analysis

**Function**: `check_urgency_advanced()`

Detects urgency/pressure language designed to prevent victims from thinking carefully.

| Severity | Example Patterns                                                                          |
| -------- | ----------------------------------------------------------------------------------------- |
| Critical | "immediate action required", "account will be terminated", "unauthorized access detected" |
| High     | "act now", "expires today", "within 24 hours", "urgent action"                            |
| Medium   | "limited time", "don't miss", "hurry", "as soon as possible"                              |

**Also detects time-pressure patterns**:

- Countdown timers: `\d+ hours? left|remaining`
- Expiration: `expires? in \d+`
- Deadlines: `deadline: \d+`

---

### 2. Credential Harvesting Detection

**Function**: `check_credential_patterns()`

Detects requests for sensitive data — the core goal of most phishing attacks.

| Severity | Patterns                                                                  |
| -------- | ------------------------------------------------------------------------- |
| Critical | "enter your password/PIN/OTP", "confirm your identity", "social security" |
| High     | "update your credentials", "reset your password", "verify your account"   |
| Medium   | "confirm your details", "update your information", "verify your email"    |

Confidence: 0.95 for critical, 0.85 for high/medium.

---

### 3. Threat Pattern Matching

**Function**: `check_threat_patterns()`

Detects threatening language used to scare victims into acting.

| Severity | Patterns                                                                                      |
| -------- | --------------------------------------------------------------------------------------------- |
| Critical | "account will be permanently closed", "legal action will be taken", "reported to authorities" |
| High     | "will be suspended", "access will be revoked", "will be blocked"                              |
| Medium   | "may be affected", "could be compromised", "review required"                                  |

---

### 4. Advanced URL Analysis

**Function**: `analyze_url_advanced()`

Performs deep structural analysis on every URL found in the content.

| Check                       | Severity | Description                                                       |
| --------------------------- | -------- | ----------------------------------------------------------------- |
| IP address as domain        | High     | URL uses raw IP instead of domain name                            |
| URL shortener (14 tracked)  | Medium   | Shortened URL hides true destination (bit.ly, t.co, etc.)         |
| Suspicious TLD (24 tracked) | High     | Domain uses risky TLD (.tk, .xyz, .zip, .top, etc.)               |
| Homograph attack            | Critical | Lookalike characters replacing real ones                          |
| Typosquatting               | Critical | Misspelled brand names in domain                                  |
| Brand in subdomain          | High     | Legitimate brand name buried in subdomain                         |
| Suspicious path keywords    | Medium   | `/login`, `/verify`, `/secure`, `/account`, `.exe`                |
| High domain entropy         | Medium   | Randomly generated domain string (entropy > 3.5)                  |
| Excessive subdomains        | Medium   | 3+ subdomain levels indicate obfuscation                          |
| Domain spoofing             | Critical | Domain mimics legitimate site (checked against 30+ legit domains) |

**Legitimate domain list** includes both **global** (google.com, paypal.com, apple.com, etc.) and **Kenya-specific** (mpesa.co.ke, safaricom.co.ke, kcbgroup.com, equitybank.co.ke, etc.).

---

### 5. Homograph Attack Detection

**Function**: `detect_homograph_attack()`

Detects Unicode/lookalike character substitution attacks where visual similarity tricks users.

**Homograph map** (subset):

| Fake Character | Real Character | Example Attack |
| -------------- | -------------- | -------------- |
| а (Cyrillic)   | a (Latin)      | pаypal.com     |
| о (Cyrillic)   | o (Latin)      | gооgle.com     |
| е (Cyrillic)   | e (Latin)      | applе.com      |
| і (Cyrillic)   | i (Latin)      | mіcrosoft.com  |
| ο (Greek)      | o (Latin)      | amazοn.com     |
| 0 (zero)       | o              | g00gle.com     |
| 1 (one)        | l              | app1e.com      |

If any substitution is detected, a **critical** severity indicator is generated with the normalized domain.

---

### 6. Typosquatting Detection

**Function**: `detect_typosquatting()`

Detects misspelled domain names targeting known brands using edit distance analysis.

**Detection methods**:

- **Missing character**: `gogle.com` → `google.com`
- **Swapped characters**: `googel.com` → `google.com`
- **Extra character**: `gooogle.com` → `google.com`
- **Character substitution**: `g00gle.com` (0→o), `app1e.com` (1→l)
- **Suspicious additions**: `google-secure.com`, `paypal-login.com`

**Brands monitored** (25+): google, facebook, apple, microsoft, amazon, paypal, netflix, safaricom, mpesa, equity, kcb, cooperative, and more.

---

### 7. Kenya-Specific Target Detection

**Function**: `check_kenya_targets()`

Detects references to Kenyan financial services and institutions commonly targeted by phishing.

| Category     | Keywords                                                               |
| ------------ | ---------------------------------------------------------------------- |
| M-Pesa       | mpesa, m-pesa, paybill, till number, lipa na mpesa, send money         |
| Banks        | equity, kcb, cooperative, stanbic, absa, ncba, dtb, standard chartered |
| Telcos       | safaricom, airtel, telkom, faiba                                       |
| Government   | kra, nhif, nssf, ecitizen, huduma, tsc                                 |
| Mobile Money | fuliza, mshwari, kcb mpesa, hustler fund                               |

**Severity escalation**: If a Kenya target keyword appears alongside credential harvesting patterns, severity is automatically escalated to **critical** (e.g., "Enter your M-Pesa PIN").

---

### 8. Suspicious Pattern Detection

**Function**: `check_suspicious_patterns()`

A comprehensive catch-all module covering 60+ regex patterns across multiple scam categories:

| Category                   | Patterns | Description                                                       |
| -------------------------- | -------- | ----------------------------------------------------------------- |
| **Suspicious CTA**         | 13       | "click here", "tap now", "login immediately", "download attached" |
| **Impersonation**          | 5        | "from the security team", "automated alert detected"              |
| **Invoice Scam**           | 5        | "attached invoice", "outstanding payment", "payment due"          |
| **Subscription Scam**      | 4        | "subscription expired", "auto-renewal failed"                     |
| **Fake Device Alert**      | 4        | "new device login", "if this wasn't you"                          |
| **Delivery Scam**          | 3        | "package delayed", "delivery fee required"                        |
| **Tax/Refund Scam**        | 4        | "tax refund approved", "KRA has determined"                       |
| **Reward/Investment Scam** | 12       | "guaranteed returns", "earn $X per day", "you've won"             |
| **Financial Request**      | 7        | "transfer KSH", "wire transfer", "bitcoin wallet"                 |
| **Grammar Red Flags**      | 3        | "do the needful", "kindly", formal notification phrasing          |
| **SMS-specific**           | 6        | "reply with your PIN", "free M-Pesa money"                        |
| **Email-specific**         | 5        | "confidential message", "failure to comply"                       |

---

### 9. Link-Text Mismatch Detection

**Function**: `check_link_text_mismatch()`

Detects deceptive links where the visible text shows one URL but the actual hyperlink points to a different domain.

```
Visible: [www.safaricom.co.ke](http://phishing-scam.xyz/steal)
Result:  CRITICAL — displayed URL differs from actual destination
```

Confidence: 0.95. This is one of the most reliable phishing indicators.

---

### 10. Financial Request Detection

Detected as part of `check_suspicious_patterns()`, this covers:

- Money transfer requests (KSH, USD, $ amounts)
- Fee advance scams ("pay a small processing fee")
- Credit card information requests
- Wire transfer instructions
- Cryptocurrency wallet scams (Bitcoin, ETH, USDT)

---

### 11. Shannon Entropy Analysis

**Function**: `calculate_entropy()`

Measures the randomness of strings using information theory.

$$H(X) = -\sum_{i=1}^{n} p(x_i) \log_2 p(x_i)$$

| Entropy Value | Interpretation                               |
| ------------- | -------------------------------------------- |
| < 2.5         | Low randomness — likely real words           |
| 2.5 – 3.5     | Normal — typical domain names                |
| > 3.5         | High randomness — likely generated/malicious |

Applied to: domain names, URL paths, full URLs, email/SMS text content, and per-word entropy.

---

## Ensemble Scoring Algorithm

ThreatLens v3.0 uses an intelligent ensemble that combines the ML classifier probability with the heuristic threat indicator score.

### Score Fusion Logic

```
Let:
  H = heuristic_score (from weighted threat indicators)
  M = ml_phishing_probability (from Random Forest or Gradient Boosting)
  I = total threat indicators found
  C = critical indicator count
  S = serious indicators (critical + high)

Fusion rules:
  IF I == 0:
    combined = M × 0.3          # No heuristic evidence → dampen ML
  ELIF S == 0 AND medium <= 1:
    combined = 0.7H + 0.3M      # Weak signals → trust heuristic more
  ELSE:
    combined = max(max(H, M), 0.55H + 0.45M)  # Real threats → use maximum

Safety floors:
  IF S >= 3 OR C >= 2: combined >= 0.85
  IF S >= 2 OR C >= 1: combined >= 0.65
  IF high >= 1 AND medium >= 2: combined >= 0.55
  IF S >= 1 AND medium >= 1: combined >= 0.45
  IF medium >= 3: combined >= 0.40
```

**Design rationale**:

- When ML finds phishing but heuristics find nothing, the ML score is dampened (×0.3) to prevent false positives on stylistically unusual but legitimate content
- When heuristics find real threats, the maximum of ML and heuristic scores is used to ensure nothing is missed
- Safety floor rules guarantee that multiple serious indicators always produce a high combined score

### Heuristic Score Calculation

Each threat indicator contributes to the heuristic score based on severity and confidence:

| Severity | Weight |
| -------- | ------ |
| Critical | 0.45   |
| High     | 0.30   |
| Medium   | 0.18   |
| Low      | 0.08   |

**Score formula**: $\text{score} = \sum (\text{weight}_i \times \text{confidence}_i)$

**Boosting rules** (common phishing combinations):
| Combination | Boost |
| -------------------------------- | ------ |
| Critical + Credential harvesting | ×1.5 |
| Credential + Urgency | ×1.4 |
| Threat + Credential | ×1.4 |
| Credential + URL issue | ×1.3 |
| Urgency + URL issue | ×1.3 |

---

## Classification System

### Thresholds

| Combined Score | Classification | Risk Level |
| -------------- | -------------- | ---------- |
| ≥ 0.70         | **phishing**   | Critical   |
| 0.40 – 0.69    | **phishing**   | High       |
| 0.20 – 0.39    | **suspicious** | Medium     |
| < 0.20         | **safe**       | Low        |

### Indicator Deduplication

Before scoring, indicators are deduplicated by `(category, matched_text)` tuple and sorted by severity (critical first) then by confidence (highest first). Maximum 15 indicators are returned to the frontend.

---

## Explainable AI Output

Every analysis returns a structured, human-readable report:

### Threat Indicators

Each indicator includes:

```json
{
  "category": "Credential Harvesting",
  "description": "Requests sensitive data: 'enter your pin'",
  "severity": "critical",
  "matched_text": "enter your pin",
  "confidence": 0.95
}
```

### ML Feature Transparency

The response includes an `ml_features` object exposing:

| Field                     | Description                                        |
| ------------------------- | -------------------------------------------------- |
| `lexical_features`        | All 35 URL features extracted (for URL scans)      |
| `text_features`           | All 30+ text features extracted (for email/SMS)    |
| `ssl_status`              | SSL certificate details (validity, issuer, expiry) |
| `domain_age`              | WHOIS registration age and score                   |
| `ml_phishing_probability` | Raw ML model output (0.0–1.0)                      |
| `top_ml_features`         | Top 5 features driving the ML prediction           |
| `model_used`              | "RandomForest" (URL) or "GradientBoosting" (text)  |

### Analysis Details

```json
{
  "urls_found": 2,
  "total_indicators": 7,
  "severity_breakdown": { "critical": 2, "high": 3, "medium": 1, "low": 1 },
  "heuristic_score": 0.82,
  "ml_score": 0.91,
  "combined_score": 0.91,
  "model_type": "GradientBoosting",
  "features_extracted": 35,
  "analysis_version": "3.0"
}
```

### Contextual Recommendations

Recommendations are generated based on classification and detected categories:

- **Phishing**: "DO NOT click links", "Delete immediately", "Contact Safaricom (100)", "Report to bank fraud desk"
- **Suspicious**: "Verify through official channels", "Check sender carefully", "Take your time"
- **Safe**: General hygiene tips — verify senders, don't share PINs, use official apps

---

## Security Layer

### Input Protection

| Layer                | Implementation                                            |
| -------------------- | --------------------------------------------------------- |
| Input sanitization   | Null byte removal, HTML tag stripping, length enforcement |
| URL validation       | Scheme validation, length limits                          |
| Pydantic validators  | Type checking, enum validation, content sanitization      |
| Content length limit | Configurable `MAX_CONTENT_LENGTH` (default: 10,000 chars) |

### API Protection

| Layer            | Implementation                                                    |
| ---------------- | ----------------------------------------------------------------- |
| CORS             | Environment-based (`FRONTEND_URL`, `ALLOWED_ORIGINS`)             |
| Trusted hosts    | `ALLOWED_HOSTS` whitelist                                         |
| Rate limiting    | 30 requests/minute per IP with `X-RateLimit-*` headers            |
| Security headers | CSP, X-Frame-Options: DENY, X-Content-Type-Options: nosniff, HSTS |

### Frontend Security

| Layer            | Implementation                                                   |
| ---------------- | ---------------------------------------------------------------- |
| `security.js`    | XSS sanitization, client-side rate limiting, secure localStorage |
| `scanStorage.js` | Validated JSON storage with CustomEvent real-time sync           |

---

## Real-World Examples

### Example 1: Kenya M-Pesa Phishing SMS

**Input**:

```
MPESA: Your account has been suspended due to unusual activity.
Verify your PIN at http://mpesa-verify.tk/login to restore access.
Act within 2 hours or your funds will be frozen.
```

**Detection results**:

| Module                 | Finding                                    | Severity |
| ---------------------- | ------------------------------------------ | -------- |
| Kenya Target Detection | References 'mpesa' with credential request | Critical |
| Credential Harvesting  | Requests PIN                               | Critical |
| Suspicious TLD         | Domain uses .tk TLD                        | High     |
| Urgency Analysis       | "act within 2 hours"                       | High     |
| Threatening Language   | "funds will be frozen"                     | High     |
| URL Path Analysis      | Contains /login path                       | Medium   |
| ML Text Classifier     | Probability: 0.94                          | —        |
| **Combined Score**     | **0.97**                                   | Critical |

---

### Example 2: Email Invoice Scam

**Input**:

```
Dear Valued Customer,

We have detected unauthorized access to your account.
Please click here to verify your identity immediately.
Failure to comply within 24 hours will result in account suspension.

Download the attached invoice for your records.
```

**Detection results**:

| Module                | Finding                               | Severity |
| --------------------- | ------------------------------------- | -------- |
| Impersonation         | "We have detected unauthorized" alert | Critical |
| Credential Harvesting | "verify your identity"                | Critical |
| Suspicious CTA        | "click here" instruction              | High     |
| Threatening Language  | "account suspension"                  | High     |
| Urgency Analysis      | "within 24 hours"                     | High     |
| Invoice Scam          | "attached invoice"                    | High     |
| Generic Greeting      | "Dear Valued Customer"                | Low      |
| ML Text Classifier    | Probability: 0.89                     | —        |
| **Combined Score**    | **0.93**                              | Critical |

---

### Example 3: Legitimate Bank Notification

**Input**:

```
Hi John, your KCB account statement for May 2025 is ready.
View it on the KCB app or at www.kcbgroup.com.
```

**Detection results**:

| Module                 | Finding                                  | Severity |
| ---------------------- | ---------------------------------------- | -------- |
| Kenya Target Detection | References 'kcb' (no credential request) | Medium   |
| ML Text Classifier     | Probability: 0.08                        | —        |
| **Combined Score**     | **0.06**                                 | Low      |
| **Classification**     | **safe**                                 | ✅       |

---

## Limitations & Future Work

### Current Limitations

- **Static model training** — Models train once at startup; no online learning from user feedback
- **WHOIS dependency** — Domain age checking requires optional `python-whois` package
- **SSL check latency** — Real-time SSL connections add ~2–5 seconds for URL scans
- **Dataset size** — URL dataset (208 records) is small; SMS dataset (5,574) is moderate
- **No image analysis** — Cannot detect phishing in screenshots or image-based emails
- **Single language** — Pattern matching primarily targets English content
- **No header analysis** — Email headers (SPF, DKIM, DMARC) are not inspected

### Future Improvements

- **Deep learning models** — BERT/transformer-based classifiers for semantic understanding
- **Larger training datasets** — Expand URL dataset to 50,000+ labeled samples
- **Online learning** — Incorporate user feedback to improve models over time
- **Swahili/Sheng support** — Detect phishing in Kenyan vernacular languages
- **Image OCR** — Extract and analyze text from screenshot-based phishing
- **Email header analysis** — SPF/DKIM/DMARC validation for email authenticity
- **Real-time threat feeds** — Integration with PhishTank, VirusTotal, Google Safe Browsing
- **Browser extension** — Real-time URL scanning while browsing

---

_ThreatLens v3.0 — Hybrid ML + Heuristic Phishing Detection Engine_
_Built for the Kenyan threat landscape_
