# AI-Phishing-Detector

# 🛡️ AI Phishing Detector for WhatsApp/Instagram DMs

> Detects phishing, scam, and social engineering messages in DM-style short chats with India-specific pattern support (Hindi, Hinglish, regional scams)

---

# 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    USER INTERFACE                           │
│     Streamlit Dashboard (port 8501)                         │
└──────────────────────┬──────────────────────────────────────┘
                       │ HTTP POST /analyze
┌──────────────────────▼──────────────────────────────────────┐
│                  FastAPI Backend (port 8000)                 │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────┐ │
│  │ AI Analyzer │  │  URL Checker │  │  Pattern Engine    │ │
│  │ (NLP/ML)    │  │  (Domain DB) │  │  (India Patterns)  │ │
│  └─────────────┘  └──────────────┘  └────────────────────┘ │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│                    MongoDB (port 27017)                      │
│  - Message logs  - Flagged records  - Pattern updates        │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔍 Detection Engine — 3 Layers

### Layer 1: AI Analyzer (`core/analyzer.py`)
- Weighted keyword scoring with 90+ phishing signals
- Structural analysis (caps ratio, urgency words, exclamations)
- Manipulation pattern regex (social engineering)
- **Upgrade path**: Replace `analyze()` with HuggingFace DistilBERT/IndicBERT

### Layer 2: URL Checker (`core/url_checker.py`)
- URL extraction from any text format
- Shortener detection (20+ services)
- Typosquatting detection for Indian brands (SBI, HDFC, PayTM, etc.)
- IP-based URL detection
- High-risk TLD detection (`.tk`, `.ml`, `.ga`, `.xyz`, etc.)
- Homograph attack detection

### Layer 3: Pattern Engine (`core/pattern_engine.py`)
- 30+ India-specific scam pattern categories
- Languages: English, Hindi, Hinglish
- Covers: KYC fraud, KBC scam, OTP theft, PM scheme scams, WFH fraud
- Legal threat patterns (Cybercrime, ED, Income Tax)

---

## 🇮🇳 India-Specific Scam Patterns

| Category | Examples |
|----------|---------|
| **Banking Fraud** | SBI KYC update, RBI compensation, ATM PIN scam |
| **KYC Scams** | "Complete KYC within 24 hours", Aadhaar link fraud |
| **OTP Theft** | "Bhai OTP send kar", "Share the OTP you received" |
| **Lottery Scams** | KBC winner, Amazon lucky draw, PM scheme bonus |
| **Job Scams** | "Ghar se karo kaam", daily earning without investment |
| **Legal Threats** | Cybercrime FIR, ED notice, Court summon, arrest threat |
| **Social Engineering** | "Main tumhara dost hu", hospital emergency fraud |
| **Chain Messages** | WhatsApp Gold, forward to N contacts |

---

## 🚀 Quick Start

### Option 1: Docker (Recommended)
```bash
git clone https://github.com/your-repo/phishing-detector
cd phishing-detector
docker-compose up -d
```
- Frontend: http://localhost:8501
- API Docs: http://localhost:8000/docs

### Option 2: Local Development
```bash
# Backend
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000

# Frontend (new terminal)
cd frontend
pip install streamlit requests
streamlit run app.py
```

### Option 3: API Only
```bash
cd backend && pip install fastapi uvicorn pydantic && uvicorn main:app --reload
```

---

## 📡 API Reference

### `POST /analyze`
Analyze a single message.

**Request:**
```json
{
  "message": "Your SBI account is blocked. Share OTP immediately.",
  "platform": "whatsapp",
  "language": "en"
}
```

**Response:**
```json
{
  "is_phishing": true,
  "confidence": 0.87,
  "risk_level": "CRITICAL",
  "threat_categories": ["otp_theft", "bank_impersonation", "account_threat"],
  "url_threats": [],
  "pattern_matches": ["SBI KYC scam", "Direct OTP request"],
  "explanation": "AI detected OTP theft patterns | Matched scam patterns: SBI KYC scam",
  "recommendation": "DANGER: This is almost certainly a scam. Block immediately..."
}
```

### `GET /patterns/india` — List all India-specific patterns
### `GET /stats` — System statistics
### `POST /analyze/batch` — Analyze up to 20 messages

---

## 🧪 Running Tests
```bash
cd phishing-detector
pip install pytest
pytest tests/ -v
```

---

## 🔧 Upgrading to Transformer Models

Replace `PhishingAnalyzer.analyze()` in `backend/core/analyzer.py`:

```python
# Install: pip install transformers torch
from transformers import pipeline

class PhishingAnalyzer:
    def __init__(self):
        # For English: use distilbert-base-uncased
        # For Indian languages: use ai4bharat/indic-bert
        self.classifier = pipeline(
            "text-classification",
            model="distilbert-base-uncased-finetuned-sst-2-english"
        )

    def analyze(self, text: str) -> dict:
        result = self.classifier(text[:512])[0]
        score = result["score"] if result["label"] == "NEGATIVE" else 1 - result["score"]
        return {"score": score, "categories": [], "component_scores": {}}
```

**Recommended Models:**
- `distilbert-base-uncased` — Fast, English, fine-tune on phishing dataset
- `ai4bharat/indic-bert` — Multi-language Indian languages
- `google/muril-base-cased` — 17 Indian languages
- `roberta-base` — More accurate, larger

---

## 🏋️ Training Your Own Model

1. Collect dataset: Phishing DMs + safe DMs (label 0/1)
2. Preprocess: tokenize, clean, lowercase
3. Fine-tune DistilBERT:
```python
from transformers import DistilBertForSequenceClassification, Trainer
model = DistilBertForSequenceClassification.from_pretrained("distilbert-base-uncased", num_labels=2)
# ... trainer setup, dataset, training loop
```
4. Save and load in `PhishingAnalyzer`

**Datasets to use:**
- PhishTank dataset
- SMS Spam Collection (UCI)
- Custom collected Indian scam messages

---

## 🌐 Optional External APIs

Add to `core/url_checker.py`:
```python
# Google Safe Browsing
import requests
def check_google_safe_browsing(url, api_key):
    resp = requests.post(
        f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
        json={"client": {"clientId": "phishing-detector", "clientVersion": "1.0"},
              "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                            "platformTypes": ["ANY_PLATFORM"],
                            "threatEntryTypes": ["URL"],
                            "threatEntries": [{"url": url}]}}
    )
    return bool(resp.json().get("matches"))
```

APIs to integrate:
- **Google Safe Browsing API** — free, 10k req/day
- **VirusTotal API** — URL/domain reputation
- **PhishTank API** — community phishing database

---

## 📊 Logging with ELK Stack

```yaml
# Add to docker-compose.yml
elasticsearch:
  image: elasticsearch:8.13.0
  environment:
    - discovery.type=single-node

kibana:
  image: kibana:8.13.0
  ports:
    - "5601:5601"
```

---

## 🔐 Security Notes

- Never log complete messages containing personal info
- Use HTTPS in production
- Rate-limit `/analyze` endpoint (add `slowapi`)
- Rotate API keys for external services

---

## 📁 Project Structure

```
phishing-detector/
├── backend/
│   ├── main.py                 # FastAPI app
│   ├── core/
│   │   ├── analyzer.py         # AI/ML analyzer
│   │   ├── url_checker.py      # URL threat detection
│   │   └── pattern_engine.py   # India pattern library
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── app.py                  # Streamlit dashboard
│   └── Dockerfile
├── tests/
│   └── test_detector.py        # pytest test suite
├── docker-compose.yml
└── README.md
```

---

## 📞 Report Cybercrime (India)
- **National Cyber Crime Portal**: [cybercrime.gov.in](https://cybercrime.gov.in)
- **Helpline**: 1930
- **WhatsApp**: Forward suspicious messages to 8800007281 (CERT-In)
