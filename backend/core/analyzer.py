"""
PhishingAnalyzer - Core ML/NLP analysis engine
Uses rule-based scoring + keyword features (no heavy GPU required)
Designed to be drop-in replaceable with DistilBERT/RoBERTa
"""

import re
import math
from typing import Dict, List, Tuple


class PhishingAnalyzer:
    """
    Hybrid analyzer combining:
    1. Feature extraction (urgency, manipulation, impersonation signals)
    2. TF-IDF-style keyword scoring
    3. Structural pattern analysis

    To upgrade to transformer model, replace analyze() with HuggingFace inference.
    """

    def __init__(self):
        self._build_feature_weights()

    def _build_feature_weights(self):
        """Weighted feature vocabulary (simulates trained model weights)"""

        # High-signal phishing indicators
        self.HIGH_RISK_TOKENS = {
            # OTP / Credential harvesting
            "otp": 0.85, "one time password": 0.85, "verification code": 0.80,
            "share your otp": 0.95, "send me otp": 0.95, "enter otp": 0.75,
            "cvv": 0.85, "pin number": 0.80, "atm pin": 0.90,

            # Urgency signals
            "urgent": 0.65, "immediately": 0.60, "right now": 0.60,
            "account suspended": 0.80, "account blocked": 0.80,
            "limited time": 0.65, "expires soon": 0.65, "act now": 0.70,
            "last warning": 0.75, "final notice": 0.75,

            # Prize / lottery scams
            "you have won": 0.85, "you've won": 0.85, "winner": 0.70,
            "congratulations": 0.55, "lottery": 0.75, "jackpot": 0.75,
            "prize money": 0.80, "claim your prize": 0.90,
            "free gift": 0.70, "selected randomly": 0.80,

            # Job scams
            "work from home": 0.60, "earn per day": 0.80, "part time job": 0.65,
            "earning opportunity": 0.75, "investment returns": 0.75,
            "double your money": 0.90, "guaranteed returns": 0.85,

            # Impersonation signals
            "i am your friend": 0.75, "this is your bank": 0.85,
            "official message": 0.65, "from rbi": 0.85, "from sbi": 0.80,
            "government scheme": 0.70, "pm scheme": 0.75,
            "irs": 0.70, "tax refund": 0.75,

            # Payment manipulation
            "send money": 0.70, "transfer funds": 0.75,
            "upi payment": 0.60, "pay now": 0.65,
            "wallet": 0.45, "paytm": 0.40, "phonepe": 0.40,

            # Fear tactics
            "legal action": 0.75, "arrested": 0.80, "police": 0.65,
            "cybercrime": 0.60, "court notice": 0.80, "fir": 0.75,
            "penalty": 0.65, "fine": 0.50,
        }

        # Medium-risk contextual tokens
        self.MEDIUM_RISK_TOKENS = {
            "click here": 0.45, "visit link": 0.40, "open link": 0.40,
            "verify account": 0.55, "update details": 0.50,
            "kyc": 0.55, "kyc update": 0.70, "complete kyc": 0.70,
            "aadhar": 0.40, "pan card": 0.40,
            "password": 0.45, "login": 0.35,
            "offer": 0.30, "discount": 0.25, "cashback": 0.35,
            "recharge": 0.30, "free recharge": 0.65,
            "don't tell anyone": 0.70, "keep secret": 0.65, "confidential": 0.45,
            "trusted friend": 0.50, "old friend": 0.45,
        }

        # Manipulation / social engineering patterns
        self.MANIPULATION_PATTERNS = [
            (r"(?:i'm|i am|this is)\s+(?:your|ur)\s+(?:friend|bro|sister|brother|dost|yaar)", 0.75),
            (r"don'?t\s+(?:tell|share|say)\s+(?:anyone|anybody)", 0.80),
            (r"(?:keep|its)\s+(?:this\s+)?(?:between|secret|confidential)", 0.75),
            (r"(?:only|just)\s+(?:you|u)\s+(?:can|could|are)\s+(?:help|save)", 0.70),
            (r"(?:trust|believe)\s+me", 0.55),
            (r"(?:emergency|urgent)\s+(?:help|money|funds)", 0.80),
            (r"stuck\s+(?:at|in)\s+(?:airport|hospital|abroad)", 0.85),
            (r"send\s+(?:me\s+)?(?:your\s+)?(?:otp|pin|password|code)", 0.95),
        ]

        # URL patterns (risk scoring)
        self.SUSPICIOUS_URL_PATTERNS = [
            (r"bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|shorturl", 0.60),
            (r"(?:bank|sbi|hdfc|icici|paytm|gov|rbi)\.\w{2,5}\.(?:com|in|tk|ml|ga|cf)", 0.90),
            (r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", 0.85),  # IP-based URLs
            (r"(?:verify|update|login|secure|account)\.\w+\.(?:tk|ml|ga|cf|xyz)", 0.90),
            (r"(?:free|win|prize|lucky).*\.(?:tk|ml|ga|cf|buzz|click)", 0.85),
        ]

    def analyze(self, text: str) -> Dict:
        """
        Main analysis function. Returns score + categories.
        Replace this method body with transformer inference to upgrade.
        """
        text_lower = text.lower()
        words = re.findall(r'\b\w+\b', text_lower)
        word_set = set(words)

        scores = []
        categories = []

        # 1. High-risk token scoring
        hr_score, hr_cats = self._score_tokens(text_lower, self.HIGH_RISK_TOKENS, "high_risk")
        scores.append(hr_score)
        categories.extend(hr_cats)

        # 2. Medium-risk token scoring
        mr_score, mr_cats = self._score_tokens(text_lower, self.MEDIUM_RISK_TOKENS, "medium_risk")
        scores.append(mr_score * 0.6)
        categories.extend(mr_cats)

        # 3. Manipulation pattern scoring
        mp_score, mp_cats = self._score_patterns(text_lower, self.MANIPULATION_PATTERNS)
        scores.append(mp_score)
        categories.extend(mp_cats)

        # 4. Structural features
        struct_score, struct_cats = self._structural_analysis(text)
        scores.append(struct_score)
        categories.extend(struct_cats)

        # 5. Urgency intensity (exclamations, caps)
        urgency_score = self._urgency_intensity(text)
        scores.append(urgency_score)
        if urgency_score > 0.3:
            categories.append("high_urgency")

        # Weighted combination
        final_score = self._combine_scores(scores)

        return {
            "score": final_score,
            "categories": list(set(categories)),
            "component_scores": {
                "high_risk_tokens": round(hr_score, 3),
                "medium_risk_tokens": round(mr_score, 3),
                "manipulation_patterns": round(mp_score, 3),
                "structural": round(struct_score, 3),
                "urgency": round(urgency_score, 3),
            }
        }

    def _score_tokens(self, text: str, vocab: Dict[str, float], category_prefix: str) -> Tuple[float, List[str]]:
        max_score = 0.0
        categories = []
        matched_count = 0

        for phrase, weight in vocab.items():
            if phrase in text:
                max_score = max(max_score, weight)
                matched_count += 1
                # Map to semantic categories
                cat = self._token_to_category(phrase)
                if cat:
                    categories.append(cat)

        # Boost for multiple matches
        if matched_count > 2:
            max_score = min(max_score * (1 + matched_count * 0.05), 1.0)

        return max_score, categories

    def _score_patterns(self, text: str, patterns: List[Tuple]) -> Tuple[float, List[str]]:
        max_score = 0.0
        categories = []

        for pattern, weight in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                max_score = max(max_score, weight)
                if weight >= 0.70:
                    categories.append("social_engineering")
                if "otp" in pattern or "password" in pattern:
                    categories.append("credential_theft")

        return max_score, categories

    def _structural_analysis(self, text: str) -> Tuple[float, List[str]]:
        score = 0.0
        categories = []

        # Short message with links = suspicious
        urls = re.findall(r'https?://\S+', text)
        if urls and len(text) < 200:
            score += 0.4
            categories.append("link_bait")

        # Multiple exclamations
        if text.count('!') >= 3:
            score += 0.2

        # All-caps words (shouting)
        caps_words = re.findall(r'\b[A-Z]{4,}\b', text)
        if len(caps_words) >= 2:
            score += 0.15
            categories.append("high_urgency")

        # Phone numbers with urgent context
        has_phone = bool(re.search(r'(?:\+91|0)\s*\d{10}', text))
        has_call_now = bool(re.search(r'call\s+(?:now|immediately|urgently)', text.lower()))
        if has_phone and has_call_now:
            score += 0.5
            categories.append("vishing")

        # KYC + link combo
        if re.search(r'kyc', text.lower()) and urls:
            score += 0.6
            categories.append("kyc_fraud")

        # OTP request
        if re.search(r'(?:send|share|give|tell).{0,30}otp', text.lower()):
            score += 0.9
            categories.append("otp_theft")

        return min(score, 1.0), categories

    def _urgency_intensity(self, text: str) -> float:
        """Score urgency based on linguistic intensity markers"""
        score = 0.0
        urgency_words = ["immediately", "urgent", "asap", "right now", "hurry",
                         "quickly", "fast", "instant", "warning", "alert",
                         "last chance", "limited", "expire"]
        count = sum(1 for w in urgency_words if w in text.lower())
        score = min(count * 0.15, 0.7)

        # Caps ratio
        alpha_chars = [c for c in text if c.isalpha()]
        if alpha_chars:
            caps_ratio = sum(1 for c in alpha_chars if c.isupper()) / len(alpha_chars)
            if caps_ratio > 0.5:
                score += 0.3

        return min(score, 1.0)

    def _combine_scores(self, scores: List[float]) -> float:
        if not scores:
            return 0.0
        # Take max + weighted mean to avoid score dilution
        max_s = max(scores)
        mean_s = sum(scores) / len(scores)
        return round(min(max_s * 0.6 + mean_s * 0.4, 1.0), 4)

    def _token_to_category(self, phrase: str) -> Optional[str]:
        categories_map = {
            "otp": "otp_theft", "password": "credential_theft",
            "pin": "credential_theft", "cvv": "credential_theft",
            "won": "lottery_scam", "winner": "lottery_scam",
            "lottery": "lottery_scam", "prize": "lottery_scam",
            "work from home": "job_scam", "earn per day": "job_scam",
            "double your money": "investment_scam", "guaranteed returns": "investment_scam",
            "account suspended": "account_threat", "account blocked": "account_threat",
            "legal action": "legal_threat", "arrested": "legal_threat",
            "rbi": "impersonation", "sbi": "impersonation",
            "government scheme": "impersonation", "pm scheme": "impersonation",
            "kyc": "kyc_fraud",
        }
        for key, cat in categories_map.items():
            if key in phrase:
                return cat
        return None

    def model_info(self) -> Dict:
        return {
            "type": "hybrid_rule_ml",
            "version": "1.0.0",
            "features": len(self.HIGH_RISK_TOKENS) + len(self.MEDIUM_RISK_TOKENS),
            "patterns": len(self.MANIPULATION_PATTERNS),
            "upgrade_path": "Replace analyze() with HuggingFace DistilBERT/IndicBERT inference"
        }


# Type annotation fix
from typing import Optional