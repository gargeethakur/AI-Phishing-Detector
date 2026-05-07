"""
PatternEngine - Rule-based scam pattern detection with India-specific patterns
Covers: Hindi, Hinglish, regional scam templates
"""

import re
from typing import Dict, List, Tuple


class PatternEngine:
    """
    India-specific scam pattern library covering:
    - UPI/Banking fraud (SBI, HDFC, PayTM)
    - KYC update scams
    - Work-from-home fraud
    - Lottery / prize scams
    - OTP theft
    - Aadhaar/PAN fraud
    - WhatsApp forward chains
    - Hindi + Hinglish patterns
    - Regional language transliteration patterns
    """

    def __init__(self):
        self._build_patterns()

    def _build_patterns(self):
        """All patterns as (regex, weight, category, description)"""

        # === INDIA BANKING SCAMS ===
        self.INDIA_BANKING = [
            (r"sbi\s+(?:kyc|account|card)\s+(?:update|expire|block)", 0.90, "kyc_fraud", "SBI KYC scam"),
            (r"(?:hdfc|icici|axis|kotak)\s+(?:alert|warning|notice)", 0.80, "bank_impersonation", "Bank alert impersonation"),
            (r"(?:your\s+)?(?:debit|credit)\s+card\s+(?:blocked|expired|suspended)", 0.80, "card_fraud", "Card block scam"),
            (r"rbi\s+(?:compensation|refund|scheme|lottery)", 0.90, "rbi_impersonation", "RBI impersonation"),
            (r"atm\s+(?:pin|password)\s+(?:change|update|share)", 0.90, "atm_fraud", "ATM PIN scam"),
            (r"net\s*banking\s+(?:suspend|block|expire)", 0.85, "netbanking_fraud", "Net banking scam"),
            (r"upi\s+(?:id|pin|blocked|limit|error)", 0.75, "upi_fraud", "UPI fraud"),
            (r"(?:paytm|phonepe|gpay)\s+(?:kyc|limit|block|verify)", 0.80, "wallet_fraud", "Payment wallet scam"),
        ]

        # === KYC SCAMS ===
        self.KYC_SCAMS = [
            (r"kyc\s+(?:not\s+done|pending|expire|update|complete)", 0.85, "kyc_fraud", "KYC pending scam"),
            (r"(?:complete|update|verify)\s+(?:your\s+)?kyc\s+(?:within|before|to\s+avoid)", 0.90, "kyc_fraud", "KYC threat scam"),
            (r"kyc\s+(?:link|form|portal)\s+(?:sent|share|click)", 0.85, "kyc_phishing", "KYC link scam"),
            (r"aadhar\s+(?:link|update|otp|verify)", 0.80, "aadhaar_fraud", "Aadhaar fraud"),
            (r"pan\s+card\s+(?:link|verify|update|block)", 0.75, "pan_fraud", "PAN card fraud"),
        ]

        # === OTP THEFT PATTERNS ===
        self.OTP_THEFT = [
            (r"(?:share|send|give|tell|bata)\s+(?:me\s+)?(?:the\s+)?otp", 0.95, "otp_theft", "Direct OTP request"),
            (r"otp\s+(?:received|aaya|aayega|will\s+come)", 0.85, "otp_theft", "OTP guidance"),
            (r"otp\s+(?:send|kar|karo|do|share)", 0.95, "otp_theft", "OTP request in Hinglish"),
            (r"code\s+(?:share|send|bata|do)", 0.85, "otp_theft", "Code share request"),
            (r"message\s+(?:mein|me\s+jo)\s+(?:code|number|otp)", 0.90, "otp_theft", "OTP from message"),
        ]

        # === LOTTERY / PRIZE SCAMS ===
        self.LOTTERY_SCAMS = [
            (r"(?:you|aap)\s+(?:have|ne)\s+(?:won|jeeta)", 0.85, "lottery_scam", "Win claim"),
            (r"(?:lucky|winner|vijeta)\s+(?:draw|selection|prize)", 0.85, "lottery_scam", "Lucky draw scam"),
            (r"(?:\d+\s+lakh|\d+\s+crore)\s+(?:prize|lottery|cash)", 0.90, "lottery_scam", "Prize amount scam"),
            (r"amazon\s+(?:lucky|spin|winner|prize|gift)", 0.80, "amazon_scam", "Fake Amazon prize"),
            (r"kaun\s+banega\s+crorepati|kbc\s+(?:winner|prize|lottery)", 0.95, "kbc_scam", "KBC lottery scam"),
            (r"(?:government|sarkari)\s+(?:scheme|yojana)\s+(?:mein|free|money)", 0.80, "scheme_scam", "Fake govt scheme"),
            (r"(?:pm|pradhan\s+mantri)\s+(?:kisan|awas|ujjwala)\s+(?:scheme|bonus|money)", 0.85, "scheme_scam", "Fake PM scheme"),
        ]

        # === JOB / INVESTMENT SCAMS ===
        self.JOB_SCAMS = [
            (r"(?:ghar|घर|home)\s+(?:se|baithe|se\s+baithe)\s+(?:karo|earn|paise)", 0.80, "job_scam", "WFH Hinglish scam"),
            (r"(?:daily|per\s+day|roz)\s+(?:\d+)\s+(?:earn|kama|rupee|rs)", 0.85, "job_scam", "Daily earning scam"),
            (r"(?:no|bina)\s+(?:investment|paise|paisa)\s+(?:earn|income|kama)", 0.80, "job_scam", "No investment scam"),
            (r"(?:part\s+time|parttime)\s+(?:job|kaam|earning)\s+(?:whatsapp|telegram|online)", 0.80, "job_scam", "Part-time job scam"),
            (r"(?:task|like|follow|share)\s+(?:karke|करके|doing)\s+(?:earn|paise|money)", 0.85, "task_scam", "Like/follow task scam"),
            (r"(?:crypto|bitcoin|trading)\s+(?:guaranteed|sure|fixed)\s+(?:return|profit|income)", 0.90, "crypto_scam", "Crypto guarantee scam"),
            (r"(?:invest|lagao|lagana)\s+\d+\s+(?:earn|get|pao)\s+\d+", 0.90, "investment_scam", "Investment return scam"),
        ]

        # === SOCIAL ENGINEERING (HINDI/HINGLISH) ===
        self.SOCIAL_ENGINEERING_INDIA = [
            (r"(?:mai|main|mein)\s+(?:tumhara|tera|aapka)\s+(?:dost|friend|bhai|behen)", 0.75, "impersonation", "Friend impersonation Hindi"),
            (r"(?:hospital|emergency|accident)\s+(?:mein|main|me)\s+(?:hu|hoon|hun|hai)", 0.85, "emergency_scam", "Hospital emergency scam"),
            (r"(?:paise|money|funds)\s+(?:bhejo|send|transfer)\s+(?:abhi|now|jaldi)", 0.85, "urgent_transfer", "Urgent money transfer"),
            (r"(?:kisi\s+ko|anyone\s+ko)\s+(?:mat\s+batao|don't\s+tell|nahi\s+batana)", 0.80, "secrecy_tactic", "Secrecy manipulation"),
            (r"(?:ek\s+kaam|ek\s+baat)\s+(?:karo|karna)\s+(?:please|plz|pls)", 0.60, "social_engineering", "Favor request pattern"),
            (r"(?:mera|meri)\s+(?:phone|number|account)\s+(?:band|block|kho\s+gaya)", 0.75, "device_scam", "Device loss manipulation"),
        ]

        # === LEGAL THREAT SCAMS ===
        self.LEGAL_THREATS = [
            (r"(?:police|cyber\s+crime|cybercrime)\s+(?:case|fir|notice|arrested)", 0.85, "legal_threat", "Police threat"),
            (r"(?:court|न्यायालय)\s+(?:notice|summon|order)", 0.85, "legal_threat", "Court notice scam"),
            (r"(?:income\s+tax|it\s+department)\s+(?:notice|raid|case|action)", 0.85, "tax_threat", "Tax threat scam"),
            (r"(?:ed|enforcement\s+directorate)\s+(?:notice|investigation|case)", 0.90, "legal_threat", "ED investigation scam"),
            (r"(?:jail|arrest|giraftari)\s+(?:ho\s+jaoge|ho\s+sakti|karenge)", 0.90, "arrest_threat", "Arrest threat scam"),
        ]

        # === WHATSAPP CHAIN / FORWARD SCAMS ===
        self.CHAIN_SCAMS = [
            (r"(?:forward|share)\s+this\s+(?:message|msg)\s+to\s+\d+", 0.70, "chain_message", "Forward chain scam"),
            (r"whatsapp\s+(?:gold|premium|new\s+version|plus)\s+(?:activate|free|download)", 0.85, "fake_update", "WhatsApp Gold scam"),
            (r"(?:don't\s+accept|accept\s+mat\s+karo)\s+(?:video\s+call|call)\s+from\s+(?:unknown|stranger)", 0.65, "chain_warning", "Chain warning hoax"),
            (r"share\s+(?:this|ye|yeh)\s+(?:\d+|kuch)\s+(?:logo|log|friends)\s+(?:mein|ko)", 0.70, "chain_message", "Hindi chain message"),
        ]

        # All patterns combined
        self.ALL_PATTERNS = (
            self.INDIA_BANKING +
            self.KYC_SCAMS +
            self.OTP_THEFT +
            self.LOTTERY_SCAMS +
            self.JOB_SCAMS +
            self.SOCIAL_ENGINEERING_INDIA +
            self.LEGAL_THREATS +
            self.CHAIN_SCAMS
        )

        self.INDIA_ONLY_PATTERNS = (
            self.INDIA_BANKING +
            self.KYC_SCAMS +
            self.OTP_THEFT[2:4] +  # Hinglish OTP
            self.LOTTERY_SCAMS[3:] +  # KBC, PM schemes
            self.JOB_SCAMS[:3] +  # Hindi WFH
            self.SOCIAL_ENGINEERING_INDIA +
            self.LEGAL_THREATS +
            self.CHAIN_SCAMS[1:]  # WA Gold
        )

    def scan(self, text: str, language: str = "en") -> Dict:
        """
        Scan message against all patterns.
        Returns score, matched categories, and pattern descriptions.
        """
        matches = []
        categories = []
        max_score = 0.0

        patterns = self.ALL_PATTERNS

        for pattern, weight, category, description in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                matches.append(description)
                categories.append(category)
                max_score = max(max_score, weight)

        # Boost score if multiple patterns match
        match_count = len(matches)
        if match_count >= 3:
            max_score = min(max_score * 1.2, 1.0)
        elif match_count >= 2:
            max_score = min(max_score * 1.1, 1.0)

        return {
            "score": round(max_score, 3),
            "matches": matches[:5],  # Top 5 matches
            "categories": list(set(categories)),
            "match_count": match_count,
        }

    def get_india_patterns(self) -> Dict:
        """Return categorized India-specific scam patterns for documentation"""
        return {
            "banking_fraud": [
                {"pattern": p[0], "category": p[2], "description": p[3]}
                for p in self.INDIA_BANKING
            ],
            "kyc_scams": [
                {"pattern": p[0], "category": p[2], "description": p[3]}
                for p in self.KYC_SCAMS
            ],
            "otp_theft": [
                {"pattern": p[0], "category": p[2], "description": p[3]}
                for p in self.OTP_THEFT
            ],
            "lottery_scams": [
                {"pattern": p[0], "category": p[2], "description": p[3]}
                for p in self.LOTTERY_SCAMS
            ],
            "job_investment_scams": [
                {"pattern": p[0], "category": p[2], "description": p[3]}
                for p in self.JOB_SCAMS
            ],
            "social_engineering": [
                {"pattern": p[0], "category": p[2], "description": p[3]}
                for p in self.SOCIAL_ENGINEERING_INDIA
            ],
            "legal_threats": [
                {"pattern": p[0], "category": p[2], "description": p[3]}
                for p in self.LEGAL_THREATS
            ],
            "chain_scams": [
                {"pattern": p[0], "category": p[2], "description": p[3]}
                for p in self.CHAIN_SCAMS
            ],
            "total_patterns": len(self.ALL_PATTERNS),
            "india_specific": len(self.INDIA_ONLY_PATTERNS),
        }

    def pattern_count(self) -> int:
        return len(self.ALL_PATTERNS)

    def india_pattern_count(self) -> int:
        return len(self.INDIA_ONLY_PATTERNS)