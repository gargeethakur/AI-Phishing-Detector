"""
Test Suite for AI Phishing Detector
Tests: API endpoints, pattern engine, URL checker, analyzer
Run: pytest tests/ -v
"""

import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../backend"))

from core.analyzer import PhishingAnalyzer
from core.url_checker import URLChecker
from core.pattern_engine import PatternEngine


# ─── Fixtures ──────────────────────────────────────────────────

@pytest.fixture
def analyzer():
    return PhishingAnalyzer()

@pytest.fixture
def url_checker():
    return URLChecker()

@pytest.fixture
def pattern_engine():
    return PatternEngine()


# ─── PhishingAnalyzer Tests ─────────────────────────────────────

class TestPhishingAnalyzer:

    def test_otp_theft_detected(self, analyzer):
        msg = "Please share the OTP you received to verify your account"
        result = analyzer.analyze(msg)
        assert result["score"] > 0.7
        assert "otp_theft" in result["categories"]

    def test_lottery_scam_detected(self, analyzer):
        msg = "Congratulations! You have won the KBC lottery prize of 50 lakh rupees!"
        result = analyzer.analyze(msg)
        assert result["score"] > 0.6

    def test_safe_message_low_score(self, analyzer):
        msg = "Hey, are you coming for dinner tonight? Mom made biryani!"
        result = analyzer.analyze(msg)
        assert result["score"] < 0.3

    def test_legal_threat_detected(self, analyzer):
        msg = "NOTICE: A cybercrime FIR has been filed against your number. Call immediately to avoid arrest."
        result = analyzer.analyze(msg)
        assert result["score"] > 0.65
        assert "legal_threat" in result["categories"]

    def test_urgency_detection(self, analyzer):
        msg = "URGENT!!! Your account will be suspended IMMEDIATELY. Act NOW before it's too late!!!"
        result = analyzer.analyze(msg)
        assert result["score"] > 0.4

    def test_bank_impersonation(self, analyzer):
        msg = "This is your SBI Bank. Your account has been blocked due to suspicious activity. Share your ATM PIN to reactivate."
        result = analyzer.analyze(msg)
        assert result["score"] > 0.80

    def test_component_scores_returned(self, analyzer):
        result = analyzer.analyze("test message")
        assert "component_scores" in result
        assert "high_risk_tokens" in result["component_scores"]

    def test_categories_are_list(self, analyzer):
        result = analyzer.analyze("send me your otp now")
        assert isinstance(result["categories"], list)


# ─── URLChecker Tests ────────────────────────────────────────────

class TestURLChecker:

    def test_shortened_url_detected(self, url_checker):
        msg = "Click this link: https://bit.ly/3xAbc12"
        threats = url_checker.check_message(msg)
        assert any("shortened_url" in t for t in threats)

    def test_ip_based_url_detected(self, url_checker):
        msg = "Verify here: http://192.168.1.1/verify"
        threats = url_checker.check_message(msg)
        assert any("ip_based_url" in t for t in threats)

    def test_fake_sbi_domain_detected(self, url_checker):
        msg = "Login at http://sbi-kyc-update.tk/verify"
        threats = url_checker.check_message(msg)
        assert any("fake_brand" in t or "suspicious_tld" in t for t in threats)

    def test_legitimate_domain_no_threat(self, url_checker):
        msg = "Check your balance at https://onlinesbi.sbi"
        threats = url_checker.check_message(msg)
        assert not any("fake_brand" in t for t in threats)

    def test_high_risk_tld_detected(self, url_checker):
        msg = "Win prize at http://free-gift.tk/claim"
        threats = url_checker.check_message(msg)
        assert any("suspicious_tld" in t for t in threats)

    def test_no_url_returns_empty(self, url_checker):
        msg = "Hello, how are you doing today?"
        threats = url_checker.check_message(msg)
        assert threats == []

    def test_multiple_urls_checked(self, url_checker):
        msg = "Go to bit.ly/abc and also tinyurl.com/xyz"
        threats = url_checker.check_message(msg)
        assert len(threats) >= 1


# ─── PatternEngine Tests ─────────────────────────────────────────

class TestPatternEngine:

    def test_kbc_scam_detected(self, pattern_engine):
        msg = "You are the KBC winner! Claim your prize money now!"
        result = pattern_engine.scan(msg)
        assert result["score"] > 0.70
        assert "lottery_scam" in result["categories"]

    def test_hinglish_otp_detected(self, pattern_engine):
        msg = "Bhai OTP send kar mujhe, abhi karo"
        result = pattern_engine.scan(msg, language="hinglish")
        assert result["score"] > 0.70
        assert "otp_theft" in result["categories"]

    def test_kyc_scam_detected(self, pattern_engine):
        msg = "Your SBI KYC is pending. Complete KYC within 24 hours to avoid account suspension."
        result = pattern_engine.scan(msg)
        assert result["score"] > 0.75

    def test_wfh_hinglish_scam(self, pattern_engine):
        msg = "Ghar se baithe daily 2000 rupee earn karo! No investment!"
        result = pattern_engine.scan(msg)
        assert result["score"] > 0.60

    def test_pm_scheme_scam(self, pattern_engine):
        msg = "PM Kisan Yojana mein aapko 6000 free money milegi. Click here."
        result = pattern_engine.scan(msg)
        assert result["score"] > 0.60

    def test_safe_message_low_score(self, pattern_engine):
        msg = "Kal milte hai office ke baad? Coffee peete hain."
        result = pattern_engine.scan(msg)
        assert result["score"] < 0.25

    def test_india_patterns_returnable(self, pattern_engine):
        patterns = pattern_engine.get_india_patterns()
        assert "banking_fraud" in patterns
        assert "kyc_scams" in patterns
        assert "otp_theft" in patterns
        assert "lottery_scams" in patterns
        assert patterns["total_patterns"] > 20

    def test_pattern_count(self, pattern_engine):
        assert pattern_engine.pattern_count() > 20
        assert pattern_engine.india_pattern_count() > 10

    def test_matches_list_returned(self, pattern_engine):
        result = pattern_engine.scan("KYC update link sent, complete immediately")
        assert isinstance(result["matches"], list)
        assert isinstance(result["categories"], list)


# ─── Integration-style Tests ─────────────────────────────────────

class TestIntegration:
    """Tests that simulate the full pipeline"""

    def test_full_otp_scam_pipeline(self, analyzer, url_checker, pattern_engine):
        msg = "Your SBI account will be blocked. Share OTP from SMS to verify: http://sbi-verify.tk/otp"

        ai = analyzer.analyze(msg)
        urls = url_checker.check_message(msg)
        patterns = pattern_engine.scan(msg)

        assert ai["score"] > 0.7
        assert len(urls) > 0
        assert patterns["score"] > 0.7

    def test_safe_message_full_pipeline(self, analyzer, url_checker, pattern_engine):
        msg = "Meeting at 3pm in conference room B. Please bring the Q3 report."

        ai = analyzer.analyze(msg)
        urls = url_checker.check_message(msg)
        patterns = pattern_engine.scan(msg)

        assert ai["score"] < 0.3
        assert urls == []
        assert patterns["score"] < 0.2

    def test_score_aggregation(self, analyzer, url_checker, pattern_engine):
        msg = "You have WON 10 lakh in KBC Lottery! Click: http://kbc-prize.tk/claim?otp=required"

        ai_score = analyzer.analyze(msg)["score"]
        url_score = min(len(url_checker.check_message(msg)) * 0.3, 0.9)
        pat_score = pattern_engine.scan(msg)["score"]

        final = min(ai_score * 0.45 + url_score * 0.30 + pat_score * 0.25, 1.0)
        assert final > 0.5  # Should be classified as phishing


if __name__ == "__main__":
    pytest.main([__file__, "-v"])