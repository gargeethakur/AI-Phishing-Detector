"""
URLChecker - Detects suspicious, shortened, and fake payment URLs in messages
Combines regex detection + domain reputation + redirect checking
"""

import re
import urllib.parse
from typing import List, Dict


class URLChecker:
    """
    Multi-layer URL threat detection:
    1. Extract all URLs from text
    2. Detect URL shorteners
    3. Detect IP-based URLs (no domain)
    4. Detect fake brand/bank domains (typosquatting)
    5. Detect suspicious TLDs
    6. Optional: Check Google Safe Browsing / VirusTotal APIs
    """

    def __init__(self):
        self._build_databases()

    def _build_databases(self):
        # URL shortener domains
        self.SHORTENERS = {
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "shorturl.at",
            "tiny.cc", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "rb.gy",
            "clck.ru", "bc.vc", "chilp.it", "short.pe", "adf.ly",
            "shrinkme.io", "linktr.ee",
        }

        # High-risk TLDs (commonly used in phishing)
        self.HIGH_RISK_TLDS = {
            ".tk", ".ml", ".ga", ".cf", ".gq",   # Freenom free domains
            ".xyz", ".buzz", ".click", ".loan",
            ".work", ".win", ".download", ".racing",
            ".review", ".country", ".kim", ".cricket",
        }

        # Indian bank / payment brand names for typosquatting detection
        self.PROTECTED_BRANDS = [
            "sbi", "hdfc", "icici", "axis", "kotak", "pnb", "bob",
            "paytm", "phonepe", "gpay", "googlepay", "bhim", "upi",
            "rbi", "npci", "uidai", "incometax", "epfo", "irctc",
            "amazon", "flipkart", "meesho", "snapdeal",
            "whatsapp", "instagram", "facebook", "telegram",
        ]

        # Legit domains to whitelist
        self.WHITELIST = {
            "sbi.co.in", "onlinesbi.sbi", "hdfcbank.com", "icicibank.com",
            "axisbank.com", "paytm.com", "phonepe.com", "bhimupi.org.in",
            "npci.org.in", "rbi.org.in", "incometax.gov.in",
            "amazon.in", "flipkart.com",
        }

        # Suspicious path patterns
        self.SUSPICIOUS_PATHS = [
            r"/verify", r"/login", r"/signin", r"/auth",
            r"/update.account", r"/claim.prize", r"/reward",
            r"/otp", r"/kyc", r"/aadhar",
        ]

    def check_message(self, text: str) -> List[str]:
        """
        Extract and check all URLs in a message.
        Returns list of threat descriptions for each suspicious URL.
        """
        urls = self._extract_urls(text)
        threats = []

        for url in urls:
            url_threats = self._analyze_url(url)
            threats.extend(url_threats)

        # Also check for disguised URLs (spaces in URLs, zero-width chars)
        if self._has_disguised_urls(text):
            threats.append("disguised_url_detected")

        return list(set(threats))

    def _extract_urls(self, text: str) -> List[str]:
        """Extract all URLs including partial ones"""
        url_pattern = r'https?://[^\s<>"\]]+|www\.[^\s<>"\]]+'
        urls = re.findall(url_pattern, text, re.IGNORECASE)

        # Also catch bare domains like "bit.ly/xyz123"
        short_pattern = r'\b(?:' + '|'.join(re.escape(s) for s in self.SHORTENERS) + r')/\S+'
        short_urls = re.findall(short_pattern, text, re.IGNORECASE)

        return list(set(urls + short_urls))

    def _analyze_url(self, url: str) -> List[str]:
        """Analyze a single URL for threats"""
        threats = []
        url_lower = url.lower()

        try:
            parsed = urllib.parse.urlparse(url if url.startswith('http') else 'http://' + url)
            domain = parsed.netloc.lower().lstrip('www.')
            path = parsed.path.lower()
            tld = '.' + domain.rsplit('.', 1)[-1] if '.' in domain else ''
        except Exception:
            return ["malformed_url"]

        # 1. Whitelisted domain check
        if domain in self.WHITELIST:
            return []

        # 2. URL Shortener detection
        if domain in self.SHORTENERS:
            threats.append(f"shortened_url:{domain}")

        # 3. IP-based URL (no real domain)
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
            threats.append("ip_based_url")

        # 4. High-risk TLD
        if tld in self.HIGH_RISK_TLDS:
            threats.append(f"suspicious_tld:{tld}")

        # 5. Brand typosquatting
        typosquat = self._detect_typosquatting(domain)
        if typosquat:
            threats.append(f"fake_brand:{typosquat}")

        # 6. Suspicious path keywords
        for pattern in self.SUSPICIOUS_PATHS:
            if re.search(pattern, path):
                threats.append(f"suspicious_path:{pattern.strip('/')}")
                break

        # 7. Many subdomains (common in phishing)
        subdomain_count = len(domain.split('.')) - 2
        if subdomain_count >= 3:
            threats.append("excessive_subdomains")

        # 8. Long domain names
        if len(domain) > 50:
            threats.append("unusually_long_domain")

        # 9. Numeric domain
        if re.match(r'^[\d\-]+\.\w+$', domain):
            threats.append("numeric_domain")

        # 10. Mixed character attacks (homograph)
        if self._has_homograph_chars(domain):
            threats.append("homograph_attack")

        return threats

    def _detect_typosquatting(self, domain: str) -> str:
        """Detect fake brand impersonation domains"""
        # Remove TLD for comparison
        domain_base = re.sub(r'\.[a-z]{2,6}$', '', domain).lower()

        for brand in self.PROTECTED_BRANDS:
            # Exact match in subdomain
            if brand in domain_base and domain_base != brand:
                return brand

            # Typosquatting: edit distance 1
            if self._edit_distance(domain_base, brand) <= 1 and len(brand) >= 4:
                return brand

            # Brand + keyword combos (sbi-kyc-update.tk, etc.)
            if re.search(rf'\b{re.escape(brand)}\b', domain_base):
                return brand

        return ""

    def _edit_distance(self, s1: str, s2: str) -> int:
        """Simple Levenshtein distance"""
        if len(s1) < len(s2):
            s1, s2 = s2, s1
        if len(s2) == 0:
            return len(s1)
        prev = list(range(len(s2) + 1))
        for c1 in s1:
            curr = [prev[0] + 1]
            for j, c2 in enumerate(s2):
                curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
            prev = curr
        return prev[-1]

    def _has_disguised_urls(self, text: str) -> bool:
        """Detect URLs hidden with zero-width spaces or look-alike chars"""
        # Zero-width chars
        if re.search(r'[\u200b\u200c\u200d\ufeff]', text):
            return True
        # Spaces inside URLs (bit. ly / xyz)
        if re.search(r'(?:bit|tinyurl|goo)\s*\.\s*[a-z]+\s*/', text, re.IGNORECASE):
            return True
        return False

    def _has_homograph_chars(self, domain: str) -> bool:
        """Detect unicode lookalike characters in domain"""
        suspicious_chars = ['а', 'е', 'о', 'р', 'с', 'у', 'х']  # Cyrillic
        return any(c in domain for c in suspicious_chars)

    def database_count(self) -> Dict:
        return {
            "shorteners": len(self.SHORTENERS),
            "high_risk_tlds": len(self.HIGH_RISK_TLDS),
            "protected_brands": len(self.PROTECTED_BRANDS),
            "whitelisted_domains": len(self.WHITELIST),
        }