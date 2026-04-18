"""
AI Phishing Detector - FastAPI Backend
Detects phishing/scam messages in DM-style chats
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional
import uvicorn
import logging

from core.analyzer import PhishingAnalyzer
from core.url_checker import URLChecker
from core.pattern_engine import PatternEngine

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="AI Phishing Detector",
    description="Detects phishing/scam messages in WhatsApp/Instagram DMs",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize components
analyzer = PhishingAnalyzer()
url_checker = URLChecker()
pattern_engine = PatternEngine()


class MessageRequest(BaseModel):
    message: str
    platform: Optional[str] = "whatsapp"  # whatsapp | instagram | telegram
    language: Optional[str] = "en"         # en | hi | hinglish


class AnalysisResponse(BaseModel):
    is_phishing: bool
    confidence: float
    risk_level: str  # LOW | MEDIUM | HIGH | CRITICAL
    threat_categories: list
    url_threats: list
    pattern_matches: list
    explanation: str
    recommendation: str


@app.get("/")
async def root():
    return {"message": "AI Phishing Detector API", "version": "1.0.0", "status": "active"}


@app.get("/health")
async def health_check():
    return {"status": "healthy", "components": {
        "analyzer": "active",
        "url_checker": "active",
        "pattern_engine": "active"
    }}


@app.post("/analyze", response_model=AnalysisResponse)
async def analyze_message(request: MessageRequest):
    """
    Main endpoint: Analyze a DM message for phishing/scam signals
    """
    if not request.message or len(request.message.strip()) < 2:
        raise HTTPException(status_code=400, detail="Message too short to analyze")

    if len(request.message) > 5000:
        raise HTTPException(status_code=400, detail="Message too long (max 5000 chars)")

    try:
        # Run all analysis modules
        ai_result = analyzer.analyze(request.message)
        url_threats = url_checker.check_message(request.message)
        pattern_result = pattern_engine.scan(request.message, request.language)

        # Aggregate scores
        final_score = aggregate_scores(ai_result, url_threats, pattern_result)
        risk_level = score_to_risk(final_score)

        # Collect all threat categories
        threat_categories = list(set(
            ai_result.get("categories", []) +
            pattern_result.get("categories", []) +
            (["suspicious_url"] if url_threats else [])
        ))

        explanation = build_explanation(ai_result, url_threats, pattern_result, risk_level)
        recommendation = get_recommendation(risk_level, threat_categories)

        return AnalysisResponse(
            is_phishing=final_score >= 0.5,
            confidence=round(final_score, 3),
            risk_level=risk_level,
            threat_categories=threat_categories,
            url_threats=url_threats,
            pattern_matches=pattern_result.get("matches", []),
            explanation=explanation,
            recommendation=recommendation
        )

    except Exception as e:
        logger.error(f"Analysis error: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@app.post("/analyze/batch")
async def analyze_batch(messages: list[MessageRequest]):
    """Analyze multiple messages at once (max 20)"""
    if len(messages) > 20:
        raise HTTPException(status_code=400, detail="Max 20 messages per batch")

    results = []
    for msg in messages:
        try:
            result = await analyze_message(msg)
            results.append({"message": msg.message[:50] + "...", "result": result})
        except Exception as e:
            results.append({"message": msg.message[:50] + "...", "error": str(e)})

    return {"batch_results": results, "total": len(messages)}


@app.get("/patterns/india")
async def get_india_patterns():
    """Return all known Indian scam patterns"""
    return pattern_engine.get_india_patterns()


@app.get("/stats")
async def get_stats():
    """Return detection statistics"""
    return {
        "total_patterns": pattern_engine.pattern_count(),
        "india_specific_patterns": pattern_engine.india_pattern_count(),
        "url_databases": url_checker.database_count(),
        "model_info": analyzer.model_info()
    }


def aggregate_scores(ai_result: dict, url_threats: list, pattern_result: dict) -> float:
    ai_score = ai_result.get("score", 0.0)
    url_score = min(len(url_threats) * 0.3, 0.9) if url_threats else 0.0
    pattern_score = pattern_result.get("score", 0.0)

    # Weighted average — URL threats are most definitive
    weights = {"ai": 0.45, "url": 0.30, "pattern": 0.25}
    final = (
        ai_score * weights["ai"] +
        url_score * weights["url"] +
        pattern_score * weights["pattern"]
    )
    return min(final, 1.0)


def score_to_risk(score: float) -> str:
    if score < 0.25:
        return "LOW"
    elif score < 0.50:
        return "MEDIUM"
    elif score < 0.75:
        return "HIGH"
    else:
        return "CRITICAL"


def build_explanation(ai_result: dict, url_threats: list, pattern_result: dict, risk: str) -> str:
    parts = []
    if ai_result.get("score", 0) > 0.5:
        parts.append(f"AI model detected suspicious patterns ({', '.join(ai_result.get('categories', []))})")
    if url_threats:
        parts.append(f"Found {len(url_threats)} suspicious URL(s): {', '.join(url_threats[:2])}")
    if pattern_result.get("matches"):
        parts.append(f"Matched scam patterns: {', '.join(pattern_result['matches'][:3])}")
    if not parts:
        return "No significant phishing indicators detected."
    return " | ".join(parts)


def get_recommendation(risk: str, categories: list) -> str:
    recs = {
        "LOW": "Message appears safe. Stay vigilant and never share OTPs or passwords.",
        "MEDIUM": "Exercise caution. Verify the sender's identity through a trusted channel before responding.",
        "HIGH": "Do NOT click links or share personal info. Report this message and block the sender.",
        "CRITICAL": "DANGER: This is almost certainly a scam. Block immediately, do not respond, report to cybercrime.gov.in"
    }
    return recs.get(risk, "Stay cautious.")


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)