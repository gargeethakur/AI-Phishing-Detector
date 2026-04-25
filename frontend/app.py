"""
AI Phishing Detector - Streamlit Frontend Dashboard
Professional UI for analyzing WhatsApp/Instagram DM phishing
"""

import streamlit as st
import requests
import json
import os
from datetime import datetime

# ─── Config ────────────────────────────────────────────────
API_URL = os.getenv("API_URL", "http://localhost:8000")

st.set_page_config(
    page_title="AI Phishing Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ─── Custom CSS ─────────────────────────────────────────────
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
        padding: 2rem;
        border-radius: 12px;
        margin-bottom: 2rem;
        text-align: center;
    }
    .risk-critical { background-color: #ff4444; color: white; padding: 8px 16px; border-radius: 8px; font-weight: bold; }
    .risk-high { background-color: #ff8800; color: white; padding: 8px 16px; border-radius: 8px; font-weight: bold; }
    .risk-medium { background-color: #ffcc00; color: black; padding: 8px 16px; border-radius: 8px; font-weight: bold; }
    .risk-low { background-color: #00cc44; color: white; padding: 8px 16px; border-radius: 8px; font-weight: bold; }
    .threat-tag {
        display: inline-block;
        background-color: #ff4444;
        color: white;
        padding: 4px 10px;
        border-radius: 20px;
        font-size: 12px;
        margin: 2px;
    }
    .safe-tag {
        display: inline-block;
        background-color: #00cc44;
        color: white;
        padding: 4px 10px;
        border-radius: 20px;
        font-size: 12px;
        margin: 2px;
    }
    .stTextArea textarea { font-family: monospace; }
</style>
""", unsafe_allow_html=True)


# ─── Header ─────────────────────────────────────────────────
st.markdown("""
<div class="main-header">
    <h1 style="color: white; margin: 0;">🛡️ AI Phishing Detector</h1>
    <p style="color: #aac4ff; margin: 0.5rem 0 0;">WhatsApp & Instagram DM Scam Detection with India-Specific Patterns</p>
</div>
""", unsafe_allow_html=True)


# ─── Sidebar ────────────────────────────────────────────────
with st.sidebar:
    st.header("⚙️ Settings")
    platform = st.selectbox("Platform", ["whatsapp", "instagram", "telegram"], index=0)
    language = st.selectbox("Language", ["en", "hi", "hinglish"], index=0)

    st.divider()
    st.subheader("📊 Quick Examples")

    examples = {
        "🚨 KBC Lottery Scam": "Congratulations! You have won KBC lottery of 50 lakh rupees. Send your Aadhar number and bank details to claim your prize immediately! Contact: +91-9876543210",
        "🔑 OTP Theft": "Hello, I am calling from SBI Bank. Your account will be blocked in 2 hours. Please share the OTP you just received to verify your identity. Don't tell anyone.",
        "💼 WFH Job Scam": "Ghar se karo kaam! Daily 2000 rupee earn karo. No investment required. Sirf WhatsApp pe like aur share tasks karo. Join karo aaj hi! Telegram pe aao.",
        "⚖️ Legal Threat": "CYBERCRIME DEPARTMENT NOTICE: An FIR has been filed against your number for illegal activity. Call immediately to avoid arrest. Case no: CYB/2024/1234",
        "✅ Safe Message": "Hey! Are you coming for dinner tonight? Mom made biryani 😊 Let me know by 7pm!"
    }

    for label, msg in examples.items():
        if st.button(label, use_container_width=True):
            st.session_state["example_msg"] = msg


# ─── Main Analysis Area ──────────────────────────────────────
col1, col2 = st.columns([1, 1], gap="large")

with col1:
    st.subheader("💬 Message Input")
    default_msg = st.session_state.get("example_msg", "")
    message = st.text_area(
        "Paste the DM message to analyze:",
        value=default_msg,
        height=200,
        placeholder="Paste WhatsApp/Instagram message here...",
        key="msg_input"
    )

    analyze_btn = st.button("🔍 Analyze Message", type="primary", use_container_width=True)

    # Batch analysis
    st.subheader("📦 Batch Analysis")
    with st.expander("Analyze multiple messages"):
        batch_text = st.text_area("One message per line:", height=150)
        batch_btn = st.button("🔍 Analyze Batch", use_container_width=True)


# ─── Analysis Result ─────────────────────────────────────────
with col2:
    st.subheader("🔎 Analysis Result")

    if analyze_btn and message.strip():
        with st.spinner("Analyzing message..."):
            try:
                resp = requests.post(f"{API_URL}/analyze", json={
                    "message": message,
                    "platform": platform,
                    "language": language
                }, timeout=10)
                result = resp.json()

                # Risk Level Badge
                risk = result.get("risk_level", "UNKNOWN")
                risk_colors = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴"}
                icon = risk_colors.get(risk, "⚪")

                st.markdown(f"### {icon} Risk Level: **{risk}**")

                # Confidence meter
                conf = result.get("confidence", 0)
                st.metric("Phishing Confidence", f"{conf * 100:.1f}%")
                st.progress(conf)

                # Is Phishing
                if result.get("is_phishing"):
                    st.error("⚠️ **PHISHING DETECTED** — Do NOT interact with this message!")
                else:
                    st.success("✅ **Appears Safe** — No major phishing indicators found.")

                st.divider()

                # Threat Categories
                cats = result.get("threat_categories", [])
                if cats:
                    st.markdown("**Threat Categories:**")
                    tags_html = " ".join(f'<span class="threat-tag">{c.replace("_", " ").title()}</span>' for c in cats)
                    st.markdown(tags_html, unsafe_allow_html=True)

                # URL Threats
                url_threats = result.get("url_threats", [])
                if url_threats:
                    st.markdown("**🔗 URL Threats:**")
                    for t in url_threats:
                        st.markdown(f"- 🚫 `{t}`")

                # Pattern Matches
                patterns = result.get("pattern_matches", [])
                if patterns:
                    st.markdown("**🎯 Matched Scam Patterns:**")
                    for p in patterns:
                        st.markdown(f"- ⚡ {p}")

                st.divider()

                # Explanation
                st.markdown(f"**🧠 Analysis:** {result.get('explanation', '')}")

                # Recommendation
                rec = result.get("recommendation", "")
                if "DANGER" in rec or risk == "CRITICAL":
                    st.error(f"**📋 Action:** {rec}")
                elif risk == "HIGH":
                    st.warning(f"**📋 Action:** {rec}")
                else:
                    st.info(f"**📋 Action:** {rec}")

            except requests.ConnectionError:
                st.error("❌ Cannot connect to API. Is the backend running?")
            except Exception as e:
                st.error(f"❌ Analysis failed: {e}")

    elif analyze_btn:
        st.warning("Please enter a message to analyze.")
    else:
        st.info("👈 Paste a message and click **Analyze** to check for phishing.")


# ─── Stats Footer ────────────────────────────────────────────
st.divider()
st.subheader("📈 System Statistics")

try:
    stats = requests.get(f"{API_URL}/stats", timeout=5).json()
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Patterns", stats.get("total_patterns", "N/A"))
    c2.metric("India Patterns", stats.get("india_specific_patterns", "N/A"))
    c3.metric("URL Databases", "-")
    c4.metric("Model", stats.get("model_info", {}).get("type", "N/A"))
except:
    st.warning("Stats unavailable — backend may not be running.")

st.caption(f"🛡️ AI Phishing Detector v1.0 | Built for India-specific scam detection | {datetime.now().strftime('%Y-%m-%d')}")