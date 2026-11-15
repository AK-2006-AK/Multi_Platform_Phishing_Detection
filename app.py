import os
import sqlite3
import pandas as pd
import plotly.express as px
import streamlit as st
import detection_engine
from database import db

st.set_page_config(
    page_title="PhishGuard AI — Scam & Phishing Protection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

st.markdown("""
<style>
    .main-header {
        background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
        padding: 1.8rem 2rem;
        border-radius: 16px;
        color: white;
        margin-bottom: 1.5rem;
        border: 1px solid #334155;
    }
    .main-header h1 {
        margin: 0;
        font-size: 2rem;
        font-weight: 700;
        color: #f8fafc;
    }
    .main-header p {
        margin: 0.4rem 0 0 0;
        color: #94a3b8;
        font-size: 1rem;
    }
    .verdict-box {
        padding: 1.5rem;
        border-radius: 14px;
        margin-top: 1rem;
        margin-bottom: 1rem;
        border-left: 8px solid;
    }
    .verdict-safe {
        background-color: #ecfdf5;
        border-color: #10b981;
        color: #065f46;
    }
    .verdict-suspicious {
        background-color: #fffbeb;
        border-color: #f59e0b;
        color: #92400e;
    }
    .verdict-malicious {
        background-color: #fef2f2;
        border-color: #ef4444;
        color: #991b1b;
    }
</style>
""", unsafe_allow_html=True)

if hasattr(db, "init_db"):
    db.init_db()

COLOR_MAP = {
    "Safe": "#10b981",
    "Suspicious": "#f59e0b",
    "Malicious": "#ef4444"
}

def get_db_connection():
    db_path = "database/phishguard.db" if os.path.exists("database/phishguard.db") else "phishguard.db"
    return sqlite3.connect(db_path)

def load_scans():
    try:
        conn = get_db_connection()
        df = pd.read_sql_query("SELECT * FROM scan_logs ORDER BY id DESC", conn)
        conn.close()
        return df
    except Exception:
        return pd.DataFrame()

def load_blacklist():
    try:
        conn = get_db_connection()
        df = pd.read_sql_query("SELECT * FROM blacklist ORDER BY id DESC", conn)
        conn.close()
        return df
    except Exception:
        return pd.DataFrame()

st.markdown("""
<div class="main-header">
    <h1>🛡️ PhishGuard AI — Multi-Platform Scam & Phishing Shield</h1>
    <p>Check suspicious SMS, WhatsApp/Telegram messages, links, or QR codes in seconds. Connected live with <b>@ak_cypher_bot</b>.</p>
</div>
""", unsafe_allow_html=True)

scans_df = load_scans()
blacklist_df = load_blacklist()

total_scans = len(scans_df)
malicious_count = len(scans_df[scans_df["verdict"] == "Malicious"]) if not scans_df.empty and "verdict" in scans_df.columns else 0
suspicious_count = len(scans_df[scans_df["verdict"] == "Suspicious"]) if not scans_df.empty and "verdict" in scans_df.columns else 0
safe_count = len(scans_df[scans_df["verdict"] == "Safe"]) if not scans_df.empty and "verdict" in scans_df.columns else 0

col1, col2, col3, col4 = st.columns(4)
col1.metric("🔍 Total Messages Scanned", total_scans)
col2.metric("🔴 High-Risk Threats Blocked", malicious_count)
col3.metric("🟡 Suspicious Warnings", suspicious_count)
col4.metric("🟢 Verified Safe", safe_count)

st.markdown("---")

tab1, tab2, tab3 = st.tabs([
    "🔎 Instant Scam & QR Scanner",
    "📊 Live Activity & Analytics",
    "🚫 Blocked Domains & Protection Rules"
])

with tab1:
    left_col, right_col = st.columns([1.2, 1], gap="large")

    with left_col:
        st.subheader("Check a Message, Link, or QR Code")
        st.caption("Paste any suspicious text/link, upload a QR image, or scan directly using your camera.")

        platform_choice = st.selectbox(
            "Where did you receive this?",
            ["WhatsApp", "Telegram", "SMS / Text", "Instagram / Social Media", "Email"],
            index=0
        )

        if "sample_text" not in st.session_state:
            st.session_state["sample_text"] = ""
        if "auto_scan" not in st.session_state:
            st.session_state["auto_scan"] = False

        st.caption("Quick Test Examples (Click to scan immediately):")
        ex1, ex2, ex3 = st.columns(3)
        if ex1.button("🔴 Test Malicious Link", use_container_width=True):
            st.session_state["sample_text"] = "Urgent! Claim your free bonus reward now at http://verify-login-bonus.xyz/claim"
            st.session_state["auto_scan"] = True
            st.rerun()
        if ex2.button("🟡 Test Suspicious Link", use_container_width=True):
            st.session_state["sample_text"] = "Hey bro, check out my new portfolio page here: http://arjun-dev-portfolio.online/home"
            st.session_state["auto_scan"] = True
            st.rerun()
        if ex3.button("🟢 Test Safe Link", use_container_width=True):
            st.session_state["sample_text"] = "Hi da, meeting is scheduled at 10 AM tomorrow. Check notes at https://github.com"
            st.session_state["auto_scan"] = True
            st.rerun()

        user_input = st.text_area(
            "Message or Website Link",
            value=st.session_state["sample_text"],
            height=110,
            placeholder="Paste any suspicious message, link, or forward here..."
        )

        qr_mode = st.radio(
            "QR Code Input Method (Optional)",
            ["📁 Upload QR Image", "📷 Scan via Camera (No Save Needed)"],
            horizontal=True
        )

        qr_source = None
        if qr_mode == "📁 Upload QR Image":
            qr_source = st.file_uploader(
                "Upload QR Code Screenshot / Image",
                type=["png", "jpg", "jpeg"]
            )
        else:
            qr_source = st.camera_input("Hold the QR code in front of your camera and click Take Photo")

        scan_clicked = st.button("🛡️ Scan Now", type="primary", use_container_width=True)

    with right_col:
        st.subheader("Scan Result")
        should_run = scan_clicked or st.session_state.get("auto_scan", False) or (qr_mode == "📷 Scan via Camera (No Save Needed)" and qr_source is not None)
        if should_run:
            st.session_state["auto_scan"] = False
            if not user_input.strip() and qr_source is None:
                st.warning("Please enter a message/link, upload a QR image, or capture a QR code via camera.")
            else:
                temp_img_path = None
                if qr_source is not None:
                    temp_img_path = "temp_web_qr_scan.png"
                    with open(temp_img_path, "wb") as f:
                        f.write(qr_source.getbuffer())

                try:
                    with st.spinner("Analyzing across AI, URL, QR & Threat Intelligence layers..."):
                        result = detection_engine.analyze(
                            text=user_input,
                            image_path=temp_img_path,
                            platform=platform_choice,
                            username="Web_User"
                        )
                finally:
                    if temp_img_path and os.path.exists(temp_img_path):
                        os.remove(temp_img_path)

                verdict = result["verdict"]
                score = result["risk_score"]

                if verdict == "Malicious":
                    css_class = "verdict-malicious"
                    badge = "🔴 DANGER — MALICIOUS PHISHING DETECTED"
                    advice = "Do NOT click this link, scan this QR code, or share any OTP/bank details."
                elif verdict == "Suspicious":
                    css_class = "verdict-suspicious"
                    badge = "🟡 CAUTION — SUSPICIOUS CONTENT"
                    advice = "Verify the sender through official channels before taking any action."
                else:
                    css_class = "verdict-safe"
                    badge = "🟢 SAFE — NO THREAT DETECTED"
                    advice = "This content appears safe based on our security checks."

                st.markdown(f"""
                <div class="verdict-box {css_class}">
                    <h3 style="margin:0 0 0.5rem 0;">{badge}</h3>
                    <p style="margin:0; font-size:1.1rem;"><b>Overall Risk Score:</b> {score}%</p>
                    <p style="margin:0.4rem 0 0 0;"><b>Recommended Action:</b> {advice}</p>
                </div>
                """, unsafe_allow_html=True)

                st.write("**Why was this verdict given?**")
                st.info(result["explanation"])

                st.write("**Layer-by-Layer Security Check:**")
                scores = result["scores"]
                b1, b2, b3, b4 = st.columns(4)
                b1.metric("AI Text Check", f"{scores['nlp']}%")
                b2.metric("Link Safety", f"{scores['url']}%")
                b3.metric("QR Code", f"{scores['qr']}%")
                b4.metric("Threat Intel", f"{scores['threat_intel']}%")
        else:
            st.info("👈 Enter a message, link, or scan a QR code on the left to see a clear safety report here.")

with tab2:
    top_bar1, top_bar2 = st.columns([4, 1])
    top_bar1.subheader("Live Threat Feed (Telegram Bot + Web Scans)")
    if top_bar2.button("🔄 Refresh Live Data", use_container_width=True):
        st.rerun()

    if scans_df.empty:
        st.info("No scans recorded yet. Send a message to @ak_cypher_bot on Telegram or use the Scanner tab!")
    else:
        c1, c2 = st.columns([1, 1.5])
        with c1:
            if "verdict" in scans_df.columns:
                fig_pie = px.pie(
                    scans_df,
                    names="verdict",
                    title="Scan Verdicts Distribution",
                    color="verdict",
                    color_discrete_map=COLOR_MAP,
                    hole=0.45
                )
                st.plotly_chart(fig_pie, use_container_width=True)

        with c2:
            if "platform" in scans_df.columns and "verdict" in scans_df.columns:
                fig_bar = px.histogram(
                    scans_df,
                    x="platform",
                    color="verdict",
                    barmode="group",
                    title="Detections by Platform",
                    color_discrete_map=COLOR_MAP
                )
                st.plotly_chart(fig_bar, use_container_width=True)

        st.subheader("Recent Scan History")
        display_cols = [c for c in ["timestamp", "platform", "username", "source_type", "content", "risk_score", "verdict", "explanation"] if c in scans_df.columns]
        st.dataframe(scans_df[display_cols] if display_cols else scans_df, use_container_width=True, hide_index=True)

with tab3:
    st.subheader("🚫 Automatically Blacklisted Domains")
    st.caption("Whenever PhishGuard detects a high-risk phishing attack (>70% risk), the malicious domain is automatically blocked here.")

    if blacklist_df.empty:
        st.success("No domains blacklisted yet. High-risk malicious domains will appear here automatically.")
    else:
        st.dataframe(blacklist_df, use_container_width=True, hide_index=True)

    st.markdown("---")
    st.subheader("ℹ️ How PhishGuard Protects Users")
    h1, h2, h3, h4 = st.columns(4)
    h1.info("**1. AI Text Analysis**\nDetects urgency, OTP theft, lottery lures, and fake bank warnings.")
    h2.info("**2. Deep URL Inspection**\nCatches fake IP links, unencrypted HTTP sites, URL shorteners, and brand spoofing.")
    h3.info("**3. QR Code Decoding**\nExtracts hidden links inside QR images before you scan them with your phone.")
    h4.info("**4. Live Threat Intel**\nCross-checks links against known phishing databases and blocks repeat attackers.")