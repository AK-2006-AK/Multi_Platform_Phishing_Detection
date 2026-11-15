# 🛡️ PhishGuard AI — Multi-Platform Phishing & Scam Detection System

PhishGuard AI is a real-time, multi-platform threat intelligence and phishing detection system designed to protect users across **Telegram, WhatsApp, Instagram, SMS, Email, and QR Codes (Quishing)**.

---

## ⚙️ Detection Architecture & Risk Formula
Each incoming payload (text, URL, image caption, or QR code) is evaluated across four independent security layers:

$$\text{Risk Score} = (0.35 \times \text{NLP}) + (0.35 \times \text{URL}) + (0.15 \times \text{QR}) + (0.15 \times \text{Threat Intel})$$

- **🟢 Safe (`< 30%`):** Passed to user.
- **🟡 Suspicious (`30% – 70%`):** Inline warning & security awareness alert issued.
- **🔴 Malicious (`> 70%`):** Link neutralized and domain automatically blacklisted in SQLite Threat Intelligence DB.

---

## 🚀 Key Features
- **NLP Text & SMS Analyzer:** Detects urgency, credential harvesting, and social engineering cues.
- **URL Heuristic & Lexical Scanner:** Identifies suspicious TLDs, IP-based links, and domain spoofing.
- **QR Code Decoder (Quishing Defense):** Extracts and scans hidden URLs from uploaded or live-captured QR images.
- **Automated Threat Intelligence:** Automatically blacklists high-risk (`> 70%`) malicious domains in real time.
- **Live Security Dashboard & Bot:** Instant scanning via Telegram (`@ak_cypher_bot`) synced with a live Streamlit analytics dashboard.

---

## 🛠️ Tech Stack
- **Frontend:** Streamlit, Plotly
- **Bot Interface:** Python-Telegram-Bot (`@ak_cypher_bot`)
- **Database:** SQLite3
- **Image & QR Processing:** OpenCV, Pyzbar, Pillow

---

## ▶️ How to Run
1. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
