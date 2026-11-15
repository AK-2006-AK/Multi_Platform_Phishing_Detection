# 🛡️ PhishGuard — Multi-Platform Phishing & Scam Detection System

PhishGuard is a real-time, AI-powered threat intelligence and phishing detection system designed to protect users across **Telegram, WhatsApp, Instagram, SMS, Email, and QR Codes (Quishing)**.

## ⚙️ Detection Architecture & Risk Formula
Each incoming payload (text, URL, image caption, or QR code) is evaluated across four independent security layers:

$$\text{Risk Score} = (0.35 \times \text{NLP}) + (0.35 \times \text{URL}) + (0.15 \times \text{QR}) + (0.15 \times \text{Threat Intel})$$

- **Safe (`< 30%`):** Passed to user.
- **Suspicious (`30% – 70%`):** Inline warning & security awareness alert issued.
- **Malicious (`> 70%`):** Link neutralized and domain automatically blacklisted in SQLite Threat Intelligence DB.

## 🚀 How to Run
1. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt