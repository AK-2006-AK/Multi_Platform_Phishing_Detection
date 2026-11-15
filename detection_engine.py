import inspect
from database import db
from modules.url_analyzer import extract_url, extract_urls, analyze_url, analyze_urls_in_text
from modules import nlp_classifier, qr_decoder, threat_intel
import mitigation


def _call_dynamic(module, candidate_names, *args, default=None):
    for name in candidate_names:
        fn = getattr(module, name, None)
        if callable(fn):
            try:
                return fn(*args)
            except TypeError:
                sig = inspect.signature(fn)
                return fn(*args[:len(sig.parameters)])
    return default


def analyze(text: str = "", image_path: str = None, platform: str = "Telegram", username: str = "@user") -> dict:
    if hasattr(db, "init_db"):
        db.init_db()

    # 1. QR Code Decoding
    qr_score = 0.0
    qr_urls = []
    qr_reasons = []
    if image_path:
        qr_res = _call_dynamic(
            qr_decoder,
            ["decode_qr_from_image", "decode_qr", "scan_qr", "analyze_qr"],
            image_path,
            default={}
        )
        if isinstance(qr_res, tuple) and len(qr_res) >= 2:
            qr_score = float(qr_res[0])
            if isinstance(qr_res[1], str) and qr_res[1]:
                qr_urls.append(qr_res[1])
            elif isinstance(qr_res[1], list):
                qr_urls.extend(qr_res[1])
        elif isinstance(qr_res, dict):
            qr_score = float(qr_res.get("score", 0.0))
            if qr_res.get("url"):
                qr_urls.append(qr_res["url"])
            qr_urls.extend(qr_res.get("urls", []))
            qr_reasons = qr_res.get("reasons", [])
        elif isinstance(qr_res, str) and qr_res:
            qr_urls.append(qr_res)
            qr_score = 75.0
            qr_reasons.append(f"QR code decoded URL: {qr_res}")

    # 2. URL Analysis (Text + QR URLs)
    url_res = analyze_urls_in_text(text, extra_urls=qr_urls)
    url_score = float(url_res.get("score", 0.0))
    all_urls = url_res.get("urls", [])
    domains = url_res.get("domains", [])
    url_reasons = url_res.get("reasons", [])

    # 3. NLP Text Classification (Calls predict_risk directly)
    nlp_score = 0.0
    nlp_reasons = []
    if hasattr(nlp_classifier, "predict_risk"):
        nlp_score, nlp_reasons = nlp_classifier.predict_risk(text)
        nlp_score = float(nlp_score)
    else:
        nlp_res = _call_dynamic(
            nlp_classifier,
            ["analyze_text", "classify_text", "predict_phishing", "predict", "score_text"],
            text,
            default={"score": 0.0, "reasons": []}
        )
        if isinstance(nlp_res, tuple) and len(nlp_res) >= 2:
            nlp_score, nlp_reasons = float(nlp_res[0]), nlp_res[1]
        elif isinstance(nlp_res, dict):
            nlp_score = float(nlp_res.get("score", nlp_res.get("risk_score", 0.0)))
            nlp_reasons = nlp_res.get("reasons", [])

    # 4. Threat Intelligence Check
    ti_score = 0.0
    ti_reasons = []
    if hasattr(threat_intel, "check_threats"):
        ti_res = threat_intel.check_threats(all_urls, domains)
        if isinstance(ti_res, dict):
            ti_score = float(ti_res.get("score", 0.0))
            ti_reasons = ti_res.get("reasons", [])
    else:
        for u in all_urls:
            ti_res = _call_dynamic(
                threat_intel,
                ["check_threat_intel", "check_url", "analyze_threat", "lookup"],
                u,
                default={}
            )
            if isinstance(ti_res, tuple) and len(ti_res) >= 2:
                ti_score = max(ti_score, float(ti_res[0]))
                ti_reasons.extend(ti_res[1])
            elif isinstance(ti_res, dict):
                ti_score = max(ti_score, float(ti_res.get("score", 0.0)))
                ti_reasons.extend(ti_res.get("reasons", []))

    # 5. Weighted Risk Formula
    if image_path and qr_score > 0:
        risk_score = (0.35 * nlp_score) + (0.35 * url_score) + (0.15 * qr_score) + (0.15 * ti_score)
    else:
        risk_score = (0.425 * nlp_score) + (0.425 * url_score) + (0.15 * ti_score)

    # Escalate if Threat Intel confirms malicious match
    if ti_score >= 80.0:
        risk_score = max(risk_score, 85.0)

    # Escalate if both NLP and URL strongly indicate phishing
    if nlp_score >= 65.0 and url_score >= 80.0:
        risk_score = max(risk_score, 76.5)

    risk_score = round(min(100.0, risk_score), 1)

    # 6. Verdict Thresholds
    if risk_score > 70.0:
        verdict = "Malicious"
    elif risk_score >= 30.0:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    # 7. Source Type
    if image_path and qr_urls:
        source_type = "QR Code + Image"
    elif all_urls:
        source_type = "URL / Link"
    else:
        source_type = "Text / SMS"

    # 8. Combine Explanations
    all_reasons = list(dict.fromkeys(nlp_reasons + url_reasons + qr_reasons + ti_reasons))
    explanation = "; ".join(all_reasons) if all_reasons else "No malicious indicators detected."

    # 9. Mitigation & Auto-Blacklisting
    action = _call_dynamic(
        mitigation,
        ["apply_mitigation", "get_mitigation_action", "mitigate"],
        verdict, domains, risk_score,
        default=("Blocked & Domain Blacklisted" if verdict == "Malicious" else ("Inline warning + User education sent" if verdict == "Suspicious" else "Passed to user"))
    )

    # 10. Log to SQLite DB
    content_preview = (text or ", ".join(qr_urls) or "[Image Scan]")[:250]
    scan_record = {
        "platform": platform,
        "username": username,
        "source_type": source_type,
        "content": content_preview,
        "risk_score": risk_score,
        "verdict": verdict,
        "nlp_score": nlp_score,
        "url_score": url_score,
        "qr_score": qr_score,
        "ti_score": ti_score,
        "explanation": explanation,
        "mitigation_action": action,
    }
    if hasattr(db, "log_scan"):
        try:
            db.log_scan(scan_record)
        except Exception:
            pass

    return {
        "verdict": verdict,
        "risk_score": risk_score,
        "platform": platform,
        "source_type": source_type,
        "mitigation": action,
        "explanation": explanation,
        "scores": {
            "nlp": round(nlp_score, 1),
            "url": round(url_score, 1),
            "qr": round(qr_score, 1),
            "threat_intel": round(ti_score, 1)
        }
    }