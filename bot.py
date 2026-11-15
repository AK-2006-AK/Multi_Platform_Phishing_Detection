import os
import asyncio
import datetime
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
import detection_engine
from database import db

BOT_TOKEN = "8914940526:AAFX_-p6YQ7NNA43XdUnS65TPOViilz72TA"

if hasattr(db, "init_db"):
    db.init_db()

def format_reply(result: dict) -> str:
    verdict = result["verdict"]
    score = result["risk_score"]
    scores = result["scores"]
    explanation = result["explanation"]

    if verdict == "Malicious":
        icon = "🔴"
        action = "Blocked / Warning Issued"
    elif verdict == "Suspicious":
        icon = "🟡"
        action = "Caution Advised"
    else:
        icon = "🟢"
        action = "Passed to user"

    return (
        f"{icon} *VERDICT: {verdict.upper()}*\n"
        f"📊 *Risk Score:* `{score}%`\n"
        f"🌐 *Platform:* Telegram (Text / SMS)\n"
        f"🛡️ *Action:* {action}\n\n"
        f"🔍 *Signal Breakdown:*\n"
        f"• NLP Text: `{scores['nlp']}%`\n"
        f"• URL Analysis: `{scores['url']}%`\n"
        f"• QR Decoder: `{scores['qr']}%`\n"
        f"• Threat Intel: `{scores['threat_intel']}%`\n\n"
        f"💡 *Reason:* {explanation}"
    )

async def start_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🛡️ *PhishGuard AI Bot is Online!*\n\n"
        "Send or forward any suspicious *text message*, *website link*, or *QR code image* to scan it instantly.",
        parse_mode="Markdown"
    )

async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text or ""
    user = update.effective_user.username or update.effective_user.first_name or "Telegram_User"

    result = detection_engine.analyze(
        text=text,
        image_path=None,
        platform="Telegram",
        username=user
    )

    now = datetime.datetime.now().strftime("%H:%M:%S")
    icon = "🔴" if result["verdict"] == "Malicious" else ("🟡" if result["verdict"] == "Suspicious" else "🟢")
    print(f"[{now}] 👤 @{user:<12} | 📂 Text / SMS     | {icon} {result['verdict'].upper()} ({result['risk_score']}%)")

    await update.message.reply_text(format_reply(result), parse_mode="Markdown")

async def handle_photo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user.username or update.effective_user.first_name or "Telegram_User"
    caption = update.message.caption or ""
    temp_path = f"temp_tg_{update.message.message_id}.jpg"

    status_msg = await update.message.reply_text("🔍 Scanning QR code & image...")

    try:
        photo = update.message.photo[-1]
        file = await context.bot.get_file(photo.file_id, read_timeout=60, connect_timeout=60)
        await file.download_to_drive(temp_path, read_timeout=60, connect_timeout=60)

        result = detection_engine.analyze(
            text=caption,
            image_path=temp_path,
            platform="Telegram",
            username=user
        )

        now = datetime.datetime.now().strftime("%H:%M:%S")
        icon = "🔴" if result["verdict"] == "Malicious" else ("🟡" if result["verdict"] == "Suspicious" else "🟢")
        print(f"[{now}] 👤 @{user:<12} | 📂 QR / Image     | {icon} {result['verdict'].upper()} ({result['risk_score']}%)")

        await status_msg.edit_text(format_reply(result), parse_mode="Markdown")

    except Exception as e:
        print(f"[ERROR] Photo scan failed: {e}")
        await status_msg.edit_text("⚠️ Network timeout while downloading image. Please send the QR photo once more.")
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

def main():
    app = (
        Application.builder()
        .token(BOT_TOKEN)
        .connect_timeout(60.0)
        .read_timeout(60.0)
        .write_timeout(60.0)
        .pool_timeout(60.0)
        .build()
    )

    app.add_handler(CommandHandler("start", start_cmd))
    app.add_handler(MessageHandler(filters.PHOTO, handle_photo))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))

    print("=" * 62)
    print("🛡️  PHISHGUARD AI — MULTI-PLATFORM THREAT DETECTION ENGINE")
    print("🤖  Telegram Bot : @ak_cypher_bot [ONLINE]")
    print("📡  Modules      : NLP | URL Analyzer | QR Decoder | Threat Intel")
    print("=" * 62)
    print("Listening for incoming messages & QR codes... (Press Ctrl+C to stop)\n")

    app.run_polling(drop_pending_updates=True)

if __name__ == "__main__":
    main()