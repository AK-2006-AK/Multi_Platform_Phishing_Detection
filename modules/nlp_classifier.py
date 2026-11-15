from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB

TRAIN_DATA = [
    ("We Just Sent Your Access Code Check your Telegram Show My Code", 1),
    ("Login code Do not give this code to anyone even if they say they are from Telegram", 1),
    ("Exclusive Desi XXX Pure HD Watch Now click link", 1),
    ("Urgent Your SBI bank account is blocked Update KYC immediately", 1),
    ("Congratulations You won a Rs 50000 lottery prize Click link to claim", 1),
    ("Verify your Paytm wallet OTP now to avoid suspension", 1),
    ("Instagram copyright violation warning verify your blue badge account now", 1),
    ("WhatsApp Pink update download new version link", 1),
    ("Free iPhone 15 giveaway Register your details here", 1),
    ("Part time work from home earn 5000 daily message on WhatsApp", 1),
    ("Hi da innu college-il class undo", 0),
    ("Meeting is scheduled at 10 AM tomorrow in the main conference room", 0),
    ("Please find attached the project report and presentation slides", 0),
    ("Happy birthday Have a great year ahead", 0),
    ("Your Amazon order has been shipped and will arrive by Friday", 0),
    ("Can you send me the notes for cybersecurity module 3", 0),
    ("Let us catch up for coffee at 5 PM near Chalakudy", 0),
    ("Thank you for your payment Receipt is attached", 0),
]

vectorizer = TfidfVectorizer(stop_words="english")
X_train = vectorizer.fit_transform([t[0] for t in TRAIN_DATA])
y_train = [t[1] for t in TRAIN_DATA]
clf = MultinomialNB().fit(X_train, y_train)

def predict_risk(text: str):
    if not text or len(text.strip()) < 3:
        return 0, []
    prob_scam = clf.predict_proba(vectorizer.transform([text]))[0][1]
    score = round(prob_scam * 100, 1)
    reasons = ["Social engineering / OTP hijack / clickbait lure detected"] if score > 50 else []
    return score, reasons