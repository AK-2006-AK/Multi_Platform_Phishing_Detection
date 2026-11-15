from database.db import add_to_blacklist

def decide_and_apply(verdict: str, domain: str = "") -> str:
    if verdict == "Malicious":
        if domain:
            add_to_blacklist(domain)
        return "Link neutralized & Domain blacklisted"
    elif verdict == "Suspicious":
        return "Inline warning + User education sent"
    return "Passed to user"
