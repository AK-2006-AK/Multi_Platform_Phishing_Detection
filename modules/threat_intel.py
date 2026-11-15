import requests
from database.db import is_blacklisted, add_to_blacklist

OPENPHISH_FEED = "https://openphish.com/feed.txt"
_cached_feed = set()

def _load_live_feed():
    global _cached_feed
    if _cached_feed:
        return _cached_feed
    try:
        resp = requests.get(OPENPHISH_FEED, timeout=4)
        if resp.status_code == 200:
            _cached_feed = {line.strip().lower() for line in resp.text.splitlines() if line.strip()}
    except Exception:
        pass
    return _cached_feed

def check_blacklist(domain: str, full_url: str = ""):
    if not domain and not full_url:
        return 0, []

    if is_blacklisted(domain):
        return 100, [f"Domain '{domain}' is in local Threat Intelligence blacklist"]

    live_urls = _load_live_feed()
    url_clean = full_url.lower().strip()
    if url_clean in live_urls or any(domain and domain in u for u in live_urls):
        add_to_blacklist(domain)
        return 100, [f"Domain '{domain}' matched live global OpenPhish threat feed"]

    return 0, []