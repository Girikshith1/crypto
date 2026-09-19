import math
import re
from urllib.parse import urlparse


def normalize_indicator(value):
    s = str(value).strip().lower()
    if not s:
        return ""
    # Remove URL scheme and trailing slash for consistent comparison.
    if "://" in s:
        parsed = urlparse(s)
        s = parsed.netloc + parsed.path
    s = s.rstrip("/")
    return s


def shannon_entropy(s):
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def indicator_features(indicator):
    s = normalize_indicator(indicator)
    raw = str(indicator).strip()
    special = sum(1 for c in s if not c.isalnum() and c not in ".-_:")
    digits = sum(c.isdigit() for c in s)
    letters = sum(c.isalpha() for c in s)
    dots = s.count(".")
    slashes = s.count("/")
    hyphens = s.count("-")
    at_count = s.count("@")
    query_chars = s.count("?") + s.count("&") + s.count("=")
    max_label = max([len(x) for x in re.split(r"[./]", s) if x] or [0])

    try:
        host = urlparse(raw if "://" in raw else "//" + raw).hostname or ""
    except Exception:
        host = ""

    return {
        "length": len(s),
        "entropy": shannon_entropy(s),
        "digit_ratio": digits / max(1, len(s)),
        "letter_ratio": letters / max(1, len(s)),
        "special_ratio": special / max(1, len(s)),
        "dot_count": dots,
        "slash_count": slashes,
        "hyphen_count": hyphens,
        "at_count": at_count,
        "query_char_count": query_chars,
        "max_label_length": max_label,
        "subdomain_count": max(0, len(host.split(".")) - 2) if host else 0,
        "has_ip_like_host": int(bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host))),
    }
