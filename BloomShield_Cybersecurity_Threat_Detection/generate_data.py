from pathlib import Path
import random
import csv

random.seed(42)
base = Path("data")
base.mkdir(exist_ok=True)

threats = [
    "malware-example.com",
    "phishing-login-security.com",
    "evil-update.net",
    "credential-steal.org",
    "bad-domain.example",
    "http://malware-example.com/payload",
    "https://phishing-login-security.com/login",
    "185.199.110.10",
    "45.76.120.44",
    "203.0.113.55",
    "a3f2d8c1b7e9f0a1c2d3e4f5a6b7c8d9",
    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
]

with open(base / "threat_indicators.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["indicator", "type", "source"])
    for x in threats:
        typ = "url" if "://" in x else ("ip" if x.replace(".", "").isdigit() else ("hash" if len(x) >= 32 else "domain"))
        w.writerow([x, typ, "academic_demo_feed"])

normal_domains = [
    "google.com", "microsoft.com", "github.com", "christuniversity.in",
    "wikipedia.org", "python.org", "stackoverflow.com", "openai.com",
    "apple.com", "amazon.com", "cloudflare.com", "example.com"
]
normal = []
for _ in range(600):
    base_domain = random.choice(normal_domains)
    variant = base_domain
    if random.random() < 0.25:
        variant = random.choice(["www.", "docs.", "mail.", "support."]) + base_domain
    if random.random() < 0.20:
        variant += random.choice(["/home", "/login", "/docs", "/about", "/products"])
    normal.append(variant)

with open(base / "normal_training.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["indicator"])
    for x in normal:
        w.writerow([x])

scan_examples = [
    "google.com",
    "malware-example.com",
    "phishing-login-security.com/login",
    "185.199.110.10",
    "random-safe-site.org",
    "xj3k9q8z1m7v4p2n6a5s9d8f0g3h1j7k.example",
    "https://github.com/docs",
]

with open(base / "sample_scan.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["indicator"])
    for x in scan_examples:
        w.writerow([x])

print("Generated data files in ./data")
