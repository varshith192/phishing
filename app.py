from flask import Flask, render_template, request
import joblib
from urllib.parse import urlparse
import socket
import requests
import whois
from datetime import datetime

app = Flask(__name__)
model = joblib.load("phishing_url_model.pkl")

RESTRICTED_KEYWORDS = [
    "movierulz", "123movies", "torrent", "piratebay",
    "porn", "xxx", "adult", "betting", "casino"
]

PHISHING_KEYWORDS = [
    "login", "verify", "secure", "update", "account",
    "bank", "paypal", "confirm", "signin", "password"
]

def extract_features(url):
    return [
        len(url),
        1 if url.startswith("https") else 0,
        url.count('.'),
        1 if '@' in url else 0,
        1 if any(c.isdigit() for c in urlparse(url).netloc) else 0
    ]

def get_domain(url):
    if not url.startswith("http"):
        url = "http://" + url
    return urlparse(url).netloc

def get_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return None

def get_ip_info(ip):
    try:
        res = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5)
        data = res.json()
        return data.get("country_name", "Unknown"), data.get("org", "Unknown ISP")
    except:
        return "Unknown", "Unknown ISP"

def get_domain_age(domain):
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        age = datetime.now().year - creation.year
        return f"{age} years"
    except:
        return "Not Available"

@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    confidence = None
    ip = country = isp = domain_age = None

    if request.method == "POST":
        url = request.form["url"].lower()

        domain = get_domain(url)
        ip = get_ip(domain)

        if ip is None:
            result = "❌ FAKE / INACTIVE WEBSITE — DOMAIN NOT FOUND"
            return render_template("index.html", result=result)

        country, isp = get_ip_info(ip)
        domain_age = get_domain_age(domain)

        if any(word in url for word in RESTRICTED_KEYWORDS):
            result = "❌ PIRACY WEBSITE — NOT SAFE"

        elif any(word in url for word in PHISHING_KEYWORDS):
            result = "❌ PHISHING WEBSITE — NOT SAFE"

        else:
            features = extract_features(url)
            proba = model.predict_proba([features])[0]
            pred = model.predict([features])[0]
            confidence = round(max(proba) * 100, 2)

            if pred == 1:
                result = "❌ PHISHING WEBSITE — NOT SAFE"
            else:
                result = "✅ SAFE WEBSITE"

    return render_template(
        "index.html",
        result=result,
        confidence=confidence,
        ip=ip,
        country=country,
        isp=isp,
        domain_age=domain_age
    )

if __name__ == "__main__":
    app.run(debug=True)
