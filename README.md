# 🔍 URL Security Scanner & Phishing Detection Tool

> ⚠ Educational Use Only
>
> All analysis runs entirely inside the browser. No URLs are submitted to external services, databases, or third-party APIs.

A React-based cybersecurity tool that analyzes URLs for phishing indicators, typosquatting, homograph attacks, URL obfuscation, brand impersonation, and suspicious domain patterns - using a multi-technique heuristic detection engine with per-flag educational explanations.

---

# 🌐 Live Demo Link

https://url-scanner-pwhm.vercel.app/

---

# 📖 Overview

Cybercriminals craft deceptive URLs to lure users into phishing websites, malware downloads, and credential theft - often making URLs appear legitimate at a glance.

This scanner evaluates URLs across 11 detection techniques, generates a 0-100 risk score, and explains every flagged issue in plain language - teaching users not just *what* is suspicious, but *why* and *how* attackers exploit it.

---

# ✨ Features

### 🔎 Multi-Technique URL Analysis

| Detection Technique | What It Catches |
|--------------------|----------------|
| Suspicious TLDs | `.xyz`, `.tk`, `.pw`, `.top` and other high-abuse extensions |
| Typosquatting | Misspelled brand names (Levenshtein distance matching) |
| Brand Impersonation | Legitimate brand names embedded in subdomains or paths |
| Homograph Attacks | Lookalike Unicode characters mimicking trusted domains |
| Excessive Subdomains | Deep subdomain chains used to obscure the real domain |
| URL Encoding Abuse | Percent-encoded characters hiding malicious content |
| Suspicious Keywords | `login`, `verify`, `secure`, `account`, `update`, `banking` etc. |
| IP Address URLs | Direct IP hostnames instead of domain names |
| Redirect Chains | Embedded redirect URLs concealing final destinations |
| Entropy Analysis | High-entropy / machine-generated random-looking domains |
| Non-Standard Ports | Unusual port numbers associated with malicious services |

### 📊 Risk Scoring Engine

- Risk score from **0–100** with three verdict tiers:
  - ✅ Likely Safe
  - ⚠️ Suspicious
  - 🚨 Dangerous
- Per-detection severity breakdown
- Detailed explanation for every flagged indicator

### 📚 Educational Explanations

Every detection includes:
- Why the pattern was flagged
- How attackers use the technique in real campaigns
- What the user should do or look for

### 🔒 Privacy-First

- Browser-only execution
- No URL logging or storage
- No external API calls
- No data leaves the browser

---

# 🎯 Learning Objectives

This project helps users:

- Analyze suspicious URLs before visiting them
- Recognize typosquatting and homograph attack patterns
- Understand how URL obfuscation hides malicious intent
- Identify brand impersonation in domain structures
- Build practical URL inspection habits for everyday browsing

---

# ⚙️ Technology Stack

- React.js
- JavaScript (ES6+)
- HTML5 / CSS3
- React Hooks
- Browser-Only Execution — no backend, no database, no API

**Detection Engine Techniques:**
- Heuristic pattern matching
- Levenshtein distance for typosquat detection
- Shannon entropy analysis for domain randomness
- URL parsing and structural decomposition
- Domain reputation indicators
- Phishing keyword and pattern recognition

---

# 🚀 Installation

## Clone Repository

```bash
git clone https://github.com/YOUR_USERNAME/url-security-scanner.git
cd url-security-scanner
```

## Install Dependencies

```bash
npm install
```

## Run Development Server

```bash
npm start
```

## Create Production Build

```bash
npm run build
```

---

# 📸 Screenshots

### Dashboard
![Dashboard](screenshots/dashboard.png)

### Detection Results
![Results](screenshots/results.png)

### Risk Score Analysis
![Risk Analysis](screenshots/risk-analysis.png)

### Phishing Detection Example
![Phishing Detection](screenshots/phishing-example.png)

---

# 🎓 Example Use Cases

- Analyzing suspicious links before clicking
- Cybersecurity awareness training and workshops
- University information security coursework
- Phishing detection demonstrations
- Threat analysis and ethical hacking training
- Security awareness campaigns

---

# 📂 Project Structure

```text
url-security-scanner/
│
├── public/
│
├── src/
│   ├── App.js
│   ├── index.js
│   └── URLScanner.jsx
│
├── screenshots/
│   ├── dashboard.png
│   ├── results.png
│   ├── risk-analysis.png
│   └── phishing-example.png
│
├── .gitignore
├── LICENSE
├── README.md
├── package.json
└── package-lock.json
```

---

# ⚠ Disclaimer

This project is intended strictly for educational purposes and cybersecurity awareness training.

The scanner uses heuristic analysis and should not be considered a replacement for professional threat intelligence platforms or enterprise security solutions.

Results should be treated as educational guidance rather than definitive security assessments.

The author assumes no responsibility for misuse of this software.

---

# 👨‍💻 Author

**Charuka Weerasinghe**
Cybersecurity Student | Information Security Enthusiast

---

# 📄 License

Licensed under the MIT License.
Free to use for educational, academic, and cybersecurity awareness purposes.
