# SECUREGUARD 🛡️
### Web Application Security Testing and Vulnerability Detection System

SECUREGUARD is an educational, pattern-based web application security testing and vulnerability detection system. It provides an intuitive, dark-themed glassmorphism interface for testing input strings against common web vulnerabilities, specifically **SQL Injection (SQLi)** and **Cross-Site Scripting (XSS)**.

---

## 🌟 Key Features & Modules

1. **SQL Injection (SQLi) Detection Module**:
   - Detects boolean-based tautologies (`' OR '1'='1`, `OR 1=1`), `UNION SELECT` extraction patterns, stacked destructive queries (`; DROP TABLE`), SQL comment injection (`--`, `/*...*/`, `#`), and time-based blind injection attempts (`WAITFOR DELAY`, `BENCHMARK`, `SLEEP`).
   - Categorizes findings into **High Risk**, **Medium Risk**, and **Low Risk** with defensive recommendations (parameterized queries/prepared statements).

2. **Cross-Site Scripting (XSS) Detection Module**:
   - Detects inline script execution (`<script>`), pseudo-protocols (`javascript:`), malicious HTML event handlers (`onerror=`, `onload=`, `onclick=`), and dangerous embedded elements (`<iframe>`, `<object>`, `<svg>`).
   - Recommends contextual HTML entity encoding, input sanitization, and Content Security Policy (CSP) implementation.

3. **Security Overview Dashboard**:
   - Live counter cards for **Total Tests**, **High Risk**, **Medium Risk**, and **Low Risk** findings.
   - Dynamic **Security Health Score** (0–100) calculated from saved test records.

4. **Security Analysis & Posture Evaluation**:
   - Posture status evaluation (Optimal Posture / Moderate Risk Warnings / Remediation Required).
   - Test execution metrics broken down by vulnerability type.

5. **Test History & SQLite Persistence**:
   - All tests, inputs, statuses, risk assessments, recommendations, and timestamps are automatically recorded in an SQLite database (`secureguard.db`).
   - Interactive history log with status badges and test input previews.

6. **CSV Security Report Export**:
   - One-click downloadable report (`secureguard_report.csv`) formatted for documentation and audits.

---

## 💻 Tech Stack

- **Backend**: Python 3, Flask
- **Database**: SQLite3
- **Frontend**: HTML5, CSS3 (Glassmorphism, Dark Navy & Purple Neon Theme), JavaScript (ES6 Fetch API)
- **Export**: Standard CSV

---

## 📁 Project Structure

```text
secureguard/
│
├── app.py                  # Main Flask application & pattern detection engine
├── requirements.txt        # Python dependencies
├── secureguard.db          # SQLite database (auto-created on startup)
├── .gitignore              # Files excluded from git tracking
├── README.md               # Project documentation
│
├── static/
│   ├── css/
│   │   └── style.css       # Glassmorphism styling, responsive layouts, animations
│   └── js/
│       └── script.js       # Dynamic routing, API integration, and DOM updates
│
└── templates/
    └── index.html          # Main application page (single-page interface)
```

---

## 🚀 How to Run the Project Locally

### 1. Prerequisites
- Python 3.8 or higher installed on your computer.

### 2. Clone or Download the Repository
```bash
git clone https://github.com/<your-username>/secureguard.git
cd secureguard
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the Application
```bash
python app.py
```

### 5. Open in Your Browser
Visit:
```
http://127.0.0.1:5000/
```

---

## ⚠️ Educational Disclaimer
SECUREGUARD is developed strictly for **educational and learning purposes** to demonstrate input validation and pattern matching techniques for defensive web security. It does not perform live network penetration testing or execute exploits on live servers.
