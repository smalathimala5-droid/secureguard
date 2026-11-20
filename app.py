from flask import Flask, render_template, request, jsonify, Response
import sqlite3
import re
import csv
import io
from datetime import datetime

app = Flask(__name__)
DB_NAME = "secureguard.db"


def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS tests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            test_type TEXT NOT NULL,
            test_input TEXT NOT NULL,
            status TEXT NOT NULL,
            risk TEXT NOT NULL,
            recommendation TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def analyze_sql(value):
    """
    Educational SQL Injection pattern detection.
    Analyzes input string for known SQL injection signatures.
    Returns: dict with detected (bool), risk (str), status (str), recommendation (str), rule (str)
    """
    # High-Risk Signatures: Definite SQL Injection attack payloads
    high_patterns = [
        (
            r"(\bOR\b|\bAND\b)\s+['\"]?\w*['\"]?\s*=\s*['\"]?\w*",
            "Boolean Tautology Pattern (e.g., OR 1=1 / ' OR ''=')",
            "High",
            "Suspicious SQL Injection Pattern Detected",
            "Use parameterized queries (prepared statements) and validate all input to prevent tautology-based SQL bypasses."
        ),
        (
            r"UNION\s+(ALL\s+)?SELECT",
            "UNION SELECT Data Extraction Pattern",
            "High",
            "Suspicious SQL Injection Pattern Detected",
            "Use parameterized queries and restrict database user permissions to prevent unauthorized schema extraction via UNION."
        ),
        (
            r";\s*(DROP|DELETE|UPDATE|INSERT|ALTER|TRUNCATE|EXEC|EXECUTE)\b",
            "Stacked Destructive Query Execution Pattern",
            "High",
            "Suspicious SQL Injection Pattern Detected",
            "Disable multi-statement execution in your database driver and enforce the principle of least privilege."
        ),
        (
            r"('|\")\s*(\bOR\b|\bAND\b)\s+",
            "Quote-Escaped SQL Logic Injection Pattern",
            "High",
            "Suspicious SQL Injection Pattern Detected",
            "Never concatenate raw user input directly into SQL queries; always use query parameterization."
        ),
        (
            r"(--|#|/\*).*",
            "SQL Comment Truncation Pattern",
            "High",
            "Suspicious SQL Injection Pattern Detected",
            "Use parameterized queries to treat special characters (like comment markers) strictly as literal data."
        ),
        (
            r"\b(WAITFOR\s+DELAY|BENCHMARK\s*\(|SLEEP\s*\()",
            "Time-Based Blind SQL Injection Pattern",
            "High",
            "Suspicious SQL Injection Pattern Detected",
            "Implement parameterized queries and query execution timeout limits to protect against blind SQL injection."
        ),
    ]

    for pattern, rule, risk, status, recommendation in high_patterns:
        if re.search(pattern, value, re.IGNORECASE):
            return {
                "detected": True,
                "risk": risk,
                "status": status,
                "recommendation": recommendation,
                "rule": rule
            }

    # Medium-Risk Signatures: Borderline suspicious SQL clauses or fragments
    medium_patterns = [
        (
            r"['\"].*\b(SELECT|FROM|WHERE|HAVING|ORDER\s+BY|GROUP\s+BY)\b",
            "Suspicious Unescaped Quote & SQL Keyword Fragment",
            "Medium",
            "Potential SQL Vulnerability Indicator",
            "Input contains unescaped quotes with SQL clauses. Apply strict schema validation and parameter binding."
        ),
        (
            r"\b(INFORMATION_SCHEMA|SYS\.TABLES|SYSOBJECTS)\b",
            "Database Metadata Probing Pattern",
            "Medium",
            "Potential SQL Vulnerability Indicator",
            "Restrict access to system tables and ensure application inputs are sanitized and parameterized."
        )
    ]

    for pattern, rule, risk, status, recommendation in medium_patterns:
        if re.search(pattern, value, re.IGNORECASE):
            return {
                "detected": True,
                "risk": risk,
                "status": status,
                "recommendation": recommendation,
                "rule": rule
            }

    # Low-Risk: No known pattern detected
    return {
        "detected": False,
        "risk": "Low",
        "status": "No Known Pattern Detected",
        "recommendation": "Continue using parameterized queries and strict input type validation.",
        "rule": "Safe Input"
    }


def analyze_xss(value):
    """
    Educational XSS pattern detection.
    Analyzes input string for known XSS signatures.
    Returns: dict with detected (bool), risk (str), status (str), recommendation (str), rule (str)
    """
    # High-Risk Signatures: Executable scripts or malicious event handlers
    high_patterns = [
        (
            r"<\s*script\b[^>]*>.*?<\s*/\s*script\s*>",
            "Explicit Inline Script Tag Injection",
            "High",
            "Suspicious XSS Pattern Detected",
            "Encode all output before rendering in HTML context, sanitize inputs, and deploy a strict Content Security Policy (CSP)."
        ),
        (
            r"<\s*script\b",
            "Script Element Tag Signature",
            "High",
            "Suspicious XSS Pattern Detected",
            "Use contextual HTML entity encoding and sanitize user input with a trusted HTML sanitization library."
        ),
        (
            r"javascript\s*:",
            "JavaScript Pseudo-Protocol URI Pattern",
            "High",
            "Suspicious XSS Pattern Detected",
            "Validate and whitelist URL schemes (only allow http, https, mailto). Reject javascript: URIs in links and frames."
        ),
        (
            r"\bon[a-z]+\s*=",
            "Inline HTML Event Handler Injection Pattern (e.g., onerror, onload, onclick)",
            "High",
            "Suspicious XSS Pattern Detected",
            "Avoid rendering raw user input inside HTML tag attributes. Apply attribute-level contextual escaping."
        ),
        (
            r"<\s*(iframe|object|embed|svg|applet|meta|link)\b",
            "Dangerous Embedded Element Tag Pattern",
            "High",
            "Suspicious XSS Pattern Detected",
            "Disallow embedding untrusted tags. Strip dangerous tags with a DOM sanitizer and restrict sources via CSP."
        ),
        (
            r"\b(document\.cookie|document\.location|window\.location)\b",
            "DOM / Session Access Pattern",
            "High",
            "Suspicious XSS Pattern Detected",
            "Protect cookies using the HttpOnly and SameSite flags, and prevent untrusted input from modifying DOM locations."
        ),
    ]

    for pattern, rule, risk, status, recommendation in high_patterns:
        if re.search(pattern, value, re.IGNORECASE | re.DOTALL):
            return {
                "detected": True,
                "risk": risk,
                "status": status,
                "recommendation": recommendation,
                "rule": rule
            }

    # Medium-Risk Signatures: Raw unescaped HTML tags that could cause HTML injection or defacement
    medium_patterns = [
        (
            r"<\s*/?\s*[a-zA-Z][a-zA-Z0-9]*\b[^>]*>",
            "Unescaped HTML Tag Fragment",
            "Medium",
            "Potential HTML Injection Indicator",
            "Input contains raw HTML tags. Ensure output encoding is applied to prevent HTML injection and page tampering."
        ),
        (
            r"(&lt;|&gt;|&#x?[0-9a-fA-F]+;)",
            "Obfuscated / Encoded HTML Entities",
            "Medium",
            "Potential Obfuscation Indicator",
            "Verify canonicalization order: always decode before validating and encode immediately before output rendering."
        )
    ]

    for pattern, rule, risk, status, recommendation in medium_patterns:
        if re.search(pattern, value, re.IGNORECASE):
            return {
                "detected": True,
                "risk": risk,
                "status": status,
                "recommendation": recommendation,
                "rule": rule
            }

    # Low-Risk: No known pattern detected
    return {
        "detected": False,
        "risk": "Low",
        "status": "No Known Pattern Detected",
        "recommendation": "Continue using contextual output encoding and a Content Security Policy (CSP).",
        "rule": "Safe Input"
    }


# Backwards compatibility wrappers
def check_sql(value):
    return analyze_sql(value)["detected"]


def check_xss(value):
    return analyze_xss(value)["detected"]


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/test", methods=["POST"])
def run_test():
    data = request.get_json(silent=True) or {}

    test_type = data.get("type", "").lower()
    test_input = data.get("input", "").strip()

    if test_type not in ("sql", "xss"):
        return jsonify({"error": "Invalid test type. Expected 'sql' or 'xss'."}), 400

    if not test_input:
        return jsonify({"error": "Please enter a test input string."}), 400

    if len(test_input) > 2000:
        return jsonify({"error": "Input must be under 2000 characters."}), 400

    analysis = analyze_sql(test_input) if test_type == "sql" else analyze_xss(test_input)

    status = analysis["status"]
    risk = analysis["risk"]
    recommendation = analysis["recommendation"]
    rule = analysis["rule"]
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db()
    cursor = conn.execute("""
        INSERT INTO tests
        (test_type, test_input, status, risk, recommendation, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        test_type.upper(), test_input, status,
        risk, recommendation, created_at
    ))

    test_id = cursor.lastrowid
    conn.commit()
    conn.close()

    return jsonify({
        "id": test_id,
        "type": test_type.upper(),
        "input": test_input,
        "status": status,
        "risk": risk,
        "recommendation": recommendation,
        "rule": rule,
        "created_at": created_at
    })


@app.route("/api/results")
def get_results():
    conn = get_db()
    rows = conn.execute(
        "SELECT id, test_type, test_input, status, risk, recommendation, created_at FROM tests ORDER BY id DESC"
    ).fetchall()
    conn.close()

    return jsonify([dict(row) for row in rows])


@app.route("/api/stats")
def get_stats():
    conn = get_db()

    total = conn.execute(
        "SELECT COUNT(*) FROM tests"
    ).fetchone()[0]

    high = conn.execute(
        "SELECT COUNT(*) FROM tests WHERE risk='High'"
    ).fetchone()[0]

    medium = conn.execute(
        "SELECT COUNT(*) FROM tests WHERE risk='Medium'"
    ).fetchone()[0]

    low = conn.execute(
        "SELECT COUNT(*) FROM tests WHERE risk='Low'"
    ).fetchone()[0]

    sql_count = conn.execute(
        "SELECT COUNT(*) FROM tests WHERE test_type='SQL'"
    ).fetchone()[0]

    xss_count = conn.execute(
        "SELECT COUNT(*) FROM tests WHERE test_type='XSS'"
    ).fetchone()[0]

    conn.close()

    if total == 0:
        score = 100
    else:
        # Weighted security score: Low = 100%, Medium = 50%, High = 0%
        score = max(0, min(100, round(((low * 100) + (medium * 50)) / total)))

    return jsonify({
        "total": total,
        "high": high,
        "medium": medium,
        "low": low,
        "sql_count": sql_count,
        "xss_count": xss_count,
        "score": score
    })


@app.route("/api/report.csv")
def download_report():
    conn = get_db()
    rows = conn.execute(
        "SELECT id, test_type, test_input, status, risk, recommendation, created_at "
        "FROM tests ORDER BY id DESC"
    ).fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "ID", "Test Type", "Test Input", "Status",
        "Risk", "Recommendation", "Date"
    ])

    for row in rows:
        writer.writerow(list(row))

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition":
            "attachment; filename=secureguard_report.csv"
        }
    )


@app.route("/api/clear", methods=["POST"])
def clear_history():
    conn = get_db()
    conn.execute("DELETE FROM tests")
    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": "Test history cleared successfully."
    })


initialize_db()

if __name__ == "__main__":
    app.run(debug=True)
