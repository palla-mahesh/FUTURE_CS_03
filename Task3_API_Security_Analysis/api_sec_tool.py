import json
import io
import os
import requests
import urllib3
from flask import Flask, render_template_string, request, jsonify, send_file
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)


class APISecurityAnalyzer:
    """Educational API security triage engine.

    Only scan endpoints that you own or are explicitly authorized to test.
    """

    def __init__(self, target_url):
        self.target_url = target_url
        self.findings = []
        self.headers = {
            "User-Agent": "Kali-Security-Scanner/1.0",
            "Accept": "application/json",
        }

    def log_finding(self, severity, category, description, impact, remediation):
        self.findings.append({
            "severity": severity,
            "category": category,
            "description": description,
            "impact": impact,
            "remediation": remediation,
        })

    def check_authentication(self):
        try:
            response = requests.get(
                self.target_url,
                headers=self.headers,
                timeout=5,
                verify=False,
            )
            if response.status_code == 200:
                self.log_finding(
                    "High",
                    "Broken Authentication",
                    "API endpoint is accessible without authentication credentials.",
                    "Unauthorized users can access sensitive data or functionality.",
                    "Implement OAuth2, JWT, or API Key authentication. Ensure endpoints validate tokens.",
                )
        except requests.RequestException as exc:
            print(f"Auth Check Error: {exc}")

    def check_security_headers(self):
        try:
            response = requests.get(
                self.target_url,
                headers=self.headers,
                timeout=5,
                verify=False,
            )
            headers = response.headers
            required_headers = {
                "Strict-Transport-Security": "HSTS missing. Vulnerable to SSL stripping.",
                "X-Content-Type-Options": "MIME sniffing possible.",
                "X-Frame-Options": "Clickjacking possible.",
                "Content-Security-Policy": "XSS protection weak.",
            }
            for header, desc in required_headers.items():
                if header not in headers:
                    self.log_finding(
                        "Medium",
                        "Security Misconfiguration",
                        f"Missing Header: {header}",
                        desc,
                        f"Add '{header}' header to server configuration.",
                    )
        except requests.RequestException as exc:
            print(f"Header Check Error: {exc}")

    def check_rate_limiting(self):
        try:
            rate_limited = False
            for _ in range(10):
                resp = requests.get(
                    self.target_url,
                    headers=self.headers,
                    timeout=2,
                    verify=False,
                )
                if resp.status_code == 429:
                    rate_limited = True
                    break

            if not rate_limited:
                self.log_finding(
                    "Medium",
                    "Lack of Resources & Rate Limiting",
                    "No rate limiting detected after 10 rapid requests.",
                    "Attackers can perform denial-of-service or brute-force attacks.",
                    "Implement rate limiting, for example through an API gateway or middleware.",
                )
        except requests.RequestException as exc:
            print(f"Rate Limit Check Error: {exc}")

    def check_data_exposure(self):
        sensitive_keywords = [
            "password",
            "secret",
            "api_key",
            "token",
            "ssn",
            "credit_card",
        ]
        try:
            response = requests.get(
                self.target_url,
                headers=self.headers,
                timeout=5,
                verify=False,
            )
            text = response.text.lower()
            found_keywords = [word for word in sensitive_keywords if word in text]

            if found_keywords:
                self.log_finding(
                    "High",
                    "Sensitive Data Exposure",
                    f"Potential sensitive data found in response: {', '.join(found_keywords)}",
                    "Exposure of credentials or PII can lead to account takeover.",
                    "Mask sensitive data in responses. Use encryption at rest and in transit.",
                )
        except requests.RequestException as exc:
            print(f"Data Exposure Check Error: {exc}")

    def check_input_validation(self):
        malformed_payloads = [
            "' OR '1'='1",
            "<script>alert(1)</script>",
            "../../../etc/passwd",
        ]
        try:
            for payload in malformed_payloads:
                response = requests.get(
                    self.target_url,
                    params={"input": payload},
                    headers=self.headers,
                    timeout=5,
                    verify=False,
                )
                response_text = response.text.lower()
                error_markers = [
                    "sql syntax",
                    "traceback",
                    "stack trace",
                    "warning: mysql",
                ]
                if any(marker in response_text for marker in error_markers):
                    self.log_finding(
                        "High",
                        "Injection / Improper Input Validation",
                        f"Server leaked error details when given malformed input: {payload}",
                        "Attackers can use error messages to map database structure or exploit injection flaws.",
                        "Sanitize all inputs and return generic error messages to clients. Log details server-side only.",
                    )
                    break
        except requests.RequestException as exc:
            print(f"Input Validation Check Error: {exc}")

    def run_all(self):
        self.check_authentication()
        self.check_security_headers()
        self.check_rate_limiting()
        self.check_data_exposure()
        self.check_input_validation()
        return self.findings


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kali API Security Analyzer</title>
    <style>
        :root {
            --bg: #0f0f0f;
            --card: #1e1e1e;
            --accent: #00ff9d;
            --text: #e0e0e0;
            --danger: #ff4444;
            --warn: #ffbb33;
        }
        body {
            font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 20px;
        }
        .container { max-width: 900px; margin: 0 auto; }
        h1 {
            color: var(--accent);
            text-align: center;
            border-bottom: 2px solid var(--accent);
            padding-bottom: 10px;
        }
        .card {
            background-color: var(--card);
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.3);
            margin-bottom: 20px;
        }
        input[type="text"] {
            width: 70%;
            padding: 10px;
            border-radius: 4px;
            border: 1px solid #333;
            background: #111;
            color: white;
        }
        button {
            padding: 10px 20px;
            background: var(--accent);
            border: none;
            color: #000;
            font-weight: bold;
            cursor: pointer;
            border-radius: 4px;
            transition: 0.3s;
        }
        button:hover { background: #00cc7a; }
        button:disabled { background: #555; cursor: not-allowed; }
        .finding {
            border-left: 4px solid var(--accent);
            padding: 10px;
            margin-bottom: 10px;
            background: #252525;
        }
        .High { border-left-color: var(--danger); }
        .Medium { border-left-color: var(--warn); }
        .Low { border-left-color: #00aaff; }
        .severity {
            font-weight: bold;
            text-transform: uppercase;
            font-size: 0.8em;
        }
        .High .severity { color: var(--danger); }
        .Medium .severity { color: var(--warn); }
        .Low .severity { color: #00aaff; }
        #loader { display: none; text-align: center; margin-top: 20px; }
        .spinner {
            border: 4px solid #333;
            border-top: 4px solid var(--accent);
            border-radius: 50%;
            width: 30px;
            height: 30px;
            animation: spin 1s linear infinite;
            margin: 0 auto;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .hidden { display: none; }
        .btn-group {
            margin-top: 20px;
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        .btn-secondary { background: #333; color: white; }
        .btn-secondary:hover { background: #444; }
        .summary { display: flex; gap: 15px; margin-bottom: 20px; }
        .summary div { padding: 10px 15px; border-radius: 4px; font-weight: bold; }
        .sum-high { background: rgba(255,68,68,0.2); color: var(--danger); }
        .sum-med { background: rgba(255,187,51,0.2); color: var(--warn); }
        .sum-low { background: rgba(0,170,255,0.2); color: #00aaff; }
    </style>
</head>
<body>
<div class="container">
    <h1>🛡️ API Security Risk Analyzer</h1>

    <div class="card">
        <h3>Target Configuration</h3>
        <p>Enter an API endpoint URL to analyze.</p>
        <input type="text" id="targetUrl" placeholder="https://example.com/api/resource">
        <button onclick="startScan()" id="scanBtn">Run Analysis</button>
    </div>

    <div id="loader">
        <div class="spinner"></div>
        <p>Analyzing API Security Posture...</p>
    </div>

    <div id="results" class="hidden">
        <div class="card">
            <h2>Analysis Report</h2>
            <div id="summary" class="summary"></div>
            <div id="findingsList"></div>
            <div class="btn-group">
                <button onclick="downloadPDF()" class="btn-secondary">📄 Download PDF Report</button>
                <button onclick="downloadMarkdown()" class="btn-secondary">📝 Export to Markdown</button>
            </div>
        </div>
    </div>
</div>

<script>
let currentFindings = [];
let targetUrl = "";

async function startScan() {
    targetUrl = document.getElementById("targetUrl").value.trim();
    if (!targetUrl) {
        alert("Please enter a URL");
        return;
    }

    document.getElementById("scanBtn").disabled = true;
    document.getElementById("loader").style.display = "block";
    document.getElementById("results").classList.add("hidden");

    try {
        const response = await fetch("/scan", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({url: targetUrl})
        });

        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.error || "Scan failed");
        }
        currentFindings = data.findings || [];
        renderResults(currentFindings);
    } catch (error) {
        alert("Error scanning API: " + error);
    } finally {
        document.getElementById("scanBtn").disabled = false;
        document.getElementById("loader").style.display = "none";
    }
}

function renderResults(findings) {
    const container = document.getElementById("findingsList");
    const summaryBox = document.getElementById("summary");
    container.innerHTML = "";
    summaryBox.innerHTML = "";

    const high = findings.filter(f => f.severity === "High").length;
    const med = findings.filter(f => f.severity === "Medium").length;
    const low = findings.filter(f => f.severity === "Low").length;

    summaryBox.innerHTML = `
        <div class="sum-high">High: ${high}</div>
        <div class="sum-med">Medium: ${med}</div>
        <div class="sum-low">Low: ${low}</div>
    `;

    if (findings.length === 0) {
        container.innerHTML =
            '<p style="color:var(--accent)">✅ No critical issues detected based on automated checks.</p>';
    } else {
        findings.forEach(f => {
            const div = document.createElement("div");
            div.className = `finding ${f.severity}`;
            div.innerHTML = `
                <div class="severity">${escapeHtml(f.severity)} Risk - ${escapeHtml(f.category)}</div>
                <div style="margin: 5px 0;"><strong>Issue:</strong> ${escapeHtml(f.description)}</div>
                <div style="margin: 5px 0; font-size: 0.9em; color: #aaa;">
                    <strong>Impact:</strong> ${escapeHtml(f.impact)}
                </div>
                <div style="margin: 5px 0; font-size: 0.9em; color: #aaa;">
                    <strong>Remediation:</strong> ${escapeHtml(f.remediation)}
                </div>
            `;
            container.appendChild(div);
        });
    }
    document.getElementById("results").classList.remove("hidden");
}

function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, function(ch) {
        return {
            "&": "&amp;", "<": "&lt;", ">": "&gt;",
            '"': "&quot;", "'": "&#39;"
        }[ch];
    });
}

function downloadPDF() {
    fetch("/download_pdf", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({findings: currentFindings, url: targetUrl})
    })
    .then(response => {
        if (!response.ok) throw new Error("PDF generation failed");
        return response.blob();
    })
    .then(blob => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "API_Security_Report.pdf";
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(url);
    })
    .catch(error => alert(error.message));
}

function downloadMarkdown() {
    let md = `# API Security Risk Analysis Report\n\n`;
    md += `**Target:** ${targetUrl}\n`;
    md += `**Date:** ${new Date().toLocaleString()}\n\n`;
    md += `## Summary\n\n`;
    md += `- High Risks: ${currentFindings.filter(f => f.severity === "High").length}\n`;
    md += `- Medium Risks: ${currentFindings.filter(f => f.severity === "Medium").length}\n`;
    md += `- Low Risks: ${currentFindings.filter(f => f.severity === "Low").length}\n\n`;
    md += `## Detailed Findings\n\n`;

    if (currentFindings.length === 0) {
        md += "No critical vulnerabilities detected.\n";
    } else {
        currentFindings.forEach(f => {
            md += `### [${f.severity}] ${f.category}\n`;
            md += `- **Issue:** ${f.description}\n`;
            md += `- **Impact:** ${f.impact}\n`;
            md += `- **Remediation:** ${f.remediation}\n\n`;
        });
    }

    const blob = new Blob([md], {type: "text/markdown"});
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "API_Security_Report.md";
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
}
</script>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    if not (url.startswith("https://") or url.startswith("http://")):
        return jsonify({"error": "Only http:// and https:// URLs are supported"}), 400

    analyzer = APISecurityAnalyzer(url)
    findings = analyzer.run_all()
    return jsonify({"findings": findings})


@app.route("/download_pdf", methods=["POST"])
def download_pdf():
    data = request.get_json(silent=True) or {}
    findings = data.get("findings", [])
    url = data.get("url", "Unknown")

    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    c.setTitle("API Security Risk Analysis Report")
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, height - 50, "API Security Risk Analysis Report")
    c.setFont("Helvetica", 10)
    c.drawString(50, height - 70, f"Target: {url}")
    c.drawString(
        50,
        height - 85,
        f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
    )

    y = height - 120

    if not findings:
        c.drawString(50, y, "No critical vulnerabilities found by the automated checks.")
    else:
        for finding in findings:
            if y < 120:
                c.showPage()
                y = height - 50

            c.setFont("Helvetica-Bold", 11)
            c.drawString(
                50,
                y,
                f"[{finding['severity']}] {finding['category']}",
            )
            y -= 18

            c.setFont("Helvetica", 9)
            for label, text in [
                ("Issue", finding["description"]),
                ("Impact", finding["impact"]),
                ("Remediation", finding["remediation"]),
            ]:
                line = f"{label}: {text}"
                # Basic word wrapping for report readability.
                words = line.split()
                current = ""
                for word in words:
                    candidate = f"{current} {word}".strip()
                    if len(candidate) > 95:
                        c.drawString(50, y, candidate[:110])
                        y -= 13
                        current = word
                    else:
                        current = candidate
                if current:
                    c.drawString(50, y, current)
                    y -= 15
            y -= 10

    c.save()
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name="API_Security_Report.pdf",
        mimetype="application/pdf",
    )


if __name__ == "__main__":
    print("=" * 50)
    print("  KALI API SECURITY ANALYZER")
    print("=" * 50)
    print("Access: http://127.0.0.1:5000")
    print("Press CTRL+C to stop")
    app.run(host="0.0.0.0", port=5000, debug=False)
