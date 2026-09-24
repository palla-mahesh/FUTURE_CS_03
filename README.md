🛡️ Task 3: API Security Risk Analysis
A full-stack Python tool for automated API Security Risk Analysis, built for Kali Linux.
📋 Task Overview
This project fulfills Task 3 - API Security Risk Analysis by providing:
Identification of insecure API endpoints and data exposure risks
Analysis of authentication and authorization issues
Detection of missing rate-limiting and input-validation gaps
Business-friendly risk explanations
Professional PDF and Markdown report generation
🛠️ Tools Used
Tool	Purpose
Python 3	Core language
Flask	Full-stack web framework
Requests	HTTP client
ReportLab	PDF generation
Browser	Report and result inspection
🚀 Installation
```bash
cd Task3_API_Security_Analysis
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```
For Kali Linux environments where PEP 668 blocks global package installation, use a virtual environment rather than `--break-system-packages`.
▶️ Running the Tool
```bash
python3 api_sec_tool.py
```
Then open:
```text
http://127.0.0.1:5000
```
Or use:
```bash
./run.sh
```
🧪 Sample Test Targets
The `test_targets/sample_targets.txt` file contains public endpoints suggested in the task material.
Only test APIs that you own or are explicitly authorized to assess.
📊 Features
Broken authentication triage
Security-header inspection
Rate-limiting check
Sensitive-data keyword scan
Malformed-input/error-leakage check
PDF report generation
Markdown export
Business-friendly remediation guidance
📁 Project Structure
```text
Task3_API_Security_Analysis/
├── api_sec_tool.py
├── requirements.txt
├── README.md
├── .gitignore
├── run.sh
├── deliverables/
│   ├── API_Security_Risk_Analysis_Report.md
│   ├── API_Security_Risk_Analysis_Report.pdf
│   └── remediation_guide.md
├── screenshots/
│   └── README.txt
└── test_targets/
    └── sample_targets.txt
```
📤 Deliverables
`deliverables/API_Security_Risk_Analysis_Report.md`
`deliverables/API_Security_Risk_Analysis_Report.pdf`
`deliverables/remediation_guide.md`
`screenshots/README.txt`
`test_targets/sample_targets.txt`
🔐 Ethical Use
This tool is for authorized security testing and educational purposes only. Do not scan third-party systems without explicit permission.
👤 Author
Created for the API Security Risk Analysis Task.
