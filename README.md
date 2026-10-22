# EthicalHackingAgent 🛡️

A Python-based local web security scanner featuring passive security checks, a web dashboard, scan history, finding comparisons, and JSON/HTML reports.

## Overview

**EthicalHackingAgent** is a security assessment tool designed to inspect local web applications and identify common security configuration issues. It provides structured findings, severity summaries, historical comparisons, and exportable reports through a command-line interface and a local web dashboard.

The project is designed for controlled, local security testing and educational use.

## Features

- **Local-only scanning** — restricts targets to localhost and loopback addresses.
- **HTTP inspection** — inspects HTTP responses without following redirects.
- **Security header analysis** — checks for missing or misconfigured security headers.
- **Passive security checks** — examines cookies, CORS configuration, HTTP methods, and technology disclosures.
- **Structured findings** — organizes observations with stable finding IDs and severity information.
- **Web dashboard** — launches a local dashboard for running scans and viewing results.
- **Scan history** — stores scan history locally and supports filtering.
- **Finding comparisons** — classifies findings as new, recurring, resolved (observed), or not assessed when comparison conditions allow.
- **Report generation** — exports findings and assessment results to JSON and HTML.
- **Security hardening** — includes request restrictions, safe error handling, report access controls, and browser security headers.
- **Automated tests** — includes tests for scanning, analysis, reporting, assessment, and dashboard behavior.

## Technology Stack

- Python 3.11
- FastAPI
- Requests
- Pytest
- HTML, CSS, and JavaScript

See [`requirements.txt`](requirements.txt) for the project's dependencies.

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/dhxxrxxn12/EthicalHackingAgent.git
cd EthicalHackingAgent
```

### 2. Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 4. Run the command-line scanner

Check the available options:

```bash
python -m app.main --help
```

Use the help output to select supported options and scan only an authorized local target.

### 5. Run the dashboard

Check the dashboard module's supported options, if available, or launch it using the project's documented startup command.

The dashboard is intended to run on the local machine at `127.0.0.1:8080`.

### 6. Run the tests

```bash
python -m pytest -q
```

## Example Local Test Target

You can start a simple local HTTP server in a separate terminal:

```bash
python3 -m http.server 8000 --bind 127.0.0.1
```

Use `http://127.0.0.1:8000/` as a local test target if supported by the scanner's command-line options.

A basic HTTP server may produce findings for missing security headers or disclosed server information. These findings are observations, not proof that a vulnerability is exploitable.

## Project Structure

```text
EthicalHackingAgent/
├── app/
│   ├── assessment.py
│   ├── dashboard.html
│   ├── dashboard.js
│   ├── dashboard.py
│   ├── findings.py
│   ├── header_analyzer.py
│   ├── http_inspector.py
│   ├── main.py
│   ├── reporter.py
│   └── target_validator.py
├── tests/
├── reports/
├── .gitignore
├── README.md
└── requirements.txt
```

## Security and Responsible Use

- Only scan systems you own or have explicit permission to assess.
- The scanner is intended for local targets and should not be treated as a penetration-testing or exploitation framework.
- Passive checks identify potential configuration weaknesses; manual verification may be required.
- Do not commit API keys, passwords, environment files, private data, or generated scan reports.
- Review findings in context before making security decisions.

## Current Scope

The project focuses on local web inspection, passive checks, scan history, finding comparisons, and report generation. It does not claim to detect every vulnerability or replace a comprehensive security audit.

## Testing

The latest reported test suite contained **60 passing tests**. Run the test command above to verify the current checkout.

## License

No license has been specified yet. Add a license file if you intend to define permissions for reuse and distribution.

---

**Author:** [dhxxrxxn12](https://github.com/dhxxrxxn12)

