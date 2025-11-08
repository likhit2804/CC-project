#!/usr/bin/env python3
import os
import time
import json
import requests
import sys
from dotenv import load_dotenv

# =============================
# === LOAD ENVIRONMENT FILE ===
# =============================
load_dotenv()  # Auto-loads .env from current directory

# =============================
# === CONFIGURATION OPTIONS ===
# =============================
API_URL = os.environ.get("TA_IAC_API_URL")
POLL_INTERVAL = int(os.environ.get("TA_IAC_POLL_INTERVAL", "10"))
MAX_WAIT = int(os.environ.get("TA_IAC_MAX_WAIT", "300"))
BLOCK_SEVERITY = os.environ.get("TA_IAC_BLOCK_SEVERITY", "HIGH").upper()

SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# =============================
# === UTILITY HELPERS =========
# =============================

def color(text, sev):
    """Add color for terminal output by severity."""
    colors = {
        "LOW": "\033[92m",       # green
        "MEDIUM": "\033[93m",    # yellow
        "HIGH": "\033[91m",      # red
        "CRITICAL": "\033[95m",  # magenta
        "END": "\033[0m"
    }
    return f"{colors.get(sev, '')}{text}{colors['END']}"

# =============================
# === CORE LOGIC ==============
# =============================

def submit_plan(plan_path="plan.json"):
    """Submit Terraform plan JSON to TA-IaC API."""
    if not API_URL:
        print("❌ Error: TA_IAC_API_URL not set in environment.")
        sys.exit(1)
    if not os.path.exists(plan_path):
        print(f"❌ Plan file not found: {plan_path}")
        sys.exit(1)

    print(f"📤 Submitting Terraform plan: {plan_path}")
    with open(plan_path, "r") as f:
        plan = json.load(f)

    try:
        resp = requests.post(f"{API_URL}/scans", json=plan, timeout=30)
        resp.raise_for_status()
    except requests.RequestException as e:
        print(f"❌ Failed to submit plan: {e}")
        sys.exit(1)

    scan_id = resp.json().get("scan_id")
    if not scan_id:
        print(f"❌ Invalid response: {resp.text}")
        sys.exit(1)

    print(f"✅ Submitted successfully → scan_id={scan_id}")
    return scan_id


def poll(scan_id):
    """Poll the TA-IaC API for scan completion."""
    print(f"⏳ Polling scan {scan_id} every {POLL_INTERVAL}s...")
    start = time.time()

    while True:
        try:
            resp = requests.get(f"{API_URL}/scans/{scan_id}", timeout=20)
            resp.raise_for_status()
        except requests.RequestException as e:
            print(f"⚠️  Polling failed: {e}")
            time.sleep(POLL_INTERVAL)
            continue

        data = resp.json()
        status = data.get("status")
        print(f"→ Status: {status}")

        if status in ("COMPLETED", "FAILED"):
            return data

        if time.time() - start > MAX_WAIT:
            raise TimeoutError(f"⏰ Timeout waiting for scan {scan_id} after {MAX_WAIT}s")

        time.sleep(POLL_INTERVAL)


def summarize_results(data):
    """Print and summarize findings from scan."""
    print("\n🧩 === Scan Summary ===")
    results = data.get("results_json", [])
    worst = "LOW"

    if not results:
        print("⚠️  No results found in scan output.")
        return worst

    for r in results:
        res_id = r.get("resource_id", "unknown")
        sev = r.get("risk_score", "LOW").upper()
        print(f" - {res_id:<50} [{color(sev, sev)}]")
        if SEVERITY_ORDER.get(sev, 1) > SEVERITY_ORDER.get(worst, 1):
            worst = sev

    print(f"\nOverall Severity: {color(worst, worst)}")
    return worst


def generate_report(data, path="scan_report.md"):
    """Write a Markdown summary report."""
    with open(path, "w", encoding="utf-8") as f:
        f.write("# 🛡️ Threat-Aware IaC Scan Report\n\n")
        f.write(f"**Scan ID:** `{data.get('scan_id')}`\n\n")
        f.write(f"**Status:** `{data.get('status')}`\n\n")
        f.write("## Findings\n\n")

        for r in data.get("results_json", []):
            f.write(f"### {r.get('resource_id', 'unknown')}\n")
            f.write(f"- **Type:** `{r.get('resource_type', 'unknown')}`\n")
            f.write(f"- **Risk:** **{r.get('risk_score', 'N/A')}**\n")
            f.write(f"- **Details:** {r.get('details', '')}\n")
            if r.get("findings"):
                f.write(f"- **Threat Feeds:**\n")
                for fnd in r["findings"]:
                    f.write(f"  - {fnd.get('feed', 'unknown')}: {fnd.get('risk_level', 'low')} → {fnd.get('evidence', '')}\n")
            f.write("\n")

    print(f"📄 Report saved → {path}")

# =============================
# === MAIN EXECUTION ==========
# =============================
if __name__ == "__main__":
    plan_file = sys.argv[1] if len(sys.argv) > 1 else "plan.json"

    try:
        scan_id = submit_plan(plan_file)
        data = poll(scan_id)
        severity = summarize_results(data)
        generate_report(data)
    except Exception as e:
        print(f"❌ Execution failed: {e}")
        sys.exit(1)

    # === CI/CD logic ===
    if SEVERITY_ORDER.get(severity, 1) >= SEVERITY_ORDER.get(BLOCK_SEVERITY, 3):
        print(f"\n❌ Build failed — {severity} ≥ {BLOCK_SEVERITY}")
        sys.exit(2)
    else:
        print(f"\n✅ Build passed — no {BLOCK_SEVERITY}+ findings")
        sys.exit(0)
