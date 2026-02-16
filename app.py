# app.py (Enhanced Dashboard)
import os
import re
import json
from collections import Counter
import streamlit as st

# ---------- Streamlit Page Config ----------
st.set_page_config(page_title="SafePipe Dashboard", layout="wide")
st.title("🛡️ SafePipe – Secret Leak Detection Tool")
st.markdown("""
Detects sensitive information like API keys, AWS tokens, passwords, and private keys.
Run scans instantly and view results in a professional dashboard.
""")

# ---------- Secret Patterns ----------
SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]",
    "Private Key": r"-----BEGIN PRIVATE KEY-----",
    "Password": r"(?i)password\s*=\s*['\"].+?['\"]",
    "Token": r"[A-Za-z0-9]{20,40}(\.[A-Za-z0-9]{20,40}){0,2}"
}

# ---------- Severity Mapping ----------
SEVERITY_MAP = {
    "Private Key": "Critical",       # Red
    "AWS Access Key": "Medium",      # Orange
    "AWS Secret Key": "Medium",      # Orange
    "Password": "Low",               # Green
    "Token": "Low"                   # Green
}

COLOR_MAP = {
    "Critical": "red",
    "Medium": "orange",
    "Low": "green"
}

# ---------- Scanner Logic ----------
def scan_content(content, source="<memory>"):
    """Scan a text content string and return findings.

    Returns list of dicts with keys: type, value (string), file (source), severity.
    """
    findings = []
    try:
        for secret_name, pattern in SECRET_PATTERNS.items():
            for m in re.finditer(pattern, content, flags=0):
                # Use full matched text, not capture groups
                try:
                    value = m.group(0)
                except Exception:
                    value = m.group()
                severity = SEVERITY_MAP.get(secret_name, "Low")
                findings.append({
                    "type": secret_name,
                    "value": str(value),
                    "file": source,
                    "severity": severity
                })
    except Exception as e:
        st.error(f"Error scanning content from {source}: {e}")
    return findings

# ---------- Summary Logic ----------
def summarize_findings(findings):
    total = len(findings)
    types = [item["type"] for item in findings]
    type_counts = Counter(types)
    files = set([item["file"] for item in findings])
    severity_counts = Counter([item["severity"] for item in findings])
    return total, type_counts, files, severity_counts


def mask_value(val, show_full=False):
    try:
        s = str(val)
    except Exception:
        s = ''
    if show_full or len(s) <= 10:
        return s
    # single-line mask: keep first 4 and last 4
    return f"{s[:4]}...{s[-4:]}"

# ---------- Sidebar: File Selection ----------
st.sidebar.header("Scan Options")
uploaded_files = st.sidebar.file_uploader("Upload files for scanning", type=["txt", "py", "js", "env", "json", "md"], accept_multiple_files=True)
use_demo_file = st.sidebar.checkbox("Use demo test file (`test_secrets.txt`)", value=not uploaded_files)
show_full = st.sidebar.checkbox("Show full secret values (warning: exposes secrets)", value=False)

# ---------- Prepare Demo File ----------
demo_file_path = "test_secrets.txt"
if use_demo_file:
    try:
        with open(demo_file_path, "x") as f:
            f.write("""\
# Dummy secrets for testing
AWS_KEY=AKIA1234567890ABCD
AWS_SECRET="aws1234567890abcdefghijklmnopqrstuvwx"
password='MyP@ssw0rd!'
PRIVATE_KEY=-----BEGIN PRIVATE KEY-----
TOKEN=abcd1234efgh5678ijkl9012mnop3456qrst
""")
    except FileExistsError:
        pass  # File exists

# ---------- Scan Button ----------
if st.button("Start Scan"):
    if not uploaded_files and not use_demo_file:
        st.error("Please upload files or select the demo file.")
    else:
        st.info("Scanning files, please wait...")

        findings = []
        
        # 1. Scan Uploaded Files
        if uploaded_files:
            for uploaded_file in uploaded_files:
                try:
                    raw = uploaded_file.read()
                    content = raw.decode('utf-8', errors='ignore')
                    source = uploaded_file.name
                    findings.extend(scan_content(content, source=source))
                    # Reset pointer for potential re-reads
                    uploaded_file.seek(0)
                except Exception as e:
                    st.error(f"Error reading {uploaded_file.name}: {e}")

        # 2. Scan Demo File if selected
        if use_demo_file:
            try:
                with open(demo_file_path, 'r', errors='ignore') as f:
                    content = f.read()
                findings.extend(scan_content(content, source="demo_test_secrets.txt"))
            except Exception as e:
                st.error(f"Error reading demo file: {e}")

        # ---------- Summary ----------
        total, type_counts, files, severity_counts = summarize_findings(findings)

        # ---------- Metrics / KPIs ----------
        st.subheader("Scan Summary")
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Secrets Found", total)
        col2.metric("Files Scanned", len(files))
        col3.metric("Critical Secrets", severity_counts.get("Critical", 0))

        # ---------- Secrets by Type ----------
        st.subheader("Secrets by Type")
        type_table = {k: v for k, v in type_counts.items()}
        st.table(type_table)

        # ---------- Full Details Table (masked by default) ----------
        st.subheader("Full Scan Results")
        if total > 0:
            results_data = []
            for item in findings:
                results_data.append({
                    "Type": item['type'],
                    # mask value unless user explicitly wants full values
                    "Value": mask_value(item.get('value', ''), show_full=show_full),
                    "Severity": item["severity"],
                    "File": item["file"]
                })
            st.table(results_data)
        else:
            st.success("No secrets found!")

        # ---------- Save & Download Results ----------
        output_file = "scan_results.json"
        with open(output_file, "w") as f:
            json.dump(findings, f, indent=4)
        st.success(f"Results saved to {output_file}")
        st.download_button(
            label="Download JSON",
            data=json.dumps(findings, indent=4),
            file_name="scan_results.json",
            mime="application/json"
        )
