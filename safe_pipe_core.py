import os
import re
from collections import Counter
import json

# ---------- Secret Patterns ----------
SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws(?:.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]?",
    "Private Key": r"-----BEGIN [A-Z ]+ PRIVATE KEY-----",
    "Password": r"(?i)(?:password|passwd|pwd)(?:\s*[:=]\s*|\s+is\s+)[#]?[a-zA-Z0-9$!@#%^&*()_\-+=]{5,30}",
    "Generic Token": r"(?i)(?:token|api_key|apikey|secret)(?:\s*[:=]\s*|\s+is\s+)['\"]?[0-9a-zA-Z]{16,64}['\"]?",
    "GitHub Token": r"ghp_[a-zA-Z0-9]{36}"
}



# ---------- Severity Mapping ----------
SEVERITY_MAP = {
    "Private Key": "Critical",
    "AWS Access Key": "Medium",
    "AWS Secret Key": "Medium",
    "GitHub Token": "Medium",
    "Password": "Low",
    "Generic Token": "Low"
}

# ---------- Scan Function ----------
def scan_file(file_path):
    findings = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            for secret_name, pattern in SECRET_PATTERNS.items():
                for m in re.finditer(pattern, content):
                    value = m.group(0)
                    severity = SEVERITY_MAP.get(secret_name, "Low")
                    findings.append({
                        "type": secret_name,
                        "value": str(value),
                        "file": file_path,
                        "severity": severity
                    })
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
    return findings

# ---------- Summarize Function ----------
def summarize_findings(findings):
    total = len(findings)
    types = [item["type"] for item in findings]
    type_counts = Counter(types)
    files = set([item["file"] for item in findings])
    severity_counts = Counter([item["severity"] for item in findings])
    return total, type_counts, files, severity_counts

# ---------- Run Scanner on Folder ----------
def scan_folder(folder_path, output_file="scan_results.json"):
    all_findings = []
    if not os.path.exists(folder_path):
        raise FileNotFoundError(f"Folder not found: {folder_path}")

    if os.path.isfile(folder_path):
        all_findings = scan_file(folder_path)
    else:
        for root, dirs, files in os.walk(folder_path):
            # Only skip .git and heavy dependency folders, but keep .github, etc.
            dirs[:] = [d for d in dirs if d not in ('.git', 'node_modules', '__pycache__', 'venv', 'env', 'dist', 'build')]
            for file_name in files:
                if file_name.lower().endswith(('.exe', '.dll', '.so', '.png', '.jpg', '.jpeg', '.gif', '.mp4', '.zip', '.tar', '.gz', '.pdf')):
                    continue
                file_path = os.path.join(root, file_name)
                findings = scan_file(file_path)
                all_findings.extend(findings)

    # Save to JSON
    if output_file:
        with open(output_file, "w") as f:
            json.dump(all_findings, f, indent=4)
        print(f"Scan complete! {len(all_findings)} secrets found. Results saved to {output_file}")
    
    return all_findings