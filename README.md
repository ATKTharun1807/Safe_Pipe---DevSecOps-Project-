---

# **SafePipe**

A powerful and developer-friendly **secret leak detection tool** designed to help teams identify exposed API keys, tokens, credentials, and sensitive data across repositories. SafePipe ensures secure software development through automated scanning and a professional dashboard.

---

# **Table of Contents**

* [Features](#features)
* [Project Structure](#project-structure)
* [Setup Instructions](#setup-instructions)
* [Usage](#usage)
* [Contributing](#contributing)
* [License](#license)

---

# **Features**

* 🔍 **Recursive Folder Scanning**: Scan entire projects or specific subdirectories for secrets.
* � **File Upload Support**: Upload specific files directly to the dashboard for instant analysis.
* � **Local Path Scanning**: Enter any local or network path to scan for sensitive data.
* ⚡ **High-accuracy Detection**: Uses advanced regex patterns to find AWS keys, private keys, passwords, and tokens.
* 🖥️ **Professional Streamlit Dashboard**: User-friendly interface with real-time metrics and results.
* 📊 **Exportable Reports**: Download scan results in JSON format for further analysis.
* 🔒 **Masked Results**: Sensitive findings are masked by default to prevent shoulder surfing.

---

# **Project Structure**

```
safepipe/
│
├── app.py                      # Main Streamlit Dashboard Application
├── safe_pipe_core.py           # Core scanning logic and patterns
├── run_safe_pipe.py            # CLI interface for folder scanning
├── test_secrets.txt            # Demo file with mock secrets
├── requirements.txt            # Python dependencies
└── reports/                    # Folder for generated scan reports
```

---

# **Setup Instructions**

### **1. Clone the repository**

```bash
git clone <your-repo-url>
cd Safe_Pipe---DevSecOps-Project-
```

### **2. Create & activate virtual environment**

```bash
python -m venv venv
# Windows
venv\Scripts\activate
# macOS/Linux
source venv/bin/activate
```

### **3. Install dependencies**

```bash
pip install -r requirements.txt
```

---

# **Usage**

### **Running the Dashboard**

Launch the interactive dashboard using Streamlit:

```bash
streamlit run app.py
```

### **Running the CLI Scanner**

Scan a folder directly from the command line:

```bash
python run_safe_pipe.py --folder ./my_project --output results.json
```

---

# **Scanning Features**

1. **Upload Files**: Drag and drop any file into the sidebar to scan it instantly.
2. **Local Path**: Provide a full path (e.g., `C:/Projects/MySecrets`) to recursively scan all files in that directory.
3. **Demo Mode**: Enable the "Use demo test file" checkbox to see the scanner in action with sample data.

---

# **Contributing**

Pull requests are welcome! For major changes, please open an issue to discuss them first.

---

# **License**

[MIT](LICENSE)
