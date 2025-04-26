Perfect — here’s an updated `README.md` section that includes the **ZAP report integration** and explains the **two main tabs** in your Burp extension:

---

## 🧩 Burp-ZAP Integration Extension

### Overview

This Burp Suite extension lets you **launch, control, and interact with OWASP ZAP** directly from Burp. It includes both **scanning** and **reporting** features, giving you a streamlined workflow between ZAP’s automation power and Burp’s interception tools.

---

### 📁 Repository Structure

Your extension consists of **two main modules (tabs)**:

| File | Function |
|------|----------|
| `Burp_Zap_Scan_Advanced.py` | Handles **ZAP launch, shutdown, scan configuration**, and automation logic |
| `Burp_Zap_Report_Tab.py` | Provides a **dedicated Reporting UI tab** to display and manage **ZAP scan results** |

---

### 🛠 Features by Tab

#### 1. 🔍 **Scan Tab (ZAP Control & Launch)**
- Launch ZAP with selected port, API key, and JAR
- Force shutdown of ZAP (even if port is unknown)
- Dynamic ZAP process detection and logging
- Background threading for smooth operation inside Burp
- Error and feedback logs visible directly in Burp’s UI

#### 2. 📄 **Report Tab (ZAP Reporting Integration)**
- Connects to the ZAP API to **pull scan results**
- Parses and displays:
  - Alert summaries
  - URLs affected
  - Risk level classifications (High/Medium/Low/Info)
- Enables Burp users to **view, sort, or export** ZAP findings
- Simple and readable presentation using Swing-based tables/panels

---

### ✅ Key Highlights

- 🧪 Full ZAP lifecycle management (launch + kill)
- 🛡️ ZAP reporting integrated into Burp as a **second tab**
- ⚙️ Supports custom ZAP JAR paths, ports, and API keys
- 🔌 Thread-safe, compatible with Jython (for Burp Extender)
- 💬 Helpful logging for troubleshooting and transparency

---

### 🧪 Example Workflow

1. Start Burp and load the extension via **Extender > Extensions**
2. Go to the **ZAP Scan** tab:
   - Select your ZAP jar path, port, and optional API key
   - Click **Launch ZAP**
3. After scanning completes in ZAP:
   - Switch to the **ZAP Report** tab
   - View results and alerts directly inside Burp

---

### 🧰 Requirements

- Burp Suite (Community or Pro)
- OWASP ZAP `.jar` file installed
- Java available on system path
- Python Jython environment (for Burp extensions)

---

