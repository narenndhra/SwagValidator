# SwagValidator – Automated API Validation for Burp Suite

SwagValidator is a **Burp Suite Jython extension** that automates testing of APIs from **OpenAPI/Swagger specs**, **Postman collections**, or **plain endpoint lists**.

It eliminates repetitive manual work by **discovering endpoints, populating parameters with intelligent defaults, executing requests, and generating results tables** — all directly inside Burp Suite.

---

## 🚀 Why This Tool Exists

API testing in Burp Suite is often manual — importing requests, adding missing parameters, and setting up authentication takes time.

SwagValidator automates that process:
- Reads API definitions from multiple formats.
- Auto-generates and executes requests with realistic parameter values.
- Summarizes the results in a clean dashboard table with actionable notes.

This means **faster coverage, fewer missed endpoints, and less time spent on setup**.

---

## ✨ Key Highlights

- **Multiple Input Formats**  
  - OpenAPI/Swagger JSON or Swagger UI HTML.  
  - Postman collection (v2.1).  
  - TXT, CSV, or TSV lists of endpoints.

- **Smart Parameter Filling**  
  - Uses `example`, `default`, or `enum` values when available.  
  - Falls back to name/format-based heuristics (e.g., `"email"` → `jsmith@example.com`).

- **Integrated Testing**  
  - Automatically sends all generated requests.  
  - Shows status codes, content lengths, and request/response views.  
  - Filters for **non-2xx** responses.

- **No External Dependencies**  
  Runs inside Burp Suite using Jython — no pip installs.

- **Postman Export**  
  - Available from Dashboard only.  
  - Exports tested endpoints to a ready-to-import Postman JSON.

- **Concise Reporting**  
  - Dashboard table of results.  
  - Summary tab with metrics, error counts, and missing parameter reports.

---

## ⚙️ How It Works

1. **Load Source**  
   - Paste a Swagger URL, load a Postman file, or import a list of endpoints.

2. **Parse & Generate Requests**  
   - For Swagger: discovers all paths and methods.  
   - For Postman: resolves placeholders.  
   - For lists: builds requests with defaults.

3. **Populate Parameters**  
   - From examples/defaults/enums in the spec.  
   - Or using intelligent fallbacks based on parameter names or data formats.

4. **Execute Requests**  
   - Runs each endpoint against the target server.  
   - Records response status, size, and body.

5. **View Results**  
   - Dashboard: sortable/filterable table.  
   - Summary: overall counts and key observations.

---

## 💡 Advantages of This Automation

- **Saves Time** – No manual request-by-request setup.  
- **Increases Coverage** – Hits every documented endpoint quickly.  
- **Finds Issues Early** – Detects missing examples, incorrect params, and failing endpoints.  
- **Works Within Burp** – No context switching to Postman for initial discovery.

---

## 📥 Installation

1. **Install Jython**  
   - Download `jython-standalone-2.7.x.jar`.
   - In Burp → `Extender → Options → Python Environment` → Select the JAR.

2. **Load Extension**  
   - Save `SwagValidator.py` somewhere on disk.
   - In Burp → `Extender → Extensions → Add`:
     - Extension type: **Python**
     - Extension file: `SwagValidator.py`

3. **Verify**  
   - A **SwagValidator** tab appears with **Settings / Dashboard / Summary**.

---

## 📊 Usage Scenarios

- **Challenge 1 – Swagger Validation**  
  Paste spec URL → Start Validate → Review 2xx/Non-2xx in Dashboard.

- **Challenge 2 – Postman Collections**  
  Import → Auto-replace placeholders → Validate.

- **Challenge 3 – List Imports**  
  Load CSV/TXT → Validate → Health map in table.

---

## 🛠 Requirements

- Burp Suite (Community or Pro)
- Jython 2.7.x
- Internet or network access to target API

_No pip packages required._

---

## 🙌 Credits

Developed with inspiration from existing API testing workflows in Burp Suite and tailored to improve **speed**, **coverage**, and **usability** for security testers and QA teams.

---

## 📜 License

MIT License – free for personal and commercial use.
