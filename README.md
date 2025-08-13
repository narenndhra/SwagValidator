# SwagValidator (Burp Suite Extension)

_Automated OpenAPI/Postman/list-driven API validation for Burp Suite — with one-click imports, heuristic param filling, and a clean, tabbed UI._

> This README mirrors the final “minimal & stable” build we discussed: no BrokenAuth Analyzer action, no charts, and Postman export available **only** from the Dashboard.

---

## ✨ What it does

- **Challenge 1 – OpenAPI/Swagger**
  - Parse Swagger/OpenAPI (JSON or Swagger UI HTML).
  - Auto-discover real spec from `configUrl` / `urls[]` or common endpoints.
  - Generate requests for all paths & allowed methods.
  - Populate parameters from `example`, `default`, `enum`; fall back to **name/format heuristics**.
  - Detect **missing examples** and **optional params**; run the whole set and summarize statuses.

- **Challenge 2 – Postman Collection**
  - Import a Postman collection (v2.1).
  - Heuristically replace `{{vars}}`, `<placeholders>`, `${env}`, `__TOKENS__`, etc.
  - Send requests with updated values and report:
    - **Leftover placeholders**, **non‑200 endpoints**, and **likely missing required params**.

- **Challenge 3 – Plain lists (TXT / CSV / TSV)**
  - Import endpoints from TXT (one per line) or CSV/TSV (columns like `method,url,headers,content_type,body`).
  - Build and run a quick **API health map** (2xx vs errors/timeouts).

---

## 🧩 Key features

- **Heuristic value filling** for common fields (email/uuid/phone/ids/username/password/etc.).
- **Auto-priming** (optional) for classic demo paths (`/user/{username}`, `/pet/{id}`).
- **Manual headers** field for quick add‑ons (e.g., `Accept-Language: en-US; X-Trace: 1`).  
- **Export Postman…** from the **Dashboard** (2xx-first, or fallback to all synthesized requests).
- **Context menu helpers** (Proxy/Repeater): _Send to Repeater / Intruder / Comparer_.
- **No charts** — Summary is **table-style metrics + notes + status histogram**.
- **Zero pip deps** — runs in **Jython 2.7** inside Burp.

> Built for fast triage: import → run → scan table and summary notes → export if needed.

---

## 📦 Files in this repo

```
SwagValidator.py         # The Burp Jython extension (single file)
README.md                # This file
requirements.txt         # Empty (documentary) — Burp+Jython only
```

> The extension ships as a single `SwagValidator.py` file so you can drop it straight into Burp.

---

## 🔧 Requirements

- **Burp Suite** (Community or Pro)
- **Jython 2.7.x** (Burp → Extender → Options → Python Environment → choose `jython-standalone-2.7.x.jar`)

> No pip packages needed — Java/Swing & Burp APIs are used directly.

---

## 🚀 Installation

1. Save `SwagValidator.py` somewhere on disk.
2. In **Burp**: `Extender → Extensions → Add`  
   - **Extension type**: `Python`  
   - **Extension file**: select `SwagValidator.py`  
3. You’ll get a new top-level tab: **SwagValidator** (with **Summary / Dashboard / Settings**).

---

## 🖥️ UI & Workflow

### Tabs

- **Settings**
  - _Spec URL / file_: OpenAPI JSON or Swagger UI HTML; can also discover via common paths.
  - _Authentication_: API Key header/value, Bearer token.
  - _Method control_: toggle allowed methods; “Test all enum values” expands query params.
  - _Client options_: User-Agent, Timeout (sec).
  - _Auto-prime resources_: create demo `user/pet` then retry `GET` after a 404 (optional).
  - _Exclude paths_: comma‑separated substrings (e.g., `/login, /auth/token`).
  - _Exclude login endpoints_: quick toggle on top of `Exclude paths`.
  - _Manual headers_: `Key: Value; Key2: Value2` (semicolon/comma separated).
  - **Save Settings** / **Clear Auth**.

- **Dashboard**
  - **Start Validate / Stop / Clear Results**
  - **Show non‑2xx** filter
  - **Import Postman…** (Challenge 2)
  - **Import List/CSV/TSV…** (Challenge 3)
  - **Export Postman…** (2xx rows; fallback to synthesized calls if no rows yet)
  - **Table**: `S.No | Method | URL | Status | Content Length`
  - **Request / Response** viewers + **Resend** button
  - **Right‑click**: Send to Repeater / Intruder / Comparer; Copy URLs
  - **Shortcut**: `Ctrl+Shift+A` → Active Scan selected (2xx only)

- **Summary**
  - **Metrics table**: Base URL, Documented/Imported, Eligible, Tested, 2xx OK
  - **Notes**: missing examples, optional params, leftover placeholders, non‑200/Errors
  - **Status Code histogram**: table of `code → count`

### Typical flows

- **Challenge 1**: Paste Spec URL → _Start Validate_ → read Summary notes & table.
- **Challenge 2**: _Import Postman…_ → auto‑replace placeholders → _Start Validate_.
- **Challenge 3**: _Import List/CSV/TSV…_ → _Start Validate_ → review health map.

---

## 📤 Exporting a Postman collection (Dashboard)

- Click **Export Postman…**.  
- If there are 2xx rows in the Dashboard, those are exported. Otherwise the tool exports **all synthesized requests** based on the current run/session (helpful for bootstrapping a collection).

> The Summary tab intentionally has **no export button**.

---

## ⚙️ Heuristics & placeholder policy

When examples/defaults/enum are missing, the tool fills values using:
- **By name**: `email`, `password`, `firstname`, `lastname`, `phone`, `id`, `status`, `tags`, `limit/page/size`, etc.
- **By format**: `email`, `uuid/guid`, `date-time`, `uri/url`, `hostname`, `ipv4/ipv6`.
- **Numeric ranges**: midpoint within `minimum/maximum` where available.

For Postman & List imports, placeholders like `{{EMAIL}}`, `<userId>`, `${token}`, or `__SOMETHING__` are replaced with reasonable test values. Remaining matches are reported as **leftover placeholders**.

---

## 🧪 Notes on priming (optional)

If enabled, a first 404 on `GET /user/{username}` or `GET /pet/{id}` triggers a best‑effort POST to create a sample record and **one retry** of the original GET. This helps demo/specs that expect an existing entity.

---

## 🛠️ Troubleshooting

- **AttributeError for `txtManualHeaders`**  
  You’re running an older file. This build includes the Manual Headers field used by settings/load/runtime.

- **Spec not found**  
  Paste the actual OpenAPI JSON or full Swagger UI HTML. Auto‑discovery attempts: `configUrl`, `urls[]`, plus common endpoints like `/openapi.json`, `/swagger/swagger.json`, etc.

- **Network timeouts**  
  Increase _Timeout (sec)_ in Settings. Check proxy, VPN, and host reachability.

- **Export Postman shows empty**  
  Run once or import a source first; the exporter needs rows or synthesized calls.

---

## 📜 License

MIT (see LICENSE file, if present).

---

## 🙌 Credits & prior art

This project’s README structure and documentation style were inspired by a separate extension’s documentation (BrokenAuth Analyzer).