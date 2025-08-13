# -*- coding: utf-8 -*-
# SwagValidator (Burp Suite, Jython 2.7) — Final minimal, stable build
# - Covers Challenge 1 / 2 / 3
# - NO BrokenAuth Analyzer option
# - NO Proxy/History special handling
# - NO placeholder settings (placeholders auto-replaced heuristically)
# - NO charts; Summary is simple tables + notes
# - Postman Export: in Dashboard (required), not in Summary
#
# Challenge 1:
#   - Parse Swagger/OpenAPI; identify endpoints & required params
#   - Auto-populate from examples; fallback to name/format heuristics
#   - Run requests; report:
#       * Parameters missing example values
#       * Endpoints with optional parameters
#       * Validate/summary of 200 statuses
#
# Challenge 2:
#   - Import Postman collection; identify endpoints & parameters
#   - Replace dummy/placeholder values via heuristics ({{email}}, {{userId}}, etc.)
#   - Run; report:
#       * Placeholders still present
#       * Non-200 statuses
#       * (Best-effort) missing required params (heuristic)
#
# Challenge 3:
#   - Import document list (TXT) or CSV/TSV (no XLSX to avoid deps)
#   - Assemble requests; run to check "health map"
#   - Report:
#       * Missing/invalid entries
#       * Non-200 statuses / exceptions / timeouts

from burp import IBurpExtender, ITab, IContextMenuFactory
from javax.swing import (JPanel, JTabbedPane, JTable, JScrollPane, JButton, JLabel, JTextField,
                         JCheckBox, JFileChooser, JOptionPane, JTextArea, SwingUtilities,
                         JSplitPane, JPopupMenu, JMenuItem, AbstractAction, KeyStroke, JComponent,
                         ListSelectionModel)
from javax.swing.table import AbstractTableModel, TableRowSorter, DefaultTableModel
from javax.swing.border import EmptyBorder
from javax.swing.filechooser import FileNameExtensionFilter
from javax.swing.event import ListSelectionListener
from java.awt import (BorderLayout, GridBagLayout, GridBagConstraints, Insets, FlowLayout,
                      Font, GridLayout, Dimension, Toolkit)
from java.awt.event import MouseAdapter, KeyEvent
from java.awt.datatransfer import StringSelection
from java.net import URL
from java.lang import String
from java.io import File

import json
import re
import threading
import time
import os

SAFE_METHODS = set(["GET","HEAD","OPTIONS"])
ALL_METHODS  = set(["GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"])
FALLBACK = {"string":"string","integer":1,"number":1,"boolean":True}

try:
    basestring
except NameError:
    basestring = str

# ---------- Heuristics for missing values & placeholder replacement ----------

def _name_based_value(name):
    ln = (name or "").lower()
    if ln in ("username","user","user_name","login","userid","user_id"): return "jsmith"
    if ln in ("password","pass","passwd","pwd"):                         return "demo1234"
    if ln in ("email","mail"):                                           return "jsmith@example.com"
    if ln == "id" or ln.endswith("id"):                                  return 1
    if ln in ("phone","mobile","tel","telephone"):                       return "1234567890"
    if ln in ("firstname","first_name","given_name"):                    return "John"
    if ln in ("lastname","last_name","family_name"):                     return "Doe"
    if ln in ("status",):                                                return "available"
    if ln in ("tags",):                                                  return "tag"
    if ln in ("limit","page","size","offset"):                           return 1
    if ln in ("subject",):                                               return "Test subject"
    if ln in ("message","comment","description","body"):                 return "Test message"
    if ln in ("name","full_name","display_name"):                        return "J Smith"
    return None

def _coerce_by_format(fmt):
    f = (fmt or "").lower()
    if f == "email": return "test@example.com"
    if f in ("uuid","guid"): return "00000000-0000-0000-0000-000000000000"
    if f in ("date","date-time","datetime","rfc3339"): return "2020-01-01T00:00:00Z"
    if f in ("uri","url"): return "https://example.com"
    if f == "hostname": return "example.com"
    if f == "ipv4": return "192.0.2.1"
    if f == "ipv6": return "2001:db8::1"
    return None

def _number_in_range(minv, maxv, typ="number"):
    try:
        if minv is None and maxv is None:
            return 1 if typ == "integer" else 1.0
        if minv is None:
            return (maxv - 1) if typ == "integer" else (maxv - 0.1)
        if maxv is None:
            return (minv + 1) if typ == "integer" else (minv + 0.1)
        if typ == "integer":
            return int(minv) if int(minv) == int(maxv) else int((minv + maxv) / 2)
        return float((minv + maxv) / 2.0)
    except Exception:
        return 1 if typ == "integer" else 1.0

def _string_meeting(schema, fallback="string"):
    enum = schema.get("enum")
    if enum and len(enum) > 0:
        return str(enum[0])
    fmt = _coerce_by_format(schema.get("format"))
    if fmt is not None:
        return fmt
    min_len = schema.get("minLength", 0) or 0
    base = (fallback if isinstance(fallback, basestring) else "string")
    s = base
    if len(s) < min_len:
        s = (s + ("_" * (min_len - len(s))))[:max(min_len, len(s))]
    return s

# =================== Core Impl ===================

class _SwagValidatorImpl(ITab, IContextMenuFactory):
    def __init__(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("SwagValidator")

        self.calls = []
        self.summary = SummaryModel()
        self.worker = None
        self._stop_requested = False
        self._creators = {}

        self._state = {
            "bearer": None,
            "cookie": {},
            "ids": {},
            "base_segments_skip": set(["api","v1","v2","v3","v4"])
        }

        # placeholder detection (Challenge 2) — heuristic only
        self._PLACEHOLDER_PAT = re.compile(r"\{\{([^}]+)\}\}|<<([^>]+)>>|<([^>]+)>|\$\{([^}]+)\}|__([^_]+)__")

        self._build_ui()
        self._load_settings()
        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)  # global (Proxy/Repeater) context menu

    # ----- ITab -----
    def getTabCaption(self):
        return "SwagValidator"

    def getUiComponent(self):
        return self.root

    def _ui(self, fn):
        SwingUtilities.invokeLater(fn)

    # ----- UI -----
    def _build_ui(self):
        self.tabs = JTabbedPane()

        self.settingsPanel  = SettingsPanel(self)
        self.dashboardPanel = DashboardPanel(self)
        self.summaryPanel   = SummaryPanel(self)

        self.tabs.add("Summary",   self.summaryPanel.panel)
        self.tabs.add("Dashboard", self.dashboardPanel.panel)
        self.tabs.add("Settings",  self.settingsPanel.panel)

        self.root = JPanel(BorderLayout())
        self.root.add(self.tabs, BorderLayout.CENTER)

        # Wire buttons
        self.dashboardPanel.btnStart.actionPerformed   = self._on_start
        self.dashboardPanel.btnStop.actionPerformed    = self._on_stop
        self.dashboardPanel.btnClear.actionPerformed   = self._on_clear_results
        self.dashboardPanel.chkShowAll.addActionListener(self._on_toggle_show_all)
        self.dashboardPanel.btnResend.actionPerformed  = self._on_resend
        self.dashboardPanel.chkRawReq.addActionListener(self._on_toggle_raw_req)
        self.dashboardPanel.chkRawResp.addActionListener(self._on_toggle_raw_resp)
        self.dashboardPanel.btnImportPM.actionPerformed   = self._on_import_postman
        self.dashboardPanel.btnImportList.actionPerformed = self._on_import_list
        self.dashboardPanel.btnExportPM.actionPerformed   = self._on_save_postman  # Export Postman (Dashboard only)

        self.settingsPanel.btnSave.actionPerformed     = self._on_save_settings
        self.settingsPanel.btnClearAuth.actionPerformed= self._on_clear_auth

        # Table selection -> details
        self.dashboardPanel.table.getSelectionModel().addListSelectionListener(RowSelectListener(self))
        sorter = TableRowSorter(self.dashboardPanel.model)
        self.dashboardPanel.table.setRowSorter(sorter)

        # Right-click menu on our table
        self._install_table_popup()

    # ----- Global context menu: basic helpers only -----
    def createMenuItems(self, invocation):
        try:
            msgs = invocation.getSelectedMessages() or []
            if not msgs:
                return None
            menu = []
            miRpt = JMenuItem("Send to Repeater")
            miInt = JMenuItem("Send to Intruder")
            miCmp = JMenuItem("Send to Comparer (requests)")

            def _send_to_repeater(evt=None):
                for m in msgs:
                    try:
                        svc = m.getHttpService()
                        self.callbacks.sendToRepeater(svc.getHost(), svc.getPort(), svc.getProtocol()=="https",
                                                      m.getRequest(), "SV:Context")
                    except Exception:
                        pass

            def _send_to_intruder(evt=None):
                for m in msgs:
                    try:
                        svc = m.getHttpService()
                        self.callbacks.sendToIntruder(svc.getHost(), svc.getPort(), svc.getProtocol()=="https",
                                                      m.getRequest(), None)
                    except Exception:
                        pass

            def _send_to_comparer(evt=None):
                for m in msgs:
                    try:
                        self.callbacks.sendToComparer(m.getRequest())
                    except Exception:
                        pass

            miRpt.actionPerformed = _send_to_repeater
            miInt.actionPerformed = _send_to_intruder
            miCmp.actionPerformed = _send_to_comparer

            menu.extend([miRpt, miInt, miCmp])
            return menu
        except Exception:
            return None

    # ----- Popup + bulk ops in our dashboard -----
    def _install_table_popup(self):
        table = self.dashboardPanel.table
        table.setRowSelectionAllowed(True)
        table.setColumnSelectionAllowed(False)
        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)

        menu = JPopupMenu()
        miSendRpt = JMenuItem("Send to Repeater")
        miSendInt = JMenuItem("Send to Intruder")
        miScan    = JMenuItem("Active Scan (selected)")
        miCmpReq  = JMenuItem("Send Request(s) to Comparer")
        miCopyURL = JMenuItem("Copy URL(s)")
        menu.add(miSendRpt); menu.add(miSendInt); menu.add(miScan); menu.add(miCmpReq); menu.add(miCopyURL)

        def _selected_endpoints(only2xx=True):
            rows = table.getSelectedRows()
            if not rows:
                Toolkit.getDefaultToolkit().beep()
                return []
            out = []
            for r in rows:
                midx = table.convertRowIndexToModel(r)
                ep = self.dashboardPanel.model.get(midx)
                if (not only2xx) or (200 <= (ep.status or 0) < 300):
                    out.append(ep)
            if not out:
                Toolkit.getDefaultToolkit().beep()
            return out

        def _send_one_to_repeater(ep):
            u = URL(ep.url)
            https = (u.getProtocol().lower() == "https")
            port = (u.getPort() if u.getPort() != -1 else (443 if https else 80))
            req_text = ep.reqRaw or ep.reqText
            if not req_text or not req_text.strip(): return
            req_bytes = self.helpers.stringToBytes(req_text)
            self.callbacks.sendToRepeater(u.getHost(), port, https, req_bytes, "SwagVal %s %s" % (ep.method, u.getPath()))

        def _send_one_to_intruder(ep):
            u = URL(ep.url); https = (u.getProtocol().lower() == "https")
            port = (u.getPort() if u.getPort() != -1 else (443 if https else 80))
            req_text = ep.reqRaw or ep.reqText
            if not req_text or not req_text.strip(): return
            self.callbacks.sendToIntruder(u.getHost(), port, https, self.helpers.stringToBytes(req_text), None)

        def _active_scan_one(ep):
            u = URL(ep.url); https = (u.getProtocol().lower() == "https")
            port = (u.getPort() if u.getPort() != -1 else (443 if https else 80))
            req_text = ep.reqRaw or ep.reqText
            if not req_text or not req_text.strip(): return
            self.callbacks.doActiveScan(u.getHost(), port, https, self.helpers.stringToBytes(req_text))

        def _cmp_request_one(ep):
            req_text = ep.reqRaw or ep.reqText or ""
            if not req_text.strip(): return
            self.callbacks.sendToComparer(self.helpers.stringToBytes(req_text))

        def _bulk(worker_fn, only2xx=True):
            eps = _selected_endpoints(only2xx=only2xx)
            if not eps: return
            def worker():
                for ep in eps:
                    try: worker_fn(ep)
                    except Exception: pass
            t = threading.Thread(target=worker); t.setDaemon(True); t.start()

        miSendRpt.actionPerformed = lambda evt: _bulk(_send_one_to_repeater, only2xx=False)
        miSendInt.actionPerformed = lambda evt: _bulk(_send_one_to_intruder, only2xx=False)
        miScan.actionPerformed    = lambda evt: _bulk(_active_scan_one,    only2xx=True)
        miCmpReq.actionPerformed  = lambda evt: _bulk(_cmp_request_one,    only2xx=False)
        miCopyURL.actionPerformed = lambda evt: (
            lambda eps: Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
                StringSelection("\n".join([ep.url for ep in eps])), None)
        )(_selected_endpoints(only2xx=False))

        class PopupListener(MouseAdapter):
            def __init__(self, table, menu): self._table=table; self._menu=menu
            def mousePressed(self, e):  self._maybe(e)
            def mouseReleased(self, e): self._maybe(e)
            def _maybe(self, e):
                if e.isPopupTrigger():
                    row = self._table.rowAtPoint(e.getPoint())
                    if row >= 0 and not self._table.isRowSelected(row):
                        self._table.setRowSelectionInterval(row, row)
                    self._menu.show(e.getComponent(), e.getX(), e.getY())

        table.addMouseListener(PopupListener(table, menu))

        # Shortcut: Ctrl+Shift+A => Active Scan all selected
        im = table.getInputMap(JComponent.WHEN_FOCUSED)
        am = table.getActionMap()
        class _ScanAllAction(AbstractAction):
            def actionPerformed(self, evt):
                rc = table.getRowCount()
                if rc > 0:
                    table.setRowSelectionInterval(0, rc-1)
                    miScan.actionPerformed(None)
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_A, KeyEvent.CTRL_DOWN_MASK | KeyEvent.SHIFT_DOWN_MASK), "scan_all")
        am.put("scan_all", _ScanAllAction())

    # ----- Settings persistence -----
    def _save_settings(self, show_toast=False):
        cb = self.callbacks
        cb.saveExtensionSetting("spec", self.settingsPanel.txtSpec.getText())
        cb.saveExtensionSetting("api_header", self.settingsPanel.txtApiHeader.getText())
        cb.saveExtensionSetting("api_value", self.settingsPanel.txtApiValue.getText())
        cb.saveExtensionSetting("bearer", self.settingsPanel.txtBearer.getText())
        cb.saveExtensionSetting("ua", self.settingsPanel.txtUA.getText())
        cb.saveExtensionSetting("timeout", self.settingsPanel.txtTimeout.getText())
        cb.saveExtensionSetting("manual_headers", self.settingsPanel.txtManualHeaders.getText())
        cb.saveExtensionSetting("exclude_paths", self.settingsPanel.txtExcludePaths.getText())
        cb.saveExtensionSetting("exclude_login", "1" if self.settingsPanel.chkExcludeLogin.isSelected() else "0")
        cb.saveExtensionSetting("enum_all", "1" if self.settingsPanel.chkEnumAll.isSelected() else "0")
        cb.saveExtensionSetting("prime", "1" if self.settingsPanel.chkPrime.isSelected() else "0")
        for m, v in self.settingsPanel.methodFlags().items():
            cb.saveExtensionSetting("method_"+m, "1" if v else "0")
        if show_toast:
            JOptionPane.showMessageDialog(self.root, "Settings saved.", "Saved", JOptionPane.INFORMATION_MESSAGE)

    def _load_settings(self):
        cb = self.callbacks
        def g(key, default=""):
            v = cb.loadExtensionSetting(key)
            return v if v is not None else default
        self.settingsPanel.txtSpec.setText(g("spec", self.settingsPanel.txtSpec.getText()))
        self.settingsPanel.txtApiHeader.setText(g("api_header", self.settingsPanel.txtApiHeader.getText()))
        self.settingsPanel.txtApiValue.setText(g("api_value", ""))
        self.settingsPanel.txtBearer.setText(g("bearer", ""))
        self.settingsPanel.txtUA.setText(g("ua", self.settingsPanel.txtUA.getText()))
        self.settingsPanel.txtTimeout.setText(g("timeout", self.settingsPanel.txtTimeout.getText()))
        self.settingsPanel.txtManualHeaders.setText(g("manual_headers", self.settingsPanel.txtManualHeaders.getText()))
        self.settingsPanel.txtExcludePaths.setText(g("exclude_paths", ""))
        self.settingsPanel.chkExcludeLogin.setSelected(g("exclude_login", "0") == "1")
        self.settingsPanel.chkEnumAll.setSelected(g("enum_all","1") == "1")
        self.settingsPanel.chkPrime.setSelected(g("prime","1") == "1")
        for m, cbx in self.settingsPanel.chk.items():
            raw = cb.loadExtensionSetting("method_"+m)
            cbx.setSelected(True if raw is None else (raw == "1"))

        saved_bearer = self.settingsPanel.txtBearer.getText().strip()
        if saved_bearer:
            self._state["bearer"] = saved_bearer
        mh = (self.settingsPanel.txtManualHeaders.getText() or "")
        for pair in re.split(r"\s*[;,]\s*", mh):
            if not pair or pair.startswith("#"): continue
            idx = pair.find(":")
            if idx > 0:
                k = pair[:idx].strip().lower(); v = pair[idx+1:].strip()
                if k == "cookie":
                    for ck in v.split(";"):
                        ck = ck.strip()
                        if "=" in ck:
                            nm, val = ck.split("=",1)
                            self._state["cookie"][nm.strip()] = val.strip()

    # ----- Buttons -----
    def _on_clear_auth(self, evt=None):
        self.settingsPanel.txtApiHeader.setText("X-API-Key")
        self.settingsPanel.txtApiValue.setText("")
        self.settingsPanel.txtBearer.setText("")
        self.settingsPanel.txtManualHeaders.setText("")
        self._state["bearer"] = None
        self._state["cookie"].clear()
        JOptionPane.showMessageDialog(self.root, "Auth headers cleared.", "Cleared", JOptionPane.INFORMATION_MESSAGE)

    def _on_clear_results(self, evt=None):
        self.dashboardPanel.model.clear()
        self.dashboardPanel.reqArea.setText("")
        self.dashboardPanel.respArea.setText("")
        self.summary.reset()
        self.summaryPanel.update(self.summary)

    def _on_toggle_show_all(self, evt=None):
        self.dashboardPanel.model.showAll = self.dashboardPanel.chkShowAll.isSelected()
        self.dashboardPanel.model.refresh()

    def _on_toggle_raw_req(self, evt=None):
        self._render_current_request_area()

    def _on_toggle_raw_resp(self, evt=None):
        self._render_current_response_area()

    def _on_save_settings(self, evt=None):
        self._save_settings(show_toast=True)

    def _on_start(self, evt=None):
        if self.worker and self.worker.is_alive():
            JOptionPane.showMessageDialog(self.root, "A run is already active.", "Info", JOptionPane.INFORMATION_MESSAGE)
            return

        self._save_settings()

        def prep_and_run():
            try:
                # If calls pre-populated via imports, use them; else load from Swagger/OpenAPI
                if not self.calls:
                    spec_src = self.settingsPanel.txtSpec.getText().strip()
                    if not spec_src:
                        self._ui(lambda: JOptionPane.showMessageDialog(self.root, "Enter Spec URL or file path (JSON or Swagger UI HTML).", "Missing", JOptionPane.WARNING_MESSAGE))
                        return
                    spec = self.load_spec_json(spec_src)
                    methods = self._selected_methods()
                    calls, documented, eligible, missrep, optrep = self.enumerate_calls(spec, methods, spec_src)
                    def set_prep():
                        self.calls = calls
                        self.summary.reset()
                        self.summary.documentedTotal = documented
                        self.summary.eligibleTotal = eligible
                        self.summary.baseUrl = self.base_url_from_spec(spec, self._origin_from_src(spec_src))
                        self.summary.missingReport = missrep
                        self.summary.optionalReport = optrep
                        self.summaryPanel.update(self.summary)
                    self._ui(set_prep)
                else:
                    def set_prep2():
                        self.summary.reset()
                        self.summary.documentedTotal = len(self.calls)
                        self.summary.eligibleTotal = len(self.calls)
                        self.summaryPanel.update(self.summary)
                    self._ui(set_prep2)

                if not self.calls:
                    self._ui(lambda: JOptionPane.showMessageDialog(self.root, "No endpoints to test. Check filters/imports.", "Nothing to run", JOptionPane.WARNING_MESSAGE))
                    return

                def ui_reset():
                    self.dashboardPanel.model.clear()
                    self.dashboardPanel.reqArea.setText("")
                    self.dashboardPanel.respArea.setText("")
                    self.summary.tested = 0
                    self.summary.ok2xx = 0
                    self.summary.statusCounts.clear()
                    self.summary.leftoverPlaceholders = getattr(self.summary, "leftoverPlaceholders", [])
                    self.summary.failedEndpoints = []
                    self.dashboardPanel.setRunning(True)
                    self._stop_requested = False
                self._ui(ui_reset)

                self.worker = threading.Thread(target=self._validate_worker)
                self.worker.setDaemon(True)
                self.worker.start()

            except Exception as e:
                self._ui(lambda: JOptionPane.showMessageDialog(self.root, "Failed to prepare run:\n" + str(e), "Error", JOptionPane.ERROR_MESSAGE))

        t = threading.Thread(target=prep_and_run); t.setDaemon(True); t.start()

    def _on_stop(self, evt=None):
        if self.worker and self.worker.is_alive():
            self._stop_requested = True
            self.dashboardPanel.setStopping()

    # ----- Dashboard: Export Postman (2xx rows; fallback to all calls) -----
    def _on_save_postman(self, evt=None):
        def build_pm_from_rows(rows):
            coll = {
                "info": {
                    "name": "SwagValidator Export " + time.strftime("%Y-%m-%d %H:%M:%S"),
                    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
                },
                "item": []
            }
            for ep in rows:
                req_raw = ep.reqRaw or ep.reqText or ""
                if not req_raw.strip():
                    continue
                h, b, ct = self._split_raw_http_text(req_raw)
                # start line
                first = (h.splitlines() or [""])[0].strip().split()
                method = (first[0] if first else "GET")
                # URL from first line "METHOD path HTTP/1.1"; reconstruct with Host header
                url = None
                try:
                    path_only = first[1] if len(first) > 1 else "/"
                    host = None
                    for line in h.splitlines():
                        if ":" in line:
                            k, v = line.split(":",1)
                            if k.strip().lower() == "host":
                                host = v.strip()
                                break
                    if host:
                        scheme = "https" if (ct or "").lower().startswith("https") else "https"
                        if path_only.startswith("http"):
                            url = path_only
                        else:
                            url = "%s://%s%s" % (scheme, host, path_only if path_only.startswith("/") else ("/"+path_only))
                except:
                    url = None
                if not url:
                    url = ep.url

                # headers
                hdrs = []
                for line in h.splitlines()[1:]:
                    if ":" in line:
                        k, v = line.split(":", 1)
                        if k.strip().lower() not in ("content-length",):
                            hdrs.append({"key": k.strip(), "value": v.strip()})

                body = None
                if b and method in ("POST","PUT","PATCH","DELETE"):
                    lang = "json" if ("json" in (ct or "").lower() or b.strip().startswith(("{","["))) else "text"
                    body = {"mode": "raw", "raw": b, "options": {"raw": {"language": lang}}}

                coll["item"].append({
                    "name": method + " " + url,
                    "request": {"method": method, "header": hdrs, "url": url, "body": body}
                })
            return coll

        try:
            rows_2xx = [ep for ep in self.dashboardPanel.model.rows if 200 <= (ep.status or 0) < 300]
            pm = build_pm_from_rows(rows_2xx)
            if not pm["item"]:
                # fallback: export ALL current calls as raw requests we can build
                tmp_rows = []
                for idx, c in enumerate(self.calls):
                    # synthesize a WorkingEndpoint with request built
                    host, port, https, req_bytes, req_text = self._build_burp_request(c, self._aggregate_headers_for_runtime())
                    tmp_rows.append(WorkingEndpoint(idx+1, c.method, c.url, None, 0, req_text, None))
                pm = build_pm_from_rows(tmp_rows)

            ch = JFileChooser()
            ch.setDialogTitle("Export Postman Collection")
            ch.setSelectedFile(File("swagger_dashboard_export.postman_collection.json"))
            ch.setFileFilter(FileNameExtensionFilter("JSON", ["json"]))
            if ch.showSaveDialog(self.root) == JFileChooser.APPROVE_OPTION:
                f = ch.getSelectedFile()
                out = open(f.getAbsolutePath(), "w")
                try:
                    out.write(json.dumps(pm, indent=2))
                finally:
                    out.close()
                JOptionPane.showMessageDialog(self.root, "Saved:\n" + f.getAbsolutePath(), "Exported", JOptionPane.INFORMATION_MESSAGE)
        except Exception as e:
            JOptionPane.showMessageDialog(self.root, "Failed to export: " + str(e), "Error", JOptionPane.ERROR_MESSAGE)

    # ----- Resend: override only if 2xx -----
    def _on_resend(self, evt=None):
        row = self.dashboardPanel.table.getSelectedRow()
        if row < 0:
            JOptionPane.showMessageDialog(self.root, "Select a row first.", "Info", JOptionPane.INFORMATION_MESSAGE)
            return
        midx = self.dashboardPanel.table.convertRowIndexToModel(row)
        ep = self.dashboardPanel.model.get(midx)
        raw_req_text = self.dashboardPanel.reqArea.getText()
        if not raw_req_text.strip():
            JOptionPane.showMessageDialog(self.root, "Request box is empty.", "Info", JOptionPane.INFORMATION_MESSAGE)
            return

        def do_send():
            try:
                u = URL(ep.url)
                https = (u.getProtocol().lower() == "https")
                port = (u.getPort() if u.getPort() != -1 else (443 if https else 80))
                svc = self.helpers.buildHttpService(u.getHost(), port, https)
                req_bytes = self.helpers.stringToBytes(raw_req_text)
                rr  = self.callbacks.makeHttpRequest(svc, req_bytes)
                resp_bytes = rr.getResponse()
                if resp_bytes is None:
                    out = "[No response]"
                    self._ui(lambda: self.dashboardPanel.respArea.setText(out))
                    return
                resp_raw = String(resp_bytes, "ISO-8859-1").toString()
                out = self._format_response_for_view(resp_raw)
                self._ui(lambda: self.dashboardPanel.respArea.setText(out))

                ri = self.helpers.analyzeResponse(resp_bytes)
                status = ri.getStatusCode()
                body_len = len(resp_bytes) - ri.getBodyOffset()

                if 200 <= status < 300:
                    def apply_override():
                        ep.status = status
                        ep.contentLength = body_len
                        ep.reqRaw = raw_req_text
                        ep.reqText = raw_req_text
                        ep.respRaw = resp_raw
                        ep.respText = resp_raw
                        self.dashboardPanel.model.rows[midx] = ep
                        self.dashboardPanel.model.refresh()
                        self._recompute_summary_from_table()
                    self._ui(apply_override)
            except Exception as e:
                self._ui(lambda: JOptionPane.showMessageDialog(self.root, "Replay failed: " + str(e), "Error", JOptionPane.ERROR_MESSAGE))

        t = threading.Thread(target=do_send); t.setDaemon(True); t.start()

    def _recompute_summary_from_table(self):
        rows = self.dashboardPanel.model.rows
        s = SummaryModel()
        s.documentedTotal = self.summary.documentedTotal
        s.eligibleTotal   = self.summary.eligibleTotal
        s.baseUrl         = getattr(self.summary, "baseUrl", "")
        s.missingReport   = getattr(self.summary, "missingReport", {})
        s.optionalReport  = getattr(self.summary, "optionalReport", {})
        s.leftoverPlaceholders = getattr(self.summary, "leftoverPlaceholders", [])
        s.failedEndpoints = getattr(self.summary, "failedEndpoints", [])
        s.tested = len(rows)
        for r in rows:
            key = str(r.status)
            s.statusCounts[key] = s.statusCounts.get(key, 0) + 1
            if 200 <= (r.status or 0) < 300:
                s.ok2xx += 1
        self.summary = s
        self.summaryPanel.update(self.summary)

    # ----- Render helpers -----
    def _render_current_request_area(self):
        row = self.dashboardPanel.table.getSelectedRow()
        if row < 0: return
        midx = self.dashboardPanel.table.convertRowIndexToModel(row)
        ep = self.dashboardPanel.model.get(midx)
        text = self._format_request_for_view(ep.reqRaw or ep.reqText)
        self.dashboardPanel.reqArea.setText(text)

    def _render_current_response_area(self):
        row = self.dashboardPanel.table.getSelectedRow()
        if row < 0: return
        midx = self.dashboardPanel.table.convertRowIndexToModel(row)
        ep = self.dashboardPanel.model.get(midx)
        text = self._format_response_for_view(ep.respRaw or ep.respText)
        self.dashboardPanel.respArea.setText(text)

    def _format_request_for_view(self, raw_http_text):
        if self.dashboardPanel.chkRawReq.isSelected():
            return raw_http_text
        h, b, ct = self._split_raw_http_text(raw_http_text)
        pretty = self._pretty_if_applicable(b, ct)
        return h + "\r\n\r\n" + pretty

    def _format_response_for_view(self, raw_http_text):
        if raw_http_text is None: return "[No response]"
        if self.dashboardPanel.chkRawResp.isSelected():
            return raw_http_text
        h, b, ct = self._split_raw_http_text(raw_http_text)
        pretty = self._pretty_if_applicable(b, ct)
        return h + "\r\n\r\n" + pretty

    # ----- helpers -----
    def _selected_methods(self):
        flags = self.settingsPanel.methodFlags()
        selected = set(m for m, v in flags.items() if v)
        return selected or set(ALL_METHODS)

    def _origin_from_src(self, src):
        try:
            u = URL(src)
            if u.getProtocol() and u.getHost():
                port = u.getPort()
                if port == -1:
                    return "%s://%s" % (u.getProtocol(), u.getHost())
                else:
                    return "%s://%s:%d" % (u.getProtocol(), u.getHost(), port)
        except Exception:
            pass
        return "http://localhost"

    def _resolve_against_origin(self, origin, maybe_url):
        if not maybe_url: return None
        try:
            if re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', maybe_url): return maybe_url
            if maybe_url.startswith("/"): return origin.rstrip("/") + maybe_url
            return origin.rstrip("/") + "/" + maybe_url
        except Exception:
            return None

    # --- dynamic discovery: HTML -> configUrl -> urls[] -> real spec
    def load_spec_json(self, src):
        if os.path.exists(src):
            f = open(src, "r")
            try:
                data = json.load(f)
                if isinstance(data, dict) and (data.get("openapi") or data.get("swagger")):
                    return data
                origin = self._origin_from_src(src)
                out = self._follow_swagger_config(origin, data)
                if out: return out
                raise Exception("File is not a valid OpenAPI/Swagger spec.")
            finally:
                f.close()

        origin = self._origin_from_src(src)
        raw = self._http_get_raw(src)
        try:
            doc = json.loads(raw)
            if isinstance(doc, dict) and (doc.get("openapi") or doc.get("swagger")):
                return doc
            out = self._follow_swagger_config(origin, doc)
            if out: return out
        except ValueError:
            html = raw or ""
            m_cfg = re.search(r'configUrl\s*:\s*["\']([^"\']+)["\']', html)
            if m_cfg:
                cfg_url = self._resolve_against_origin(origin, m_cfg.group(1))
                cfg_raw = self._http_get_raw(cfg_url)
                cfg_doc = json.loads(cfg_raw)
                out = self._follow_swagger_config(origin, cfg_doc)
                if out: return out
            m_urls = re.search(r'urls\s*:\s*\[\s*(\{.*?\})\s*\]', html, re.DOTALL)
            if m_urls:
                for rel in re.findall(r'url\s*:\s*["\']([^"\']+)["\']', m_urls.group(1)):
                    u2 = self._resolve_against_origin(origin, rel)
                    spec_raw = self._http_get_raw(u2)
                    spec = json.loads(spec_raw)
                    if isinstance(spec, dict) and (spec.get("openapi") or spec.get("swagger")):
                        return spec
            m_url  = re.search(r'url\s*:\s*["\']([^"\']+)["\']', html)
            if m_url:
                u2 = self._resolve_against_origin(origin, m_url.group(1))
                spec_raw = self._http_get_raw(u2)
                spec = json.loads(spec_raw)
                if isinstance(spec, dict) and (spec.get("openapi") or spec.get("swagger")):
                    return spec

        for p in ["/swagger/properties.json", "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
                  "/swagger/swagger.json", "/openapi.json", "/api-docs", "/v2/api-docs"]:
            try:
                doc = json.loads(self._http_get_raw(origin.rstrip("/") + p))
                if isinstance(doc, dict) and (doc.get("openapi") or doc.get("swagger")):
                    return doc
                out = self._follow_swagger_config(origin, doc)
                if out: return out
            except Exception:
                continue

        raise Exception("Spec not found. Paste Swagger UI HTML or OpenAPI JSON; discovery is dynamic.")

    def _follow_swagger_config(self, origin, cfg):
        if not isinstance(cfg, dict): return None
        urls = cfg.get("urls")
        if isinstance(urls, list):
            for item in urls:
                u2 = self._resolve_against_origin(origin, (item or {}).get("url"))
                if not u2: continue
                try:
                    spec = json.loads(self._http_get_raw(u2))
                    if isinstance(spec, dict) and (spec.get("openapi") or spec.get("swagger")):
                        return spec
                except Exception:
                    continue
        u1 = cfg.get("url")
        if isinstance(u1, basestring):
            u2 = self._resolve_against_origin(origin, u1)
            if u2:
                spec = json.loads(self._http_get_raw(u2))
                if isinstance(spec, dict) and (spec.get("openapi") or spec.get("swagger")):
                    return spec
        return None

    def _http_get_raw(self, url):
        u = URL(url)
        https = (u.getProtocol().lower() == "https")
        port = (u.getPort() if u.getPort() != -1 else (443 if https else 80))
        path = u.getFile() or "/"

        sb = []
        sb.append("GET " + path + " HTTP/1.1\r\n")
        sb.append("Host: " + u.getHost() + "\r\n")
        ua = self.settingsPanel.txtUA.getText().strip()
        if ua: sb.append("User-Agent: " + ua + "\r\n")
        sb.append("Accept: application/json\r\n")
        for k, v in self._aggregate_headers_for_runtime().items():
            lk = (k or "").lower()
            if lk not in ("host", "content-length", "accept"):
                sb.append(k + ": " + str(v) + "\r\n")
        sb.append("\r\n")

        svc = self.helpers.buildHttpService(u.getHost(), port, https)
        rr  = self.callbacks.makeHttpRequest(svc, self.helpers.stringToBytes("".join(sb)))
        resp_bytes = rr.getResponse()
        if resp_bytes is None: raise Exception("No response for spec: " + url)
        ri = self.helpers.analyzeResponse(resp_bytes)
        if ri.getStatusCode() < 200 or ri.getStatusCode() >= 300:
            raise Exception("Failed to fetch spec (HTTP %d)" % ri.getStatusCode())
        off = ri.getBodyOffset()
        return String(resp_bytes[off:], "ISO-8859-1").toString()

    def _aggregate_headers_for_runtime(self):
        headers = {"Accept": "application/json"}
        ua = self.settingsPanel.txtUA.getText().strip()
        if ua: headers["User-Agent"] = ua
        api_h = self.settingsPanel.txtApiHeader.getText().strip()
        api_v = self.settingsPanel.txtApiValue.getText().strip()
        if api_h and api_v: headers[api_h] = api_v
        bearer = self.settingsPanel.txtBearer.getText().strip()
        if bearer: headers["Authorization"] = "Bearer " + bearer
        mh = (self.settingsPanel.txtManualHeaders.getText() or "").strip()
        if mh:
            for pair in re.split(r"\s*[;,]\s*", mh):
                if not pair or pair.startswith("#"): continue
                idx = pair.find(":")
                if idx > 0:
                    k = pair[:idx].strip(); v = pair[idx+1:].strip()
                    if k: headers[k] = v
        return headers

    # ----- enumeration from Swagger/OpenAPI -----
    def is_oas3(self, spec): return bool(spec.get("openapi"))

    def _infer_basepath_from_paths(self, spec):
        paths = spec.get("paths") or {}
        segs = []
        for p in paths.keys():
            if not isinstance(p, basestring): continue
            if not p.startswith("/"): continue
            parts = p.split("/")
            if len(parts) > 1 and parts[1]:
                segs.append("/" + parts[1])
        if not segs: return ""
        from collections import Counter
        seg, cnt = Counter(segs).most_common(1)[0]
        if cnt >= max(3, int(0.6 * len(segs))):
            return seg
        return ""

    def base_url_from_spec(self, spec, fallback_origin):
        if not self.is_oas3(spec):
            host = spec.get("host")
            schemes = spec.get("schemes") or ["https"]
            base_path = spec.get("basePath") or ""
            if not base_path:
                base_path = self._infer_basepath_from_paths(spec)
            if host:
                scheme = schemes[0] if schemes else "https"
                out = (scheme + "://" + host + (base_path or "/")).rstrip("/")
            else:
                out = fallback_origin.rstrip("/") + (base_path or "")
            return out or fallback_origin.rstrip("/")

        servers = spec.get("servers") or []
        if servers:
            raw = (servers[0].get("url") or "").strip()
            if raw:
                if re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', raw):
                    return raw.rstrip("/")
                vars = servers[0].get("variables") or {}
                def _sub_var(m):
                    key = m.group(1)
                    v = vars.get(key, {}).get("default")
                    return v if v is not None else m.group(0)
                raw2 = re.sub(r"\{([^}]+)\}", _sub_var, raw)
                base = fallback_origin.rstrip("/")
                if raw2.startswith("/"): return (base + raw2).rstrip("/")
                return (base + "/" + raw2).rstrip("/")
        infer = self._infer_basepath_from_paths(spec)
        if infer:
            return (fallback_origin.rstrip("/") + infer).rstrip("/")
        return fallback_origin.rstrip("/")

    def enumerate_calls(self, spec, method_allow, spec_src=None):
        origin = self._origin_from_src(spec_src or "")
        base = self.base_url_from_spec(spec, origin)

        paths = spec.get("paths") or {}
        documented = 0; eligible = 0
        missing_report = {}; optional_report = {}

        header_template = self._aggregate_headers_for_runtime()
        calls = []
        self._creators = {}

        try:
            self.summary.baseUrl = base
        except Exception:
            pass

        exclude_raw = (self.settingsPanel.txtExcludePaths.getText() or "")
        exclude_tokens = [s.strip().lower() for s in re.split(r"\s*,\s*", exclude_raw) if s.strip()]
        excl_login = self.settingsPanel.chkExcludeLogin.isSelected()

        for path, ops in (paths.items() if hasattr(paths, "items") else []):
            if not ops: continue

            if "post" in ops:
                if path.strip() == "/user": self._creators["user"] = ("POST", path)
                if path.strip() == "/pet":  self._creators["pet"]  = ("POST", path)

            for m, op in ops.items():
                method = m.upper(); documented += 1
                if method not in ALL_METHODS or method not in method_allow: continue

                lo_path = path.lower()
                if any(tok in lo_path for tok in exclude_tokens): continue
                opid = (op.get("operationId") or "").lower()
                if excl_login and ("login" in lo_path or "login" in opid or "auth" in lo_path): continue

                miss = []; optional = []
                params = op.get("parameters") or []
                vals = self.param_values(params, miss, optional)

                list_query_params = []
                for p in params:
                    if p.get("in") == "query":
                        nm = p.get("name")
                        if nm in vals and isinstance(vals[nm], list) and vals[nm]:
                            list_query_params.append(nm)

                def build_url_with(qdict):
                    final_path = self.fill_path(path, vals)
                    q = {}
                    for p in params:
                        if p.get("in") == "query":
                            n = p.get("name")
                            v = qdict.get(n, vals.get(n))
                            if isinstance(v, list): v = ",".join([str(x) for x in v])
                            q[n] = v
                    u = self.join_base(base, final_path)
                    if q: u += "?" + self.urlencode(q)
                    return u

                urls_to_make = [build_url_with({})]
                if list_query_params and self.settingsPanel.chkEnumAll.isSelected():
                    nm = list_query_params[0]
                    urls_to_make = [build_url_with({nm: item}) for item in vals[nm]]

                body_ct, body_val = self.build_body(spec, op, miss)

                for one_url in urls_to_make:
                    key = method + " " + path
                    if miss:     missing_report[key]  = sorted(list(set(miss)))
                    if optional: optional_report[key] = sorted(list(set(optional)))
                    calls.append(SpecCall(method, one_url, body_ct, body_val, path))
                    eligible += 1

        self.summary.missingReport = missing_report
        self.summary.optionalReport = optional_report

        return calls, documented, eligible, missing_report, optional_report

    # ----- example builders (schema-aware) -----
    def pick_example(self, obj):
        if not isinstance(obj, dict): return None
        if "example" in obj: return obj["example"]
        if "examples" in obj and isinstance(obj["examples"], dict):
            for ex in obj["examples"].values():
                if isinstance(ex, dict) and "value" in ex: return ex["value"]
                if not isinstance(ex, dict): return ex
        sch = obj.get("schema") if "schema" in obj else obj
        if isinstance(sch, dict):
            if "example" in sch: return sch["example"]
            if "default" in sch: return sch["default"]
            if "enum" in sch and sch["enum"]: return sch["enum"][0]
            if "x-example" in sch: return sch["x-example"]
        if "x-example" in obj: return obj["x-example"]
        if "x-examples" in obj and isinstance(obj["x-examples"], dict):
            for exv in obj["x-examples"].values(): return exv
        return None

    def resolve_ref(self, spec, ref):
        if not ref or not ref.startswith("#/"): return None
        node = spec
        for p in ref.lstrip("#/").split("/"):
            if isinstance(node, dict) and p in node: node = node[p]
            else: return None
        return node if isinstance(node, dict) else None

    def build_from_schema(self, spec, schema, missing, prefix):
        if not isinstance(schema, dict): return None
        if "$ref" in schema:
            tgt = self.resolve_ref(spec, schema["$ref"])
            return self.build_from_schema(spec, tgt or {}, missing, prefix)

        ex = self.pick_example(schema)
        if ex is not None: return ex

        if schema.get("oneOf"): return self.build_from_schema(spec, schema["oneOf"][0], missing, prefix)
        if schema.get("anyOf"): return self.build_from_schema(spec, schema.get("anyOf")[0], missing, prefix)
        if schema.get("allOf"):
            merged = {}
            for sub in schema["allOf"]:
                v = self.build_from_schema(spec, sub, missing, prefix)
                if isinstance(v, dict): merged.update(v)
            if merged: return merged

        t = schema.get("type")
        if t == "object" or "properties" in schema:
            props = schema.get("properties") or {}
            req = set(schema.get("required") or [])
            out = {}
            for k, sub in props.items():
                v = self.build_from_schema(spec, sub, missing, prefix + k + ".")
                if v is None:
                    byname = _name_based_value(k)
                    if byname is not None:
                        v = byname
                    else:
                        sub_t = sub.get("type", "string")
                        if sub_t in ("integer","number"):
                            v = _number_in_range(sub.get("minimum"), sub.get("maximum"), "integer" if sub_t=="integer" else "number")
                        elif sub_t == "boolean":
                            v = True
                        else:
                            v = _string_meeting(sub, FALLBACK.get(sub_t, "string"))
                out[k] = v
                if k in req and (v is None or v == "" or v == {}):
                    missing.append(prefix + k.strip("."))
            return out

        if t == "array" or ("items" in schema):
            items = schema.get("items") or {"type":"string"}
            iv = self.build_from_schema(spec, items, missing, prefix + "[]")
            if iv is None:
                sub_t = items.get("type","string")
                if sub_t in ("integer","number"):
                    iv = _number_in_range(items.get("minimum"), items.get("maximum"), "integer" if sub_t=="integer" else "number")
                elif sub_t == "boolean":
                    iv = True
                else:
                    iv = _string_meeting(items, FALLBACK.get(sub_t, "string"))
            return [iv]

        if t in ("integer","number"):
            return _number_in_range(schema.get("minimum"), schema.get("maximum"), "integer" if t=="integer" else "number")
        if t == "boolean":
            return True
        if t == "string" or t is None:
            return _string_meeting(schema, "string")

        return {}

    def param_values(self, parameters, missing, optional_params):
        vals = {}
        expand_all = self.settingsPanel.chkEnumAll.isSelected()
        for p in (parameters or []):
            where = p.get("in")
            if where not in ("path","query","header","cookie"):
                continue
            name = p.get("name")
            required = p.get("required", False)
            sch = p.get("schema") or {}

            st_match = None
            ln = (name or "").lower()
            if ln in ("id","userid","user_id","feedbackid","feedback_id","petid","pet_id","itemid","item_id"):
                st_match = self._state["ids"].get(ln.replace("_","").replace("id","").strip())
                if not st_match:
                    for v in self._state["ids"].values():
                        st_match = v; break

            val = st_match

            if val is None:
                val = self.pick_example(p)
            if val is None:
                if "default" in sch: val = sch["default"]
                elif "enum" in sch and sch["enum"]:
                    val = list(sch["enum"]) if expand_all else sch["enum"][0]

            if val is None:
                byname = _name_based_value(name)
                if byname is not None: val = byname

            if val is None:
                typ = sch.get("type") or p.get("type") or "string"
                if typ in ("integer","number"):
                    val = _number_in_range(sch.get("minimum"), sch.get("maximum"),
                                           "integer" if typ=="integer" else "number")
                elif typ == "boolean":
                    val = True
                else:
                    val = _string_meeting(sch, FALLBACK.get(typ, "string"))

            if not required:
                optional_params.append(name)
            elif val in (None, "", {}):
                missing.append("param:" + name)

            is_array = (sch.get("type") == "array")
            if is_array and isinstance(val, list):
                vals[name] = val[:]
            elif is_array and isinstance(val, (tuple,set)):
                vals[name] = list(val)
            else:
                vals[name] = val
        return vals

    def fill_path(self, path, vals):
        out = path
        for k, v in vals.items():
            out = re.sub(r"{\s*" + re.escape(k) + r"\s*}", str(v), out)
        return out

    def urlencode(self, d):
        if not d: return ""
        pairs = []
        for k, v in d.items():
            k_enc = self.helpers.urlEncode(str(k))
            v_enc = self.helpers.urlEncode(str(v))
            pairs.append("%s=%s" % (k_enc, v_enc))
        return "&".join(pairs)

    def join_base(self, base, path):
        if base.endswith("/") and path.startswith("/"): return base[:-1] + path
        if (not base.endswith("/")) and (not path.startswith("/")): return base + "/" + path
        return base + path

    def choose_oas3_body(self, spec, op):
        rb = op.get("requestBody") or {}
        content = rb.get("content") or {}
        for ct in ("application/json","application/x-www-form-urlencoded","multipart/form-data","text/plain","application/xml"):
            if ct in content: return ct, content[ct]
        if content:
            for k in content.keys(): return k, content[k]
        return None, None

    def build_body(self, spec, op, missing):
        if self.is_oas3(spec):
            ct, media = self.choose_oas3_body(spec, op)
            if not media: return None, None
            if "example" in media: return ct, media["example"]
            if "examples" in media and isinstance(media["examples"], dict):
                for ex in media["examples"].values():
                    if isinstance(ex, dict) and "value" in ex: return ct, ex["value"]
                    if not isinstance(ex, dict): return ct, ex
            sch = media.get("schema")
            if sch:
                return ct, self.build_from_schema(spec, sch, missing, "body.")
            return ct, {}

        params = op.get("parameters") or []
        consumes = None
        if "consumes" in op and isinstance(op["consumes"], list) and op["consumes"]:
            consumes = op["consumes"][0]
        elif "consumes" in spec and isinstance(spec["consumes"], list) and spec["consumes"]:
            consumes = spec["consumes"][0]

        body_schema = None
        form = {}
        for p in params:
            where = p.get("in")
            if where == "body" and p.get("schema"):
                body_schema = p["schema"]
            elif where == "formData":
                t = p.get("type","string"); name = p.get("name")
                if t != "file":
                    val = self.pick_example(p)
                    if val is None:
                        byname = _name_based_value(name)
                        if byname is not None:
                            val = byname
                        else:
                            if t in ("integer","number"):
                                val = _number_in_range(p.get("minimum"), p.get("maximum"), "integer" if t=="integer" else "number")
                            elif t == "boolean":
                                val = True
                            else:
                                val = _string_meeting({"type":t}, FALLBACK.get(t, "string"))
                    form[name] = val

        if body_schema is not None:
            ct = consumes or "application/json"
            return ct, self.build_from_schema(spec, body_schema, missing, "body.")

        if form:
            ct = consumes or "application/x-www-form-urlencoded"
            return ct, form

        return None, None

    # ---------- Challenge 2: Import Postman, replace placeholders heuristically ----------
    def _load_json_from_path_or_url(self, path_or_url):
        try:
            if os.path.exists(path_or_url):
                with open(path_or_url, "r") as f: return json.load(f)
            raw = self._http_get_raw(path_or_url)
            return json.loads(raw)
        except Exception as e:
            raise Exception("Failed to load JSON: %s" % e)

    def _replace_placeholders_heuristic(self, s):
        if not isinstance(s, basestring): return s
        def repl(match):
            token = None
            for i in range(1,6):
                if match.group(i):
                    token = match.group(i); break
            val = _name_based_value(token)
            if val is None:
                if token and token.lower().endswith("id"):
                    val = 1
                elif token and "email" in token.lower():
                    val = "test@example.com"
                else:
                    val = "test"
            return str(val)
        return self._PLACEHOLDER_PAT.sub(repl, s)

    def _pm_item_to_spec_calls(self, item):
        calls = []
        if "request" in item:
            req = item["request"]
            method = (req.get("method") or "GET").upper()
            url = req.get("url")
            if isinstance(url, dict):
                url = url.get("raw") or url.get("host") or ""
            url = self._replace_placeholders_heuristic(url or "")

            headers = {}
            for h in (req.get("header") or []):
                if h and h.get("key"):
                    headers[h["key"]] = self._replace_placeholders_heuristic(h.get("value","") or "")

            body_ct = None; body_val = None
            body = req.get("body") or {}
            mode = body.get("mode")
            if mode == "raw":
                raw = body.get("raw") or ""
                raw = self._replace_placeholders_heuristic(raw)
                if raw.strip().startswith(("{","[")):
                    body_ct = "application/json"
                    try: body_val = json.loads(raw)
                    except: body_val = raw
                else:
                    body_ct = "text/plain"; body_val = raw
            elif mode == "urlencoded":
                body_ct = "application/x-www-form-urlencoded"
                body_val = dict(((kv.get("key","") or ""), self._replace_placeholders_heuristic(kv.get("value","") or ""))
                                for kv in (body.get("urlencoded") or []))
            elif mode == "formdata":
                body_ct = "multipart/form-data"
                body_val = dict(((kv.get("key","") or ""), self._replace_placeholders_heuristic(kv.get("value","") or ""))
                                for kv in (body.get("formdata") or []) if kv.get("type","text")=="text")

            hdrs = self._aggregate_headers_for_runtime()
            hdrs.update(headers)
            sc = SpecCall(method, url, body_ct, body_val, url)
            sc._inline_headers = hdrs
            calls.append(sc)

        for ch in (item.get("item") or []):
            calls.extend(self._pm_item_to_spec_calls(ch))
        return calls

    def import_postman_collection(self, src):
        coll = self._load_json_from_path_or_url(src)
        items = coll.get("item") or []
        calls = []
        for it in items:
            calls.extend(self._pm_item_to_spec_calls(it))

        leftovers = []
        for sc in calls:
            if self._PLACEHOLDER_PAT.search(sc.url or ""):
                leftovers.append("URL: " + sc.url)
            if isinstance(getattr(sc, "body_val", None), basestring) and self._PLACEHOLDER_PAT.search(sc.body_val):
                leftovers.append("Body: " + sc.body_val[:120])
            if isinstance(getattr(sc, "body_val", None), dict):
                for k,v in sc.body_val.items():
                    if isinstance(v, basestring) and self._PLACEHOLDER_PAT.search(v):
                        leftovers.append("Body %s=%s" % (k, v))
        self.summary.leftoverPlaceholders = leftovers
        return calls, leftovers

    def _on_import_postman(self, evt=None):
        ch = JFileChooser()
        ch.setDialogTitle("Open Postman collection (JSON)")
        ch.setFileFilter(FileNameExtensionFilter("JSON", ["json"]))
        if ch.showOpenDialog(self.root) != JFileChooser.APPROVE_OPTION:
            return
        f = ch.getSelectedFile().getAbsolutePath()
        try:
            calls, leftovers = self.import_postman_collection(f)
            self.calls = calls
            self.summary.reset()
            self.summary.documentedTotal = len(calls)
            self.summary.eligibleTotal = len(calls)
            self.summary.leftoverPlaceholders = leftovers
            self.summaryPanel.update(self.summary)
            self.dashboardPanel.model.clear()
            self._on_start()
        except Exception as e:
            JOptionPane.showMessageDialog(self.root, "Import failed:\n"+str(e), "Error", JOptionPane.ERROR_MESSAGE)

    # ---------- Challenge 3: Import TXT/CSV/TSV endpoint lists ----------
    def import_endpoint_list(self, path):
        calls = []

        def add_call(method, url, body_ct=None, body_val=None, headers=None):
            sc = SpecCall(method.upper(), self._replace_placeholders_heuristic(url), body_ct, body_val, url)
            if headers:
                hdrs = self._aggregate_headers_for_runtime()
                hdrs.update(headers)
                sc._inline_headers = hdrs
            calls.append(sc)

        ext = os.path.splitext(path)[1].lower()

        if ext in (".txt", ".list"):
            with open(path, "r") as f:
                for ln in f:
                    ln = ln.strip()
                    if not ln or ln.startswith("#"): continue
                    parts = ln.split(None, 1)
                    if len(parts) == 1:
                        add_call("GET", parts[0])
                    else:
                        add_call(parts[0], parts[1])

        elif ext in (".csv", ".tsv"):
            import csv
            delim = "," if ext == ".csv" else "\t"
            with open(path, "r") as f:
                rdr = csv.DictReader(f, delimiter=delim)
                for row in rdr:
                    m = (row.get("method") or "GET").strip()
                    u = (row.get("url") or row.get("endpoint") or "").strip()
                    if not u: continue
                    hdrs = {}
                    hv = (row.get("headers") or "").strip()
                    if hv:
                        for pair in re.split(r"\s*[;,]\s*", hv):
                            if ":" in pair:
                                k,v = pair.split(":",1); hdrs[k.strip()] = self._replace_placeholders_heuristic(v.strip())
                    body_ct = (row.get("content_type") or row.get("content-type") or "").strip() or None
                    body = row.get("body")
                    body_val = None
                    if body is not None and body.strip() != "":
                        body = self._replace_placeholders_heuristic(body)
                        if (body_ct or "").lower().find("json") != -1 or body.strip().startswith(("{","[")):
                            try: body_val = json.loads(body)
                            except: body_val = body
                        else:
                            body_val = body
                    add_call(m, u, body_ct, body_val, hdrs)
        else:
            raise Exception("Unsupported list format. Use TXT/CSV/TSV.")

        return calls

    def _on_import_list(self, evt=None):
        ch = JFileChooser()
        ch.setDialogTitle("Open endpoint list (TXT/CSV/TSV)")
        if ch.showOpenDialog(self.root) != JFileChooser.APPROVE_OPTION:
            return
        f = ch.getSelectedFile().getAbsolutePath()
        try:
            calls = self.import_endpoint_list(f)
            self.calls = calls
            self.summary.reset()
            self.summary.documentedTotal = len(calls)
            self.summary.eligibleTotal = len(calls)
            self.summaryPanel.update(self.summary)
            self.dashboardPanel.model.clear()
            self._on_start()
        except Exception as e:
            JOptionPane.showMessageDialog(self.root, "Import failed:\n"+str(e), "Error", JOptionPane.ERROR_MESSAGE)

    # ----- validation worker -----
    def _validate_worker(self):
        base_headers_map = self._aggregate_headers_for_runtime()
        for idx, call in enumerate(self.calls):
            if self._stop_requested: break

            host, port, https, req_bytes, req_text = self._build_burp_request(call, base_headers_map)
            try:
                svc = self.helpers.buildHttpService(host, port, https)
                rr  = self.callbacks.makeHttpRequest(svc, req_bytes)
                resp_bytes = rr.getResponse()

                status = 0; body_len = 0
                resp_raw_text = None
                if resp_bytes is not None:
                    ri = self.helpers.analyzeResponse(resp_bytes)
                    status = ri.getStatusCode()
                    body_len = len(resp_bytes) - ri.getBodyOffset()

                    if status == 404 and call.method == "GET":
                        try:
                            fam = self._resource_family(call.url, URL(call.url).getPath())
                        except Exception:
                            fam = None
                        if fam and self._prime_if_needed(fam, call.url, base_headers_map):
                            rr2 = self.callbacks.makeHttpRequest(svc, req_bytes)
                            if rr2 is not None and rr2.getResponse() is not None:
                                resp_bytes = rr2.getResponse()
                                ri = self.helpers.analyzeResponse(resp_bytes)
                                status = ri.getStatusCode()
                                body_len = len(resp_bytes) - ri.getBodyOffset()

                    resp_raw_text = String(resp_bytes, "ISO-8859-1").toString()

                ep = WorkingEndpoint(idx+1, call.method, call.url, status, body_len, req_text, resp_raw_text)
                self.dashboardPanel.model.add(ep)

                if not (200 <= status < 300):
                    self.summary.failedEndpoints.append("%s %s -> %s" % (call.method, call.url, str(status)))

                if resp_raw_text:
                    self._update_state_from_response(call, status, resp_raw_text)
                    try:
                        u = URL(call.url)
                        fam = self._family_from_path(u.getPath())
                        st_id = self._state["ids"].get(fam)
                        if st_id:
                            self._retarget_future_calls_with_id(fam, st_id, idx)
                    except Exception:
                        pass

                self.summary.tested += 1
                key = str(status)
                self.summary.statusCounts[key] = self.summary.statusCounts.get(key, 0) + 1
                if 200 <= status < 300: self.summary.ok2xx += 1
                self.summaryPanel.update(self.summary)

                if self._stop_requested:
                    break

            except Exception:
                self.summary.tested += 1
                self.summary.statusCounts["EXCEPTION"] = self.summary.statusCounts.get("EXCEPTION", 0) + 1
                self.summary.failedEndpoints.append("%s %s -> EXCEPTION" % (call.method, call.url))
                self.summaryPanel.update(self.summary)
                if self._stop_requested:
                    break
        self.dashboardPanel.setIdle()

    def _build_burp_request(self, call, base_headers_map):
        u = URL(call.url)
        https = (u.getProtocol().lower() == "https")
        port = (u.getPort() if u.getPort() != -1 else (443 if https else 80))
        path = u.getFile() or "/"

        sb = []
        sb.append(call.method + " " + path + " HTTP/1.1\r\n")
        sb.append("Host: " + u.getHost() + "\r\n")

        header_lines = []
        hdr_src = getattr(call, "_inline_headers", None) or base_headers_map
        content_type_set = False
        for k, v in hdr_src.items():
            lk = (k or "").lower()
            if lk in ("host", "content-length"): continue
            if lk == "content-type": content_type_set = True
            header_lines.append(k + ": " + str(v) + "\r\n")

        self._apply_state_headers(header_lines, call.url)

        body_str = ""
        if call.body_ct and call.method in set(["POST","PUT","PATCH","DELETE"]):
            if call.body_ct.lower() == "application/json":
                raw = json.dumps(call.body_val) if not isinstance(call.body_val, basestring) else call.body_val
                if not content_type_set: header_lines.append("Content-Type: application/json\r\n")
                header_lines.append("Content-Length: " + str(len(raw)) + "\r\n")
                body_str = raw
            elif call.body_ct.lower() == "application/x-www-form-urlencoded" and isinstance(call.body_val, dict):
                form = "&".join(["%s=%s" % (self.helpers.urlEncode(str(k)), self.helpers.urlEncode(str(v))) for k, v in call.body_val.items()])
                if not content_type_set: header_lines.append("Content-Type: application/x-www-form-urlencoded\r\n")
                header_lines.append("Content-Length: " + str(len(form)) + "\r\n")
                body_str = form
            else:
                raw2 = str(call.body_val)
                if not content_type_set: header_lines.append("Content-Type: " + call.body_ct + "\r\n")
                header_lines.append("Content-Length: " + str(len(raw2)) + "\r\n")
                body_str = raw2

        for h in header_lines:
            sb.append(h)

        sb.append("\r\n")
        head = "".join(sb)
        req_text = head + (body_str or "")
        req_bytes = self.helpers.stringToBytes(req_text)
        return (u.getHost(), port, https, req_bytes, req_text)

    # ---------- pretty & split ----------
    def _pretty_if_applicable(self, body_text, content_type_hint):
        try:
            txt = (body_text or "").strip()
            if not txt:
                return body_text
            cth = (content_type_hint or "").lower()
            if ("json" in cth) or (txt.startswith("{") or txt.startswith("[")):
                obj = json.loads(txt)
                return json.dumps(obj, indent=2, sort_keys=False)
        except Exception:
            return body_text
        return body_text

    def _split_raw_http_text(self, s):
        if s is None: return ("","","")
        p = s.find("\r\n\r\n")
        if p == -1:
            p = s.find("\n\n")
        if p == -1:
            return (s, "", "")
        headers = s[:p]
        body = s[p+4:] if s.startswith("HTTP/") else s[p+2:]
        ct = ""
        for line in headers.splitlines():
            if line.lower().startswith("content-type:"):
                ct = line.split(":",1)[1].strip()
                break
        return (headers, body, ct)

    # ----- priming helpers (legacy demo) -----
    def _family_from_path(self, path):
        parts = [p for p in path.split("/") if p]
        for p in parts:
            lp = p.lower()
            if lp not in self._state["base_segments_skip"]:
                return lp
        return parts[0].lower() if parts else None

    def _update_ids_from_json(self, family, obj):
        try:
            if obj is None: return
            if isinstance(obj, list) and obj:
                self._update_ids_from_json(family, obj[0]); return
            if isinstance(obj, dict):
                if "id" in obj and obj["id"]:
                    self._state["ids"][family or "id"] = str(obj["id"]); return
                for k, v in obj.items():
                    if k.lower().endswith("id") and v not in (None, ""):
                        self._state["ids"][family or "id"] = str(v); return
                if "data" in obj:
                    self._update_ids_from_json(family, obj["data"])
        except Exception:
            pass

    def _retarget_future_calls_with_id(self, family, new_id, current_index):
        if not new_id or not family: return
        fam = family.lower()
        pat_seg = re.compile(r"/(" + re.escape(fam) + r")/([^/?#]+)")
        pat_qid = re.compile(r"([?&])([a-zA-Z0-9_]*id)=([^&#]*)")
        for i in range(current_index + 1, len(self.calls)):
            c = self.calls[i]
            if pat_seg.search(c.url):
                c.url = pat_seg.sub(r"/\1/" + str(new_id), c.url)
            if pat_qid.search(c.url):
                c.url = pat_qid.sub(lambda m: m.group(1) + m.group(2) + "=" + str(new_id), c.url)

    def _update_state_from_response(self, call, status, resp_raw_text):
        try:
            headers, body, ct = self._split_raw_http_text(resp_raw_text or "")
            for line in headers.splitlines():
                if line.lower().startswith("set-cookie:"):
                    cookie_part = line.split(":",1)[1].strip()
                    if cookie_part:
                        cookie_kv = cookie_part.split(";",1)[0]
                        if "=" in cookie_kv:
                            nm, val = cookie_kv.split("=",1)
                            self._state["cookie"][nm.strip()] = val.strip()

            obj = None
            try:
                if (ct or "").lower().find("json") != -1 or (body or "").strip().startswith(("{","[")):
                    obj = json.loads(body)
            except Exception:
                obj = None

            def _maybe_set_bearer(tok):
                if tok and isinstance(tok, basestring) and len(tok) >= 8:
                    self._state["bearer"] = tok

            if isinstance(obj, dict):
                if "access_token" in obj: _maybe_set_bearer(obj.get("access_token"))
                elif "token" in obj:     _maybe_set_bearer(obj.get("token"))
                elif "id_token" in obj:  _maybe_set_bearer(obj.get("id_token"))
                elif "data" in obj and isinstance(obj["data"], dict):
                    for key in ("access_token","token","id_token"):
                        if key in obj["data"]:
                            _maybe_set_bearer(obj["data"][key])

            try:
                u = URL(call.url)
                fam = self._family_from_path(u.getPath())
            except Exception:
                fam = None
            self._update_ids_from_json(fam, obj)

        except Exception:
            pass

    def _resource_family(self, url, path_template):
        if "/user/" in path_template: return "user"
        if "/pet/"  in path_template: return "pet"
        return None

    def _apply_state_headers(self, sb_headers_list, call_url):
        already_auth = any(h.lower().startswith("authorization:") for h in sb_headers_list)
        if self._state.get("bearer") and not already_auth:
            sb_headers_list.append("Authorization: Bearer " + self._state["bearer"] + "\r\n")

        learned = self._state.get("cookie") or {}
        if learned:
            existing_cookie = None
            for i, h in enumerate(sb_headers_list):
                if h.lower().startswith("cookie:"):
                    existing_cookie = (i, h.split(":",1)[1].strip())
                    break
            learned_str = "; ".join(["%s=%s" % (k, v) for k, v in learned.items()])
            if existing_cookie:
                idx, val = existing_cookie
                combined = val
                for k, v in learned.items():
                    if ("%s=" % k) not in val:
                        combined = (combined + "; " if combined else "") + ("%s=%s" % (k, v))
                sb_headers_list[idx] = "Cookie: " + combined + "\r\n"
            else:
                sb_headers_list.append("Cookie: " + learned_str + "\r\n")

    def _prime_if_needed(self, fam, target_url, headers_map):
        if not self.settingsPanel.chkPrime.isSelected(): return False
        creator = self._creators.get(fam)
        if not creator: return False

        method, path = creator
        spec_src = self.settingsPanel.txtSpec.getText().strip()
        spec = self.load_spec_json(spec_src)
        post_op = spec.get("paths",{}).get(path,{}).get("post")
        if not post_op: return False

        miss = []
        body_ct, body_val = self.build_body(spec, post_op, miss)
        if not body_ct: body_ct = "application/json"

        m = re.search(r"/user/([^/?#]+)", target_url)
        if fam == "user" and m and isinstance(body_val, dict):
            body_val["username"] = m.group(1)

        base = self.base_url_from_spec(spec, self._origin_from_src(spec_src))
        url = self.join_base(base, path)

        tmp = SpecCall("POST", url, body_ct, body_val, path)
        host, port, https, req_bytes, _ = self._build_burp_request(tmp, headers_map)
        svc = self.helpers.buildHttpService(URL(url).getHost(), port, https)
        rr  = self.callbacks.makeHttpRequest(svc, req_bytes)
        return rr is not None

# =================== models & UI ===================

class SpecCall(object):
    def __init__(self, method, url, body_ct, body_val, path_template):
        self.method = method; self.url = url
        self.body_ct = body_ct; self.body_val = body_val
        self.path_template = path_template

class WorkingEndpoint(object):
    def __init__(self, sno, method, url, status, contentLength, reqRaw, respRaw):
        self.sno = sno; self.method = method; self.url = url
        self.status = status; self.contentLength = contentLength
        self.reqRaw = reqRaw; self.respRaw = respRaw
        self.reqText = reqRaw; self.respText = respRaw

class EndpointTableModel(AbstractTableModel):
    def __init__(self):
        self.cols = ["S.No", "Method", "URL", "Status", "Content Length"]
        self.rows = []; self.showAll = True
    def getRowCount(self): return len(self._filtered())
    def getColumnCount(self): return len(self.cols)
    def getColumnName(self, c): return self.cols[c]
    def getValueAt(self, r, c):
        e = self._filtered()[r]
        return [e.sno, e.method, e.url, e.status, e.contentLength][c]
    def add(self, e): self.rows.append(e); self.refresh()
    def clear(self): self.rows = []; self.refresh()
    def refresh(self): self.fireTableDataChanged()
    def get(self, r): return self._filtered()[r]
    def _filtered(self):
        return self.rows if self.showAll else [x for x in self.rows if 200 <= (x.status or 0) < 300]

class SummaryModel(object):
    def __init__(self): self.reset()
    def reset(self):
        self.documentedTotal = 0
        self.eligibleTotal = 0
        self.tested = 0
        self.ok2xx = 0
        self.statusCounts = {}
        self.baseUrl = ""
        self.missingReport = {}
        self.optionalReport = {}
        self.leftoverPlaceholders = []
        self.failedEndpoints = []

class SettingsPanel(object):
    def __init__(self, app):
        self.app = app
        self.panel = JPanel(BorderLayout())
        self.panel.setBorder(EmptyBorder(6, 10, 6, 10))

        form = JPanel(GridBagLayout())
        form.setBorder(EmptyBorder(4, 0, 4, 0))
        c = GridBagConstraints()
        c.insets = Insets(6, 8, 6, 8)
        c.anchor = GridBagConstraints.NORTHWEST
        c.fill = GridBagConstraints.HORIZONTAL
        c.weightx = 1.0
        r = 0

        self._addRow(form, c, r, "Spec URL / file (JSON or Swagger UI HTML)",
                     self._mk_text("https://demo.testfire.net/swagger/index.html",
                                   "Paste the Swagger UI HTML OR the OpenAPI JSON URL.")); self.txtSpec = self._last; r += 1

        self._addSection(form, c, r, "Authentication"); r += 1
        self._addRow(form, c, r, "API Key Header", self._mk_text("X-API-Key", "Header name for API key.")); self.txtApiHeader = self._last; r += 1
        self._addRow(form, c, r, "API Key Value",  self._mk_text("", "Header value (kept local)."));        self.txtApiValue  = self._last; r += 1
        self._addRow(form, c, r, "Bearer Token",   self._mk_text("", "If set, adds Authorization: Bearer <token>")); self.txtBearer = self._last; r += 1

        self._addSection(form, c, r, "Method control"); r += 1
        self.chk = {}
        row = JPanel(FlowLayout(FlowLayout.LEFT,8,0))
        for m in ["GET","HEAD","OPTIONS","POST","PUT","PATCH","DELETE"]:
            cb = JCheckBox(m, True); self.chk[m] = cb; row.add(cb)
        self._addRow(form, c, r, "Allowed methods", row); r += 1

        self.chkEnumAll = JCheckBox("Test all enum values (expand requests)", True)
        self.chkEnumAll.setToolTipText("If a query parameter has enum or array values, send one request per value.")
        self._addRow(form, c, r, "", self.chkEnumAll); r += 1

        self._addSection(form, c, r, "Client options"); r += 1
        self._addRow(form, c, r, "User-Agent", self._mk_text("SwaggerPostmanValidator/1.2 (Jython)", "HTTP User-Agent header.")); self.txtUA = self._last; r += 1
        self._addRow(form, c, r, "Timeout (sec)", self._mk_text("15", "Connection/read timeout.")); self.txtTimeout = self._last; r += 1

        self.chkPrime = JCheckBox("Auto-prime resources (create then retry on 404)", True)
        self.chkPrime.setToolTipText("If a GET returns 404 for /user/{username} or /pet/{id}, the extension will POST a sample user/pet, then retry the GET once.")
        self._addRow(form, c, r, "", self.chkPrime); r += 1

        self._addSection(form, c, r, "Exclude paths (comma-separated substrings)"); r += 1
        self.txtExcludePaths = JTextField("", 64)
        self.txtExcludePaths.setToolTipText("Comma-separated: e.g. /login, /auth/token")
        self.txtExcludePaths.setPreferredSize(Dimension(1000, self.txtExcludePaths.getPreferredSize().height))
        self._addRow(form, c, r, "Exclude list", self.txtExcludePaths); r += 1

        self.chkExcludeLogin = JCheckBox("Exclude login endpoints", False)
        self.chkExcludeLogin.setToolTipText("Skips any path containing 'login' or operationId with 'login'/'auth'.")
        self._addRow(form, c, r, "", self.chkExcludeLogin); r += 1

        # Manual Headers section (needed by load/save + runtime)
        self._addSection(form, c, r, "Manual Headers"); r += 1
        self.txtManualHeaders = JTextField("", 64)
        self.txtManualHeaders.setToolTipText("Semicolon- or comma-separated header pairs. Example: 'Accept-Language: en-US; X-Trace: 1'")
        self.txtManualHeaders.setPreferredSize(Dimension(1000, self.txtManualHeaders.getPreferredSize().height))
        self._addRow(form, c, r, "Extra headers", self.txtManualHeaders); r += 1

        self.panel.add(form, BorderLayout.CENTER)

        bar = JPanel(FlowLayout(FlowLayout.RIGHT))
        self.btnClearAuth = JButton("Clear Auth")
        self.btnSave = JButton("Save Settings")
        bar.add(self.btnClearAuth); bar.add(self.btnSave)
        self.panel.add(bar, BorderLayout.SOUTH)

    def _mk_text(self, text, tip=None):
        tf = JTextField(text, 64)
        tf.setPreferredSize(Dimension(1000, tf.getPreferredSize().height))
        if tip: tf.setToolTipText(tip)
        return tf

    def _addRow(self, form, c, row, label, component, weighty=0.0):
        c.gridx = 0; c.gridy = row; c.weightx = 0.0; c.weighty = 0.0; c.fill = GridBagConstraints.NONE
        lab = JLabel(label); form.add(lab, c)
        c.gridx = 1; c.weightx = 1.0; c.fill = GridBagConstraints.HORIZONTAL; c.weighty = weighty
        form.add(component, c); self._last = component

    def _addSection(self, form, c, row, title):
        L = JLabel(title); L.setFont(L.getFont().deriveFont(Font.BOLD))
        c.gridx = 0; c.gridy = row; c.gridwidth = 2; c.weightx = 1.0; c.fill = GridBagConstraints.HORIZONTAL
        form.add(L, c); c.gridwidth = 1

    def methodFlags(self):
        return dict((m, cb.isSelected()) for m, cb in self.chk.items())

class DashboardPanel(object):
    def __init__(self, app):
        self.app = app
        self.panel = JPanel(BorderLayout())

        top = JPanel(FlowLayout(FlowLayout.LEFT,8,8))
        self.btnStart = JButton("Start Validate")
        self.btnStop = JButton("Stop"); self.btnStop.setEnabled(False)
        self.btnClear = JButton("Clear Results")
        self.chkShowAll = JCheckBox("Show non-2xx", True)
        self.btnImportPM = JButton("Import Postman...")
        self.btnImportList = JButton("Import List/CSV/TSV...")
        self.btnExportPM = JButton("Export Postman...")  # in Dashboard (required)
        self.lblState = JLabel("Idle")
        top.add(self.btnStart); top.add(self.btnStop); top.add(self.btnClear)
        top.add(self.chkShowAll); top.add(self.btnImportPM); top.add(self.btnImportList); top.add(self.btnExportPM)
        top.add(JLabel("Status: ")); top.add(self.lblState)
        self.panel.add(top, BorderLayout.NORTH)

        self.model = EndpointTableModel()
        self.table = JTable(self.model)
        self.table.setFillsViewportHeight(True)

        leftReqPanel = JPanel(BorderLayout())
        headReq = JPanel(BorderLayout())
        headReq.add(JLabel("Request"), BorderLayout.WEST)
        self.chkRawReq = JCheckBox("Raw", False)
        headReq.add(self.chkRawReq, BorderLayout.EAST)
        leftReqPanel.add(headReq, BorderLayout.NORTH)
        self.reqArea = JTextArea(); self.reqArea.setEditable(True)
        self.reqArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        leftReqPanel.add(JScrollPane(self.reqArea), BorderLayout.CENTER)
        leftButtons = JPanel(FlowLayout(FlowLayout.LEFT))
        self.btnResend = JButton("Resend")
        leftButtons.add(self.btnResend)
        leftReqPanel.add(leftButtons, BorderLayout.SOUTH)

        rightRespPanel = JPanel(BorderLayout())
        headResp = JPanel(BorderLayout())
        headResp.add(JLabel("Response"), BorderLayout.WEST)
        self.chkRawResp = JCheckBox("Raw", False)
        headResp.add(self.chkRawResp, BorderLayout.EAST)
        rightRespPanel.add(headResp, BorderLayout.NORTH)
        self.respArea = JTextArea(); self.respArea.setEditable(False)
        self.respArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        rightRespPanel.add(JScrollPane(self.respArea), BorderLayout.CENTER)

        bottomSplit = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftReqPanel, rightRespPanel)
        bottomSplit.setResizeWeight(0.5)

        mainSplit = JSplitPane(JSplitPane.VERTICAL_SPLIT, JScrollPane(self.table), bottomSplit)
        mainSplit.setResizeWeight(0.55)
        self.panel.add(mainSplit, BorderLayout.CENTER)

    def setRunning(self, running):
        if running:
            self.lblState.setText("Running...")
            self.btnStart.setEnabled(False); self.btnStop.setEnabled(True)
        else:
            self.lblState.setText("Idle")
            self.btnStart.setEnabled(True); self.btnStop.setEnabled(False)

    def setStopping(self):
        self.lblState.setText("Stopping..."); self.btnStop.setEnabled(False)

    def setIdle(self):
        self.setRunning(False)

# ===== Simplified Summary: table-style stats & notes =====

class SummaryPanel(object):
    def __init__(self, app):
        self.app = app
        self.panel = JPanel(BorderLayout())

        top = JPanel(GridLayout(1,1,12,12)); top.setBorder(EmptyBorder(12,12,0,12))
        cols = ["Metric", "Value"]
        self.tblModel = DefaultTableModel(cols, 0)
        self.tbl = JTable(self.tblModel)
        self.tbl.setFillsViewportHeight(True)
        top.add(JScrollPane(self.tbl))
        self.panel.add(top, BorderLayout.NORTH)

        center = JPanel(GridLayout(1,2,12,12)); center.setBorder(EmptyBorder(12,12,12,12))
        self.notesArea = JTextArea(); self.notesArea.setEditable(False)
        self.notesArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        center.add(JScrollPane(self.notesArea))

        self.statusModel = DefaultTableModel(["Status Code", "Count"], 0)
        self.statusTbl = JTable(self.statusModel)
        center.add(JScrollPane(self.statusTbl))
        self.panel.add(center, BorderLayout.CENTER)

        bottom = JPanel(BorderLayout())
        self.statusArea = JTextArea(); self.statusArea.setEditable(False)
        self.statusArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        bottom.add(JScrollPane(self.statusArea), BorderLayout.CENTER)
        self.panel.add(bottom, BorderLayout.SOUTH)

    def _set_kv(self, k, v):
        found = -1
        for i in range(self.tblModel.getRowCount()):
            if self.tblModel.getValueAt(i,0) == k:
                found = i; break
        if found >= 0:
            self.tblModel.setValueAt(str(v), found, 1)
        else:
            self.tblModel.addRow([k, str(v)])

    def update(self, s):
        self.tblModel.setRowCount(0)
        self._set_kv("Project Base URL", s.baseUrl or "-")
        self._set_kv("Endpoints (Documented/Imported)", s.documentedTotal)
        self._set_kv("Eligible to Test", s.eligibleTotal)
        self._set_kv("Tested", s.tested)
        self._set_kv("2xx OK", s.ok2xx)

        self.statusModel.setRowCount(0)
        def keyf(x):
            try: return (0, int(x))
            except: return (1, x)
        for k in sorted(s.statusCounts.keys(), key=keyf):
            self.statusModel.addRow([k, s.statusCounts[k]])

        notes = []
        if s.leftoverPlaceholders:
            notes.append("Challenge 2: Placeholders still present after replacement:")
            for item in s.leftoverPlaceholders:
                notes.append("  - " + item)
        if s.missingReport:
            notes.append("\nChallenge 1: Parameters missing example values:")
            for k in sorted(s.missingReport.keys()):
                notes.append("  * %s :: %s" % (k, ", ".join(s.missingReport[k])))
        if s.optionalReport:
            notes.append("\nChallenge 1: Endpoints with optional parameters:")
            for k in sorted(s.optionalReport.keys()):
                notes.append("  * %s :: %s" % (k, ", ".join(s.optionalReport[k])))

        if s.failedEndpoints:
            notes.append("\nHealth Map: Non-200 / Errors:")
            for line in s.failedEndpoints[:500]:
                notes.append("  - " + line)

        self.notesArea.setText("\n".join(notes) if notes else "No notes.")

        lines = []
        lines.append("HEALTH MAP")
        lines.append("==========")
        lines.append("Total Tested : %d" % s.tested)
        lines.append("2xx OK       : %d" % s.ok2xx)
        fail = sum(v for k,v in s.statusCounts.items() if not (k.isdigit() and 200 <= int(k) < 300))
        lines.append("Non-2xx/Err  : %d" % fail)
        self.statusArea.setText("\n".join(lines))

class RowSelectListener(ListSelectionListener):
    def __init__(self, app): self.app = app
    def valueChanged(self, event):
        if event.getValueIsAdjusting(): return
        t = self.app.dashboardPanel.table; m = self.app.dashboardPanel.model
        v = t.getSelectedRow(); 
        if v < 0: return
        try:
            idx = t.convertRowIndexToModel(v); ep = m.get(idx)
            self.app.dashboardPanel.reqArea.setText(self.app._format_request_for_view(ep.reqRaw or ep.reqText))
            self.app.dashboardPanel.respArea.setText(self.app._format_response_for_view(ep.respRaw or ep.respText))
        except Exception as e:
            self.app.dashboardPanel.reqArea.setText("Error: " + str(e))
            self.app.dashboardPanel.respArea.setText("")

# =================== Burp entrypoint ===================

class BurpExtender(IBurpExtender, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._impl = _SwagValidatorImpl(callbacks)
    def getTabCaption(self):   return self._impl.getTabCaption()
    def getUiComponent(self):  return self._impl.getUiComponent()
