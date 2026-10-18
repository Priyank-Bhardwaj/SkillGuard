"""Native desktop UI. Workers never access Tk; reports contain no source snippets."""

import json
from queue import Empty, Queue
import sys
from threading import Event, Thread

from .batch import BatchReport, Selection, export_batch, scan_batch
from .discovery import absolute_path
from .rules import SEVERITIES
from .theme import COLORS, apply_theme

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
except ImportError:
    tk = None
    filedialog = messagebox = ttk = None


def display(value: str) -> str:
    """Escape controls/bidi characters in untrusted names, without interpreting markup."""
    return json.dumps(value, ensure_ascii=True)[1:-1]


def _worker(selections: list[Selection], excludes: bool, stop: Event, events: Queue) -> None:
    try:
        report = scan_batch(selections, use_default_excludes=excludes,
                            cancelled=stop.is_set,
                            progress=lambda message: events.put(("progress", message)))
        events.put(("done", report))
    except Exception as error:
        # Do not echo exception messages that might include hostile source content.
        events.put(("error", type(error).__name__))


class SkillGuardApp:
    def __init__(self, root):
        self.root = root
        self.selections: list[Selection] = []
        self.report: BatchReport | None = None
        self.events = Queue()
        self.stop = Event()
        self.busy = False
        self.finding_rows = {}
        self.root.title("SkillGuard — Skill & Agent Security Scanner")
        self.font_family = apply_theme(root)
        width = max(1120, min(1360, root.winfo_screenwidth() - 60))
        height = max(740, min(900, root.winfo_screenheight() - 100))
        self.root.geometry(f"{width}x{height}")
        self.root.minsize(1120, 740)
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.status = tk.StringVar(value="Choose files, a folder, or a project to begin.")
        self.summary = tk.StringVar(value="Choose your scan sources. Review risks before enabling a skill.")
        self.unit_summary = tk.StringVar(value="Select a scanned skill or agent to inspect its findings.")
        self.excludes = tk.BooleanVar(value=True)
        self.flagged_only = tk.BooleanVar(value=False)
        self.severity = tk.StringVar(value="ALL")
        self.queue_count = tk.StringVar(value="0 QUEUED")
        self.scan_state = tk.StringVar(value="READY TO SCAN")
        self.metric_values = {name: tk.StringVar(value="—") for name in (
            "Targets scanned", "Need review", "Total findings", "Files inspected")}
        self._build()
        self.poll_id = self.root.after(80, self._poll)

    @staticmethod
    def _tree(parent, columns, height):
        frame = ttk.Frame(parent, style="Card.TFrame")
        frame.pack(fill="both", expand=True)
        tree = ttk.Treeview(frame, columns=[c[0] for c in columns], show="headings", height=height)
        for key, label, width in columns:
            tree.heading(key, text=label)
            tree.column(key, width=width, minwidth=60, stretch=key in {"path", "title"})
        vertical = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        horizontal = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        tree.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        tree.tag_configure("alternate", background=COLORS["sidebar"])
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            tree.tag_configure(severity, foreground=COLORS[severity])
        return tree

    def _build(self):
        self.root.rowconfigure(0, weight=1)
        self.root.columnconfigure(1, weight=1)
        sidebar = ttk.Frame(self.root, style="Sidebar.TFrame", padding=20, width=280)
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_propagate(False)
        sidebar.pack_propagate(False)
        ttk.Label(sidebar, text="◈  SkillGuard", style="Brand.TLabel").pack(anchor="w", pady=(4, 4))
        ttk.Label(sidebar, text="SKILL & AGENT SECURITY", style="SidebarMuted.TLabel",
                  font=(self.font_family, 9, "bold")).pack(anchor="w", pady=(0, 28))
        ttk.Label(sidebar, text="ADD SCAN SOURCES", style="SidebarMuted.TLabel",
                  font=(self.font_family, 10, "bold")).pack(anchor="w", pady=(0, 12))
        self.edit_buttons = []
        for label, hint, action in (
            ("01   Browse files…", "Select one or more files", self.browse_files),
            ("02   Add skill / agent folder…", "Inspect a complete bundle", self.browse_folder),
            ("03   Discover in project…", "Automatically find skills & agents", self.browse_project),
        ):
            button = ttk.Button(sidebar, text=label, command=action, style="Source.TButton")
            button.pack(fill="x")
            self.edit_buttons.append(button)
            ttk.Label(sidebar, text=hint, style="SidebarMuted.TLabel",
                      font=(self.font_family, 10)).pack(anchor="w", padx=3, pady=(5, 14))

        # Reserve the bottom actions before allowing the queue to take remaining space.
        actions = ttk.Frame(sidebar, style="Sidebar.TFrame")
        actions.pack(side="bottom", fill="x")
        ttk.Label(actions, text="●  OFFLINE   /   READ-ONLY", style="SidebarMuted.TLabel",
                  font=(self.font_family, 9, "bold")).pack(side="bottom", pady=(14, 0))
        self.progress = ttk.Progressbar(actions, mode="indeterminate")
        self.progress.pack(side="bottom", fill="x", pady=(10, 0))
        self.scan_button = ttk.Button(actions, text="Scan queued items  →", command=self.start_scan,
                                      state="disabled", style="Primary.TButton")
        self.scan_button.pack(side="bottom", fill="x", pady=(8, 0))
        self.exclude_check = ttk.Checkbutton(actions, text="Exclude dependencies / caches",
                                             variable=self.excludes, style="Sidebar.TCheckbutton")
        self.exclude_check.pack(side="bottom", anchor="w")

        queue_area = ttk.Frame(sidebar, style="Sidebar.TFrame")
        queue_area.pack(fill="both", expand=True, pady=(6, 16))
        queue_header = ttk.Frame(queue_area, style="Sidebar.TFrame")
        queue_header.pack(fill="x", pady=(0, 10))
        ttk.Label(queue_header, text="Scan queue", style="Sidebar.TLabel",
                  font=(self.font_family, 12, "bold")).pack(side="left")
        ttk.Label(queue_header, textvariable=self.queue_count, style="SidebarMuted.TLabel",
                  font=(self.font_family, 9)).pack(side="right")
        queue_actions = ttk.Frame(queue_area, style="Sidebar.TFrame")
        queue_actions.pack(side="bottom", fill="x", pady=(8, 0))
        for label, action in (("Remove selected", self.remove_selected), ("Clear", self.clear_queue)):
            button = ttk.Button(queue_actions, text=label, command=action, style="Quiet.TButton")
            button.pack(side="left", padx=(0, 8))
            self.edit_buttons.append(button)
        queue_holder = ttk.Frame(queue_area, style="Card.TFrame")
        queue_holder.pack(fill="both", expand=True)
        self.queue_tree = self._tree(queue_holder, [("mode", "TYPE", 64), ("path", "SOURCE", 165)], 2)

        page = ttk.Frame(self.root, padding=(24, 22, 24, 16))
        page.grid(row=0, column=1, sticky="nsew")
        page.columnconfigure(0, weight=1)
        page.rowconfigure(3, weight=1)
        header = ttk.Frame(page)
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(0, weight=1)
        ttk.Label(header, text="SECURITY WORKSPACE", style="Eyebrow.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(header, text="Scan overview", style="Title.TLabel").grid(row=1, column=0, sticky="w", pady=(5, 0))
        header_actions = ttk.Frame(header)
        header_actions.grid(row=0, column=1, rowspan=2, sticky="e")
        self.cancel_button = ttk.Button(header_actions, text="Cancel scan", command=self.cancel_scan, state="disabled")
        self.cancel_button.pack(side="left", padx=(0, 8))
        self.export_button = ttk.Button(header_actions, text="Export JSON ↗", command=self.export, state="disabled")
        self.export_button.pack(side="left")
        self.summary_label = ttk.Label(header, textvariable=self.summary, style="Muted.TLabel", wraplength=720)
        self.summary_label.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(10, 0))

        metrics = ttk.Frame(page)
        metrics.grid(row=1, column=0, sticky="ew", pady=(20, 16))
        for column, (name, variable) in enumerate(self.metric_values.items()):
            metrics.columnconfigure(column, weight=1, uniform="metrics")
            card = ttk.Frame(metrics, style="Card.TFrame", padding=(16, 12))
            card.grid(row=0, column=column, sticky="nsew", padx=(0 if column == 0 else 10, 0))
            ttk.Label(card, text=name.upper(), style="CardMuted.TLabel",
                      font=(self.font_family, 9, "bold")).pack(anchor="w")
            variant = ("Accent.", "Warning.", "", "Teal.")[column]
            ttk.Label(card, textvariable=variable, style=f"{variant}Metric.TLabel").pack(anchor="w", pady=(4, 0))

        section = ttk.Frame(page)
        section.grid(row=2, column=0, sticky="ew", pady=(0, 12))
        ttk.Label(section, text="Review center", font=(self.font_family, 15, "bold")).pack(side="left")
        self.state_badge = ttk.Label(section, textvariable=self.scan_state, style="Pill.TLabel")
        self.state_badge.pack(side="right")

        self.review_panes = ttk.Panedwindow(page, orient="vertical")
        self.review_panes.grid(row=3, column=0, sticky="nsew")
        targets_card = ttk.Frame(self.review_panes, style="Card.TFrame", padding=12)
        self.review_panes.add(targets_card, weight=2)
        targets_header = ttk.Frame(targets_card, style="Card.TFrame")
        targets_header.pack(fill="x", pady=(0, 10))
        ttk.Label(targets_header, text="Targets", style="CardTitle.TLabel").pack(side="left")
        ttk.Checkbutton(targets_header, text="Only targets with findings", variable=self.flagged_only,
                        command=self._render_units).pack(side="right")
        target_holder = ttk.Frame(targets_card, style="Card.TFrame")
        target_holder.pack(fill="both", expand=True)
        self.units_tree = self._tree(target_holder, [
            ("path", "SKILL / AGENT", 300), ("status", "REVIEW STATUS", 165),
            ("severity", "SEVERITY", 105), ("count", "FINDINGS", 75), ("kind", "TYPE", 150),
        ], 3)
        self.units_tree.bind("<<TreeviewSelect>>", self._select_unit)
        self.units_tree.configure(selectmode="browse")
        self.empty_targets = ttk.Label(target_holder, text="Your scan results will appear here.\nAdd sources in the sidebar, then start a scan.",
                                       style="CardMuted.TLabel", justify="center", anchor="center", padding=16)
        self.empty_targets.place(relx=0.5, rely=0.62, anchor="center")

        self.detail_panes = ttk.Panedwindow(self.review_panes, orient="horizontal")
        self.review_panes.add(self.detail_panes, weight=3)
        findings_card = ttk.Frame(self.detail_panes, style="Card.TFrame", padding=12)
        self.detail_panes.add(findings_card, weight=1)
        finding_header = ttk.Frame(findings_card, style="Card.TFrame")
        finding_header.pack(fill="x", pady=(0, 8))
        ttk.Label(finding_header, text="Findings", style="CardTitle.TLabel").pack(side="left")
        severity_picker = ttk.Combobox(finding_header, textvariable=self.severity,
                                      values=("ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"),
                                      state="readonly", width=10)
        severity_picker.pack(side="right")
        severity_picker.bind("<<ComboboxSelected>>", self._select_unit)
        unit_label = ttk.Label(findings_card, textvariable=self.unit_summary, style="CardMuted.TLabel", wraplength=350)
        unit_label.pack(fill="x", pady=(0, 10))
        findings_card.bind("<Configure>", lambda event: unit_label.configure(wraplength=max(160, event.width - 28)))
        self.findings_tree = self._tree(findings_card, [
            ("severity", "SEVERITY", 95), ("title", "FINDING", 270),
            ("rule", "RULE", 75), ("path", "FILE : LINES", 320),
        ], 4)
        self.findings_tree.configure(selectmode="browse")
        self.findings_tree.bind("<<TreeviewSelect>>", self._select_finding)
        inspector = ttk.Frame(self.detail_panes, style="Card.TFrame", padding=12)
        self.detail_panes.add(inspector, weight=1)
        inspector_header = ttk.Frame(inspector, style="Card.TFrame")
        inspector_header.pack(fill="x", pady=(0, 10))
        ttk.Label(inspector_header, text="Inspection", style="CardTitle.TLabel").pack(side="left")
        self.finding_badge = ttk.Label(inspector_header, text="NO SELECTION", style="Pill.TLabel")
        self.finding_badge.pack(side="right")
        self.notebook = ttk.Notebook(inspector)
        self.notebook.pack(fill="both", expand=True)
        self.details = self._text_tab(self.notebook, "Explanation & action")
        self.coverage = self._text_tab(self.notebook, "Coverage & discovery")
        self._set_text(self.details, "Review with context\n\nSelect a target and a finding to understand the risk and recommended action.\n\nScanned instructions are never executed. Source snippets and secrets are not displayed.")
        self._set_text(self.coverage, "No scan yet. Project discovery is based on filenames and folder conventions, not a complete audit of the project.")
        footer = ttk.Frame(page)
        footer.grid(row=4, column=0, sticky="ew", pady=(12, 0))
        self.status_label = ttk.Label(footer, textvariable=self.status, style="Muted.TLabel", wraplength=800)
        self.status_label.pack(anchor="w", fill="x")
        ttk.Label(footer, text="No indicators ≠ safe. Review HIGH / CRITICAL findings before enabling a skill.",
                  style="Muted.TLabel", font=(self.font_family, 10)).pack(anchor="w", pady=(6, 0))
        page.bind("<Configure>", self._resize_content)
        self.root.after_idle(self._initial_sashes)

    def _resize_content(self, event):
        width = max(300, event.width - 48)
        self.summary_label.configure(wraplength=width)
        self.status_label.configure(wraplength=width)

    def _initial_sashes(self):
        self.review_panes.sashpos(0, max(160, int(self.review_panes.winfo_height() * 0.42)))
        self.detail_panes.sashpos(0, max(300, int(self.detail_panes.winfo_width() * 0.46)))

    def _text_tab(self, notebook, title):
        frame = ttk.Frame(notebook, style="Card.TFrame")
        notebook.add(frame, text=title)
        text = tk.Text(frame, height=6, width=28, wrap="word", font=(self.font_family, 11),
                       padx=14, pady=14, background=COLORS["surface"], foreground=COLORS["text"],
                       selectbackground=COLORS["selection"], selectforeground=COLORS["text"],
                       insertbackground=COLORS["text"], relief="flat", borderwidth=0,
                       highlightthickness=0, spacing1=3, spacing3=5)
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        text.pack(side="left", fill="both", expand=True)
        text.tag_configure("title", font=(self.font_family, 13, "bold"), spacing3=12)
        text.tag_configure("section", foreground=COLORS["accent"], font=(self.font_family, 10, "bold"), spacing1=14)
        text.tag_configure("metadata", foreground=COLORS["muted"], font=(self.font_family, 10))
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            text.tag_configure(severity, foreground=COLORS[severity])
        text.configure(state="disabled")
        return text

    @staticmethod
    def _set_text(widget, content):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", content)
        widget.tag_add("title", "1.0", "1.end")
        for index, line in enumerate(content.splitlines(), start=1):
            if line in {"WHY RISKY", "WHAT TO DO / WHEN TO REMOVE"}:
                widget.tag_add("section", f"{index}.0", f"{index}.end")
            elif line.startswith(("File:", "Category:", "Target:", "Default exclusions:")):
                widget.tag_add("metadata", f"{index}.0", f"{index}.end")
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if content.startswith(f"[{severity}]"):
                widget.tag_add(severity, "1.0", "1.end")
        widget.configure(state="disabled")

    def add_selection(self, path, mode):
        if self.busy:
            return
        selection = Selection(str(absolute_path(path)), mode)
        if selection not in self.selections:
            if len(self.selections) >= 128:
                messagebox.showwarning("Queue limit", "Use at most 128 selections per scan.", parent=self.root)
                return
            self.selections.append(selection)
            self._refresh_queue()

    def browse_files(self):
        for path in filedialog.askopenfilenames(parent=self.root, title="Select skill/agent files (multiple allowed)"):
            self.add_selection(path, "file")

    def browse_folder(self):
        path = filedialog.askdirectory(parent=self.root, title="Choose a skill or agent folder to scan recursively", mustexist=True)
        if path:
            self.add_selection(path, "folder")

    def browse_project(self):
        path = filedialog.askdirectory(parent=self.root, title="Choose a project to discover skills and agents", mustexist=True)
        if path:
            self.add_selection(path, "project")

    def remove_selected(self):
        indices = {int(i) for i in self.queue_tree.selection()}
        self.selections = [s for i, s in enumerate(self.selections) if i not in indices]
        self._refresh_queue()

    def clear_queue(self):
        self.selections.clear()
        self._refresh_queue()

    def _refresh_queue(self):
        self.queue_tree.delete(*self.queue_tree.get_children())
        for i, selection in enumerate(self.selections):
            self.queue_tree.insert("", "end", iid=str(i), values=(selection.mode.upper(), display(selection.path)),
                                   tags=("alternate",) if i % 2 else ())
        self.queue_count.set(f"{len(self.selections)} QUEUED")
        self.scan_button.configure(state="normal" if self.selections else "disabled")
        self.status.set("Queue updated. Press Scan queued items. Displayed results, if any, belong to the last scan.")

    def _set_busy(self, busy):
        self.busy = busy
        for button in [*self.edit_buttons, self.exclude_check]:
            button.configure(state="disabled" if busy else "normal")
        self.scan_button.configure(state="normal" if self.selections and not busy else "disabled")
        self.cancel_button.configure(state="normal" if busy else "disabled")
        self.export_button.configure(state="normal" if self.report is not None and not busy else "disabled")
        if busy:
            self.scan_button.configure(text="Scanning…")
            self.scan_state.set("SCANNING")
            self.state_badge.configure(style="Active.Pill.TLabel")
            self.progress.start(12)
        else:
            self.scan_button.configure(text="Scan queued items  →")
            self.progress.stop()

    def start_scan(self):
        if self.busy or not self.selections:
            return
        self.report = None
        self.stop = Event()
        for variable in self.metric_values.values():
            variable.set("—")
        self._render_units()
        self.empty_targets.configure(text="Inspecting your scan sources…\nResults will appear when the scan finishes.")
        self._set_text(self.coverage, "Scanning… coverage information will appear when finished or cancelled.")
        self.summary.set("Scanning queued items…")
        self.status.set("Starting scan…")
        self._set_busy(True)
        Thread(target=_worker, args=(list(self.selections), self.excludes.get(), self.stop, self.events), daemon=True).start()

    def cancel_scan(self):
        self.stop.set()
        self.cancel_button.configure(state="disabled")
        self.scan_state.set("CANCELLING")
        self.state_badge.configure(style="Warning.Pill.TLabel")
        self.status.set("Cancellation requested; the current bounded file read/analysis may finish first.")

    def _poll(self):
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "progress":
                    if not self.stop.is_set():
                        self.status.set(payload[:220])
                elif kind == "done":
                    self.report = payload
                    self._set_busy(False)
                    self._render_report()
                elif kind == "error":
                    self._set_busy(False)
                    self.scan_state.set("SCAN FAILED")
                    self.state_badge.configure(style="Warning.Pill.TLabel")
                    self.empty_targets.configure(text="The scan could not finish.\nNo complete results are available.")
                    self.summary.set("Scan failed — results unavailable; not a clean scan.")
                    self.status.set(f"Worker error ({payload}). Try a smaller selection and inspect filesystem access.")
                    self._set_text(self.coverage, "Scan failed. No complete report is available.")
        except Empty:
            pass
        self.poll_id = self.root.after(80, self._poll)

    def _render_report(self):
        summary = self.report.summary()
        for name, key in (("Targets scanned", "units_scanned"), ("Need review", "units_with_findings"),
                          ("Total findings", "findings"), ("Files inspected", "files_scanned")):
            self.metric_values[name].set(f"{summary[key]:,}")
        state = "CANCELLED" if self.report.cancelled else ("COMPLETE within scope" if self.report.complete else "INCOMPLETE")
        badge = state if not self.report.complete else (
            "REVIEW REQUIRED" if summary["findings"] else ("NO INDICATORS" if summary["files_scanned"] else "NO TEXT SCANNED"))
        self.scan_state.set(badge)
        self.state_badge.configure(style="Warning.Pill.TLabel" if not self.report.complete or summary["findings"] else "Pill.TLabel")
        self.summary.set(f"{state}  •  {summary['units_scanned']} targets  •  {summary['units_with_findings']} with findings  •  "
                         f"{summary['findings']} findings  •  {summary['files_scanned']} files scanned")
        self.status.set("Review each target and the Coverage & discovery tab. Export includes all results, even those hidden by filters.")
        self._render_units()
        lines = ["Discovery only recognizes documented conventions. Other project files are outside coverage.",
                 "Default exclusions (when enabled): .git, .venv, venv, __pycache__, node_modules.",
                 "Overlapping selections are merged; outer folders/bundles cover their nested files.", ""]
        for discovery in self.report.discoveries:
            lines.append(f"Project: {display(discovery.project)}\n  Candidates: {len(discovery.targets)}; entries examined: {discovery.entries_examined}; excluded directories: {discovery.excluded_directories}")
            if not discovery.targets:
                lines.append("  No supported skill/agent candidates found. This is NOT a clean-project verdict. Use Browse files or Add folder for custom layouts.")
        for unit in self.report.units:
            lines.append(f"Target: {display(unit.target.path)} — {unit.status}; text files: {unit.report.files_scanned}; excluded directories: {unit.report.excluded_directories}")
        issues = [*self.report.issues]
        issues.extend(issue for d in self.report.discoveries for issue in d.issues)
        issues.extend(issue for u in self.report.units for issue in u.report.issues)
        lines.append(f"\nCoverage issues: {len(issues)}")
        lines.extend(f"{display(i.path)}: {i.reason}" for i in issues[:500])
        if len(issues) > 500:
            lines.append("Only the first 500 issues are displayed; export JSON for all issues.")
        if self.report.cancelled:
            lines.append("Cancelled: unprocessed selections/files are not assessed.")
        self._set_text(self.coverage, "\n".join(lines))

    def _render_units(self):
        self.units_tree.delete(*self.units_tree.get_children())
        self.findings_tree.delete(*self.findings_tree.get_children())
        self.finding_rows.clear()
        self.finding_badge.configure(text="NO SELECTION", style="Pill.TLabel")
        self.unit_summary.set("Select a target to inspect findings.")
        self._set_text(self.details, "Select a target and then a finding to see its explanation and recommended action.")
        if self.report is None:
            self.empty_targets.configure(text="Your scan results will appear here.\nAdd sources in the sidebar, then start a scan.")
            self.empty_targets.place(relx=0.5, rely=0.62, anchor="center")
            return
        ordered = sorted(enumerate(self.report.units), key=lambda pair: (
            -SEVERITIES.get(pair[1].highest_severity, 0), pair[1].report.complete, pair[1].target.path))
        for index, unit in ordered:
            if self.flagged_only.get() and not unit.report.findings:
                continue
            self.units_tree.insert("", "end", iid=str(index), values=(
                display(unit.target.path), unit.status, unit.highest_severity, len(unit.report.findings), unit.target.kind),
                tags=(unit.highest_severity, "alternate") if index % 2 else (unit.highest_severity,))
        children = self.units_tree.get_children()
        if children:
            self.empty_targets.place_forget()
            self.units_tree.selection_set(children[0])
            self._select_unit()
        else:
            if self.report.units:
                message = "No targets match this filter.\nTurn off ‘Only targets with findings’ to see all results."
            elif not self.report.complete:
                message = "No targets were scanned.\nCoverage is incomplete — check Coverage & discovery."
            else:
                message = "No supported skills or agents were discovered.\nTry Browse files or Add skill / agent folder for custom layouts."
            self.empty_targets.configure(text=message)
            self.empty_targets.place(relx=0.5, rely=0.62, anchor="center")

    def _select_unit(self, _event=None):
        self.findings_tree.delete(*self.findings_tree.get_children())
        self.finding_rows.clear()
        self.finding_badge.configure(text="TARGET OVERVIEW", style="Pill.TLabel")
        selected = self.units_tree.selection()
        if not selected or self.report is None:
            return
        unit = self.report.units[int(selected[0])]
        findings = [f for f in unit.report.findings if self.severity.get() == "ALL" or f.severity == self.severity.get()]
        self.unit_summary.set(f"{unit.status} · {unit.report.files_scanned} files · showing {min(500, len(findings))}/{len(findings)} matching findings (export contains all)")
        for index, finding in enumerate(findings[:500]):
            iid = str(index)
            self.finding_rows[iid] = finding
            self.findings_tree.insert("", "end", iid=iid, values=(
                finding.severity, finding.title, finding.rule_id,
                f"{display(finding.file)}:{finding.line}-{finding.end_line}"),
                tags=(finding.severity, "alternate") if index % 2 else (finding.severity,))
        self._set_text(self.details, f"Target: {display(unit.target.path)}\nStatus: {unit.status}\n"
                       f"Coverage issues: {len(unit.report.issues)}\nDefault exclusions: {', '.join(unit.report.default_exclusions) or 'none'}\n\n"
                       "Select a finding for its explanation. No indicators does not prove safety; see Coverage & discovery for skipped files.")
        children = self.findings_tree.get_children()
        if children:
            self.findings_tree.selection_set(children[0])
            self._select_finding()

    def _select_finding(self, _event=None):
        selected = self.findings_tree.selection()
        if not selected or selected[0] not in self.finding_rows:
            return
        f = self.finding_rows[selected[0]]
        self.finding_badge.configure(text=f.severity, style=f"{f.severity}.Pill.TLabel")
        self._set_text(self.details, f"[{f.severity}] {f.rule_id} — {f.title}\n"
                       f"File: {display(f.file)}:{f.line}-{f.end_line}\n"
                       f"Category: {f.category} | Match confidence: {f.confidence}\n\n"
                       f"WHY RISKY\n{f.explanation}\n\nWHAT TO DO / WHEN TO REMOVE\n{f.recommendation}\n\n"
                       "A pattern match is not proof of malicious intent. Review the context before removing a skill.")

    def export(self):
        if self.report is None or self.busy:
            return
        path = filedialog.asksaveasfilename(parent=self.root, title="Export report to a NEW filename",
                                          defaultextension=".json", initialfile="skillguard-report.json",
                                          filetypes=[("JSON report", "*.json")])
        if not path:
            return
        try:
            export_batch(self.report, path)
        except OSError:
            messagebox.showerror("Export failed", "Use a new filename in a writable directory. Existing files will not be overwritten.", parent=self.root)
        else:
            self.status.set(f"Report saved: {display(path)}. Paths may be sensitive; share carefully.")

    def close(self):
        self.stop.set()
        self.root.after_cancel(self.poll_id)
        self.root.destroy()


def main() -> int:
    if tk is None:
        print("Tkinter is unavailable. For Homebrew Python, install the matching python-tk package "
              "(for Python 3.14: brew install python-tk@3.14). On Debian/Ubuntu: install python3-tk.", file=sys.stderr)
        return 2
    try:
        root = tk.Tk()
    except tk.TclError:
        print("Cannot open the desktop UI. Use a graphical desktop session with Tk support; the CLI remains available.", file=sys.stderr)
        return 2
    SkillGuardApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

