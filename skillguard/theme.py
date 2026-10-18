"""Shared desktop design tokens; importing this module does not require Tk."""

COLORS = {
    "background": "#0b1020", "sidebar": "#10182a", "surface": "#141e32",
    "raised": "#1c2942", "border": "#2a3955", "text": "#edf2fa",
    "muted": "#a1afc6", "subtle": "#788ba8", "accent": "#a5a0ff",
    "accent_hover": "#bcb8ff", "selection": "#354772", "teal": "#6ee7d0",
    "CRITICAL": "#ff8fa4", "HIGH": "#ffc18a", "MEDIUM": "#f4dc87",
    "LOW": "#90c9ff", "NONE": "#a1afc6",
}


def apply_theme(root):
    """Use a fully styled ttk theme instead of OS-dependent legacy widget chrome."""
    from tkinter import font, ttk

    available = set(font.families(root))
    family = next((name for name in ("SF Pro Text", "Helvetica Neue", "Segoe UI", "DejaVu Sans")
                   if name in available), "TkDefaultFont")
    for name in ("TkDefaultFont", "TkTextFont", "TkMenuFont", "TkHeadingFont"):
        font.nametofont(name, root=root).configure(family=family, size=11)
    c = COLORS
    style = ttk.Style(root)
    style.theme_use("clam")
    root.configure(background=c["background"])
    style.configure(".", background=c["background"], foreground=c["text"],
                    font=(family, 11), bordercolor=c["border"], focuscolor=c["accent"])
    for name, color in (("TFrame", c["background"]), ("Sidebar.TFrame", c["sidebar"]),
                        ("Card.TFrame", c["surface"]), ("Raised.TFrame", c["raised"])):
        style.configure(name, background=color)
    style.configure("Card.TFrame", borderwidth=1, relief="solid")
    style.configure("TLabel", background=c["background"], foreground=c["text"])
    style.configure("Title.TLabel", font=(family, 25, "bold"))
    style.configure("Eyebrow.TLabel", foreground=c["accent"], font=(family, 10, "bold"))
    style.configure("Muted.TLabel", foreground=c["muted"])
    style.configure("Sidebar.TLabel", background=c["sidebar"])
    style.configure("Brand.TLabel", background=c["sidebar"], font=(family, 20, "bold"))
    style.configure("SidebarMuted.TLabel", background=c["sidebar"], foreground=c["muted"])
    style.configure("Card.TLabel", background=c["surface"])
    style.configure("CardTitle.TLabel", background=c["surface"], font=(family, 12, "bold"))
    style.configure("CardMuted.TLabel", background=c["surface"], foreground=c["muted"])
    style.configure("Metric.TLabel", background=c["surface"], font=(family, 27, "bold"))
    for name, color in (("Accent", c["accent"]), ("Warning", c["HIGH"]), ("Teal", c["teal"])):
        style.configure(f"{name}.Metric.TLabel", foreground=color)
    style.configure("Pill.TLabel", background=c["raised"], foreground=c["muted"],
                    padding=(12, 6), font=(family, 10, "bold"))
    style.configure("Active.Pill.TLabel", foreground=c["accent"])
    style.configure("Warning.Pill.TLabel", foreground=c["HIGH"])
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        style.configure(f"{severity}.Pill.TLabel", foreground=c[severity])

    style.configure("TButton", background=c["raised"], foreground=c["text"],
                    padding=(14, 10), borderwidth=1, relief="flat", focusthickness=1)
    style.map("TButton", background=[("disabled", c["surface"]), ("active", c["border"])],
              foreground=[("disabled", c["subtle"])], bordercolor=[("focus", c["accent"])])
    style.configure("Primary.TButton", background=c["accent"], foreground=c["background"],
                    font=(family, 12, "bold"), padding=(16, 12), borderwidth=0)
    style.map("Primary.TButton", background=[("disabled", c["raised"]), ("active", c["accent_hover"])],
              foreground=[("disabled", c["subtle"]), ("!disabled", c["background"])])
    style.configure("Source.TButton", anchor="w", padding=(14, 12))
    style.configure("Quiet.TButton", background=c["sidebar"], foreground=c["muted"],
                    padding=(8, 6), borderwidth=0)
    style.configure("TCheckbutton", background=c["surface"], foreground=c["muted"],
                    padding=4, indicatorbackground=c["raised"], indicatorforeground=c["text"])
    style.map("TCheckbutton", background=[("active", c["surface"])],
              foreground=[("disabled", c["subtle"]), ("active", c["text"])],
              indicatorbackground=[("selected", c["accent"])])
    style.configure("Sidebar.TCheckbutton", background=c["sidebar"])
    style.map("Sidebar.TCheckbutton", background=[("active", c["sidebar"])])

    style.configure("Treeview", background=c["surface"], fieldbackground=c["surface"],
                    foreground=c["text"], rowheight=34, borderwidth=0, relief="flat")
    style.map("Treeview", background=[("selected", c["selection"])],
              foreground=[("selected", c["text"])])
    style.configure("Treeview.Heading", background=c["raised"], foreground=c["muted"],
                    padding=(10, 9), relief="flat", font=(family, 10, "bold"))
    style.map("Treeview.Heading", background=[("active", c["border"])])
    style.configure("TCombobox", fieldbackground=c["raised"], background=c["raised"],
                    foreground=c["text"], arrowcolor=c["muted"], padding=(10, 7), borderwidth=1)
    style.map("TCombobox", fieldbackground=[("readonly", c["raised"])],
              foreground=[("readonly", c["text"])], selectbackground=[("readonly", c["raised"])],
              selectforeground=[("readonly", c["text"])])
    root.option_add("*TCombobox*Listbox.background", c["raised"])
    root.option_add("*TCombobox*Listbox.foreground", c["text"])
    root.option_add("*TCombobox*Listbox.selectBackground", c["selection"])
    root.option_add("*TCombobox*Listbox.selectForeground", c["text"])
    for orientation in ("Vertical", "Horizontal"):
        style.configure(f"{orientation}.TScrollbar", background=c["border"],
                        troughcolor=c["surface"], arrowcolor=c["muted"], borderwidth=0,
                        arrowsize=11, relief="flat")
        style.map(f"{orientation}.TScrollbar", background=[("active", c["subtle"])])
    style.configure("TNotebook", background=c["surface"], borderwidth=0, tabmargins=(0, 0, 0, 0))
    style.configure("TNotebook.Tab", background=c["surface"], foreground=c["muted"],
                    padding=(16, 11), borderwidth=0)
    style.map("TNotebook.Tab", background=[("selected", c["raised"])],
              foreground=[("selected", c["accent"])])
    style.configure("Horizontal.TProgressbar", background=c["accent"], troughcolor=c["raised"],
                    borderwidth=0, thickness=3)
    style.configure("TPanedwindow", background=c["background"])
    style.configure("Sash", sashthickness=8, background=c["background"])
    style.configure("TSeparator", background=c["border"])
    return family
