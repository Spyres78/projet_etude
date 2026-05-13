#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MDOS — Multitool OSINT & Detection Operations System
Interface graphique Python (tkinter) — style terminal hacker vert/noir
Fusion complète : logique mdos.txt + design mdos_gui.html
"""

import tkinter as tk
from tkinter import font as tkfont
import subprocess
import threading
import datetime
import webbrowser
import json
import shlex
import socket
import getpass
import os
import sys
from pathlib import Path

# ══════════════════════════════════════════════════════════════════════
#  PALETTE COULEURS (calquée sur le CSS de la version HTML)
# ══════════════════════════════════════════════════════════════════════
C = {
    "bg":         "#020c06",
    "bg2":        "#040f0a",
    "panel":      "#050e08",
    "panel2":     "#071210",
    "border":     "#1a4a2a",
    "green":      "#00ff88",
    "green_dim":  "#00cc66",
    "text":       "#b8ffd8",
    "text_dim":   "#4a8a65",
    "red":        "#ff2255",
    "yellow":     "#ffcc00",
    "purple":     "#aa44ff",
    "cyan":       "#00ccff",
    "statusbar":  "#010d05",
    "entry_bg":   "#010a04",
    "term_bg":    "#010a04",
}

# ══════════════════════════════════════════════════════════════════════
#  CHEMINS RÉSULTATS
# ══════════════════════════════════════════════════════════════════════
RESULTS_DIR = Path.cwd() / "MDOS_RESULTS"
GLOBAL_JSON = RESULTS_DIR / "mdos_global.json"


def safe_mkdir(p: Path):
    p.mkdir(parents=True, exist_ok=True)


def now_iso():
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


def ts_filename():
    return datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def export_json(tool, category, target, command, rc, output):
    safe_mkdir(RESULTS_DIR / category)
    out_file = RESULTS_DIR / category / f"{tool}_{ts_filename()}.json"
    entry = {
        "tool": tool, "category": category, "target": target,
        "date": now_iso(), "user": getpass.getuser(),
        "host": socket.gethostname(), "command": command,
        "returncode": rc, "raw_output": output
    }
    out_file.write_text(json.dumps(entry, ensure_ascii=False, indent=2), encoding="utf-8")
    safe_mkdir(RESULTS_DIR)
    if not GLOBAL_JSON.exists():
        GLOBAL_JSON.write_text("[]", encoding="utf-8")
    data = json.loads(GLOBAL_JSON.read_text(encoding="utf-8"))
    data.append(entry)
    GLOBAL_JSON.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return out_file


# ══════════════════════════════════════════════════════════════════════
#  DONNÉES MENUS — fusion html + txt
# ══════════════════════════════════════════════════════════════════════
MENU_CARDS = [
    ("01", "network",    "Network Scan",                  "SCAN",  C["cyan"]),
    ("02", "footprint",  "Footprinting & Recon",          "RECON", C["purple"]),
    ("03", "enum",       "Enumeration",                   "ENUM",  C["purple"]),
    ("04", "vuln",       "Analyse Vulnérabilité",         "VULN",  C["red"]),
    ("05", "sniff",      "Sniffing",                      "SNIFF", C["yellow"]),
    ("06", "web",        "Hacking Web Servers",           "WEB",   C["green"]),
    ("07", "report",     "Rapport de session",            "",      C["green_dim"]),
    ("08", "quit",       "Quitter",                       "",      C["red"]),
]

SUBMENUS = {
    "network": {
        "title": "NETWORK SCAN",
        "desc":  "nmap · unicornscan · hping3 · sx",
        "items": [
            # ── Nmap ──
            {"label": "Nmap — Ports ouverts (IP)",      "badge": "TCP",   "cat": "scans",
             "fields": [("ip", "Adresse IP cible")],
             "cmd": lambda ip: f"nmap {shlex.quote(ip)} -p-"},
            {"label": "Nmap — Ports ouverts (Subnet)",  "badge": "CIDR",  "cat": "scans",
             "fields": [("subnet", "Sous-réseau (ex: 192.168.1.0/24)")],
             "cmd": lambda s: f"nmap {shlex.quote(s)} -p-"},
            {"label": "Nmap — Services",                "badge": "SV",    "cat": "scans",
             "fields": [("ip", "Adresse IP cible")],
             "cmd": lambda ip: f"nmap -sV {shlex.quote(ip)}"},
            {"label": "Nmap — OS Detection",            "badge": "OS",    "cat": "scans",
             "fields": [("ip", "Adresse IP cible")],
             "cmd": lambda ip: f"nmap -O {shlex.quote(ip)}"},
            {"label": "Nmap — Scan agressif",           "badge": "AGG",   "cat": "scans",
             "fields": [("ip", "Adresse IP cible")],
             "cmd": lambda ip: f"nmap -A {shlex.quote(ip)}"},
            # ── UnicornScan ──
            {"label": "UnicornScan — OS (TTL)",         "badge": "TTL",   "cat": "scans",
             "fields": [("ip", "Adresse IP cible")],
             "cmd": lambda ip: f"unicornscan {shlex.quote(ip)} -Iv",
             "hint": "Linux/FreeBSD=64  Windows=128  Cisco=255"},
            # ── SX ──
            {"label": "SX — Scan ARP réseau local",     "badge": "ARP",   "cat": "scans",
             "fields": [("target", "IP ou CIDR cible")],
             "cmd": lambda t: f"sx arp {shlex.quote(t)}"},
            # ── Hping3 ──
            {"label": "Hping3 — SYN Scan (0-100)",      "badge": "SYN",   "cat": "scans",
             "fields": [("ip", "Adresse IP cible")],
             "cmd": lambda ip: f"hping3 -8 0-100 -S {shlex.quote(ip)} -V"},
            {"label": "Hping3 — Port Range",            "badge": "RANGE", "cat": "scans",
             "fields": [("ip", "IP cible"), ("ports", "Range ports (ex: 0-65536)")],
             "cmd": lambda ip, ports: f"hping3 --scan {shlex.quote(ports)} -S {shlex.quote(ip)}"},
            {"label": "Hping3 — ICMP rand-dest",        "badge": "ICMP",  "cat": "scans",
             "fields": [("ip", "Adresse IP cible")],
             "cmd": lambda ip: f"hping3 -1 {shlex.quote(ip)} --rand-dest -I eth0"},
            {"label": "Hping3 — UDP test port 80",      "badge": "UDP",   "cat": "scans",
             "fields": [("ip", "Adresse IP cible")],
             "cmd": lambda ip: f"hping3 -2 {shlex.quote(ip)} -p 80 -c 5"},
        ]
    },

    "footprint": {
        "title": "FOOTPRINTING & RECON",
        "desc":  "theHarvester · sherlock · whois · cewl · domainfy",
        "items": [
            {"label": "theHarvester — Emails (Google)",  "badge": "EMAIL", "cat": "footprinting",
             "fields": [("target", "Nom de domaine cible")],
             "cmd": lambda t: f"theHarvester -d {shlex.quote(t)} -l 200 -b google"},
            {"label": "theHarvester — LinkedIn",         "badge": "LI",    "cat": "footprinting",
             "fields": [("target", "Nom de domaine cible")],
             "cmd": lambda t: f"theHarvester -d {shlex.quote(t)} -l 200 -b linkedin"},
            {"label": "Sherlock — Profils réseaux",      "badge": "OSINT", "cat": "footprinting",
             "fields": [("name", "Nom / Username cible")],
             "cmd": lambda n: f"python3 sherlock {shlex.quote(n)}"},
            {"label": "CEWL — Wordlist depuis site",     "badge": "WL",    "cat": "footprinting",
             "fields": [("site", "URL du site cible")],
             "cmd": lambda s: f"cewl -w wordlist.txt -d 2 -m 5 {shlex.quote(s)}"},
            {"label": "Traceroute",                      "badge": "TRACE", "cat": "footprinting",
             "fields": [("target", "IP ou domaine cible")],
             "cmd": lambda t: f"traceroute {shlex.quote(t)}"},
            {"label": "domainfy — Vérif domaines",       "badge": "DOM",   "cat": "footprinting",
             "fields": [("dom", "Nom de domaine")],
             "cmd": lambda d: f"domainfy -n {shlex.quote(d)} -t all"},
            {"label": "searchfy — Réseaux sociaux",      "badge": "SRCH",  "cat": "footprinting",
             "fields": [("name", "Nom cible")],
             "cmd": lambda n: f"searchfy -q {shlex.quote(n)}"},
            {"label": "mattw.io — YouTube Metadata",     "badge": "URL",   "cat": "footprinting",
             "fields": [],
             "cmd": lambda: "# Ouverture navigateur",
             "url": "https://mattw.io/youtube-metadata/"},
            {"label": "SearchFTPS — FTP public",         "badge": "URL",   "cat": "footprinting",
             "fields": [],
             "cmd": lambda: "# Ouverture navigateur",
             "url": "https://www.searchftps.net/"},
            {"label": "Censys — OS via IP",              "badge": "URL",   "cat": "footprinting",
             "fields": [],
             "cmd": lambda: "# Ouverture navigateur",
             "url": "https://search.censys.io/"},
            {"label": "DomainTools — Whois",             "badge": "URL",   "cat": "footprinting",
             "fields": [],
             "cmd": lambda: "# Ouverture navigateur",
             "url": "http://whois.domaintools.com"},
        ]
    },

    "enum": {
        "title": "ÉNUMÉRATION",
        "desc":  "NetBIOS · SNMP · LDAP · NFS · DNS · SMTP",
        "items": [
            {"label": "NetBIOS (nbstat NSE)",            "badge": "SMB",  "cat": "enumeration",
             "fields": [("ip", "IP cible")],
             "cmd": lambda ip: f"nmap -sV -v --script nbstat.nse {shlex.quote(ip)}"},
            {"label": "SNMP — snmp-check",               "badge": "SNMP", "cat": "enumeration",
             "fields": [("ip", "IP cible")],
             "cmd": lambda ip: f"snmp-check {shlex.quote(ip)}"},
            {"label": "SNMP — snmpwalk",                 "badge": "SNMP", "cat": "enumeration",
             "fields": [("ip", "IP cible")],
             "cmd": lambda ip: f"snmpwalk -v2c -c public {shlex.quote(ip)}"},
            {"label": "SNMP — nmap UDP processes",       "badge": "UDP",  "cat": "enumeration",
             "fields": [("ip", "IP cible"), ("port", "Port UDP")],
             "cmd": lambda ip, port: f"nmap -sU -p {shlex.quote(port)} --script=snmp-processes {shlex.quote(ip)}"},
            {"label": "LDAP — namingcontexts",           "badge": "LDAP", "cat": "enumeration",
             "fields": [("ip", "IP serveur LDAP")],
             "cmd": lambda ip: f"ldapsearch -h {shlex.quote(ip)} -x -s base namingcontexts"},
            {"label": "DNS — broadcast discovery",       "badge": "DNS",  "cat": "enumeration",
             "fields": [("dom", "Nom de domaine")],
             "cmd": lambda d: f"nmap --script=broadcast-dns-service-discovery {shlex.quote(d)}"},
            {"label": "DNS — brute force",               "badge": "DNS",  "cat": "enumeration",
             "fields": [("dom", "Nom de domaine")],
             "cmd": lambda d: f"nmap -T4 -p 53 --script dns-brute {shlex.quote(d)}"},
            {"label": "SMTP — enum-users",               "badge": "SMTP", "cat": "enumeration",
             "fields": [("ip", "IP serveur SMTP")],
             "cmd": lambda ip: f"nmap -p 25 --script=smtp-enum-users {shlex.quote(ip)}"},
            {"label": "SMTP — open-relay",               "badge": "SMTP", "cat": "enumeration",
             "fields": [("ip", "IP serveur SMTP")],
             "cmd": lambda ip: f"nmap -p 25 --script=smtp-open-relay {shlex.quote(ip)}"},
        ]
    },

    "vuln": {
        "title": "ANALYSE VULNÉRABILITÉ",
        "desc":  "Nikto · CWE · CVE · NVD",
        "items": [
            {"label": "Nikto — Web Scan",  "badge": "NIKTO", "cat": "vuln",
             "fields": [("site", "URL ou IP du serveur web")],
             "cmd": lambda s: f"nikto -h {shlex.quote(s)} -Tuning x"},
            {"label": "CWE — MITRE",       "badge": "URL",   "cat": "vuln",
             "fields": [], "cmd": lambda: "# https://cwe.mitre.org/",
             "url": "https://cwe.mitre.org/"},
            {"label": "CVE — MITRE",       "badge": "URL",   "cat": "vuln",
             "fields": [], "cmd": lambda: "# https://cve.mitre.org/",
             "url": "https://cve.mitre.org/"},
            {"label": "NVD — NIST",        "badge": "URL",   "cat": "vuln",
             "fields": [], "cmd": lambda: "# https://nvd.nist.gov/",
             "url": "https://nvd.nist.gov/"},
        ]
    },

    "sniff": {
        "title": "SNIFFING",
        "desc":  "macof · arpspoof · macchanger",
        "items": [
            {"label": "MAC Flooding (macof)",   "badge": "FLOOD", "cat": "sniffing",
             "fields": [("iface", "Interface (ex: eth0)"), ("nb", "Nombre de paquets")],
             "cmd": lambda i, n: f"macof -i {shlex.quote(i)} -n {shlex.quote(n)}"},
            {"label": "ARP Spoof (arpspoof)",   "badge": "ARP",   "cat": "sniffing",
             "fields": [("ip", "IP cible"), ("gw", "IP passerelle")],
             "cmd": lambda ip, gw: f"arpspoof -i eth0 -t {shlex.quote(gw)} {shlex.quote(ip)}",
             "hint": "Ctrl+C dans le terminal pour arrêter"},
            {"label": "MAC Spoof (macchanger)", "badge": "MAC",   "cat": "sniffing",
             "fields": [("iface", "Interface réseau")],
             "cmd": lambda i: f"sudo ifconfig {shlex.quote(i)} down && sudo macchanger -a {shlex.quote(i)} && sudo macchanger -r {shlex.quote(i)} && sudo ifconfig {shlex.quote(i)} up && ifconfig"},
        ]
    },

    "web": {
        "title": "HACKING WEB SERVERS",
        "desc":  "nmap http · uniscan · brute force",
        "items": [
            {"label": "Nmap — http-enum",       "badge": "HTTP",  "cat": "web",
             "fields": [("target", "Domaine ou IP")],
             "cmd": lambda t: f"nmap -sV --script=http-enum {shlex.quote(t)}"},
            {"label": "Nmap — hostmap-bfk",     "badge": "MAP",   "cat": "web",
             "fields": [("target", "Domaine ou IP")],
             "cmd": lambda t: f"nmap --script hostmap-bfk --script-args hostmap-bfk.prefix=hostmap- {shlex.quote(t)}"},
            {"label": "Nmap — http-trace",      "badge": "TRACE", "cat": "web",
             "fields": [("target", "Domaine ou IP")],
             "cmd": lambda t: f"nmap --script http-trace -d {shlex.quote(t)}"},
            {"label": "Nmap — WAF Detect",      "badge": "WAF",   "cat": "web",
             "fields": [("target", "Domaine ou IP")],
             "cmd": lambda t: f"nmap -p80 --script http-waf-detect {shlex.quote(t)}"},
            {"label": "Uniscan — Simple",       "badge": "UNI",   "cat": "web",
             "fields": [("target", "Domaine ou IP")],
             "cmd": lambda t: f"uniscan -u {shlex.quote(t)} -q"},
            {"label": "Uniscan — Dynamique",    "badge": "DYN",   "cat": "web",
             "fields": [("target", "Domaine ou IP")],
             "cmd": lambda t: f"uniscan -u {shlex.quote(t)} -d",
             "hint": "Scan long — peut durer plusieurs minutes"},
        ]
    },
}


# ══════════════════════════════════════════════════════════════════════
#  WIDGETS HELPERS
# ══════════════════════════════════════════════════════════════════════
def make_sep(parent, color=None, height=1, pady=0):
    f = tk.Frame(parent, bg=color or C["border"], height=height)
    f.pack(fill="x", pady=pady)
    return f


def green_btn(parent, text, cmd, width=None):
    kw = {"width": width} if width else {}
    b = tk.Button(parent, text=text, command=cmd,
                  fg=C["green"], bg=C["bg"],
                  activeforeground=C["bg"], activebackground=C["green"],
                  font=("Courier New", 10, "bold"),
                  relief="flat",
                  highlightbackground=C["green"], highlightthickness=1,
                  padx=18, pady=8, cursor="hand2", **kw)
    return b


def sec_btn(parent, text, cmd):
    b = tk.Button(parent, text=text, command=cmd,
                  fg=C["text_dim"], bg=C["bg"],
                  activeforeground=C["green_dim"], activebackground=C["bg2"],
                  font=("Courier New", 9),
                  relief="flat",
                  highlightbackground=C["border"], highlightthickness=1,
                  padx=14, pady=8, cursor="hand2")
    return b


def back_btn(parent, cmd):
    return tk.Button(parent, text="◀  RETOUR", command=cmd,
                     fg=C["text_dim"], bg=C["bg"],
                     activeforeground=C["green"], activebackground=C["bg"],
                     font=("Courier New", 9),
                     relief="flat",
                     highlightbackground=C["border"], highlightthickness=1,
                     padx=12, pady=6, cursor="hand2")


class LabelPanel(tk.Frame):
    """Panneau avec label flottant en haut à gauche (style CSS ::before)."""
    def __init__(self, parent, label_text, **kw):
        super().__init__(parent, bg=C["panel"],
                         highlightbackground=C["border"], highlightthickness=1, **kw)
        lbl = tk.Label(self, text=f" {label_text} ",
                       fg=C["green_dim"], bg=C["bg"],
                       font=("Courier New", 8))
        lbl.place(x=12, y=-9)

    def inner_pad(self):
        f = tk.Frame(self, bg=C["panel"])
        f.pack(fill="both", expand=True, padx=16, pady=(14, 14))
        return f


class ScrollableFrame(tk.Frame):
    """Frame scrollable verticalement."""
    def __init__(self, parent, **kw):
        super().__init__(parent, bg=C["bg"], **kw)
        canvas = tk.Canvas(self, bg=C["bg"], highlightthickness=0)
        sb = tk.Scrollbar(self, orient="vertical", command=canvas.yview,
                          bg=C["bg2"], troughcolor=C["bg"])
        self.inner = tk.Frame(canvas, bg=C["bg"])
        self.inner.bind("<Configure>",
                        lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=self.inner, anchor="nw")
        canvas.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        # mousewheel
        canvas.bind_all("<MouseWheel>",
                        lambda e: canvas.yview_scroll(int(-1*(e.delta/120)), "units"))


# ══════════════════════════════════════════════════════════════════════
#  APPLICATION PRINCIPALE
# ══════════════════════════════════════════════════════════════════════
class MDOSApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("MDOS — Access Terminal  v2.0.0")
        self.root.configure(bg=C["bg"])
        self.root.geometry("1020x740")
        self.root.minsize(880, 620)

        self.pseudo      = ""
        self.session_log = []
        self.field_vars  = []
        self.current_item = None
        self.current_key  = None

        self._build_statusbar()
        self._build_screens()
        self._tick()

    # ──────────────────────────────────────────────
    #  STATUSBAR
    # ──────────────────────────────────────────────
    def _build_statusbar(self):
        bar = tk.Frame(self.root, bg=C["statusbar"], height=28)
        bar.pack(fill="x", side="top")
        bar.pack_propagate(False)

        left = tk.Frame(bar, bg=C["statusbar"])
        left.pack(side="left", padx=12)
        self._dot_canvas = tk.Canvas(left, width=8, height=8,
                                     bg=C["statusbar"], highlightthickness=0)
        self._dot_canvas.pack(side="left", padx=(0, 6))
        self._dot_id = self._dot_canvas.create_oval(1, 1, 7, 7,
                                                     fill=C["green"], outline="")
        self._blink_dot()
        tk.Label(left,
                 text="MDOS SYSTEM ONLINE  |  v2.0.0  |  SECURE CHANNEL",
                 fg=C["text_dim"], bg=C["statusbar"],
                 font=("Courier New", 8)).pack(side="left")

        right = tk.Frame(bar, bg=C["statusbar"])
        right.pack(side="right", padx=12)
        self._clock_var  = tk.StringVar(value="--:--:--")
        self._status_var = tk.StringVar(value="NOT_AUTH")
        tk.Label(right, textvariable=self._clock_var,
                 fg=C["green"], bg=C["statusbar"],
                 font=("Courier New", 8)).pack(side="right", padx=(12, 0))
        tk.Label(right, textvariable=self._status_var,
                 fg=C["text_dim"], bg=C["statusbar"],
                 font=("Courier New", 8)).pack(side="right")

    def _blink_dot(self):
        cur = self._dot_canvas.itemcget(self._dot_id, "fill")
        nxt = C["green"] if cur != C["green"] else C["bg"]
        self._dot_canvas.itemconfig(self._dot_id, fill=nxt)
        self.root.after(900, self._blink_dot)

    def _tick(self):
        self._clock_var.set(datetime.datetime.now().strftime("%H:%M:%S  %d/%m/%Y"))
        self.root.after(1000, self._tick)

    # ──────────────────────────────────────────────
    #  ÉCRANS
    # ──────────────────────────────────────────────
    def _build_screens(self):
        self._container = tk.Frame(self.root, bg=C["bg"])
        self._container.pack(fill="both", expand=True, padx=24, pady=(38, 10))

        self._screens = {}
        for name in ("login", "menu", "submenu", "cmd", "report"):
            f = tk.Frame(self._container, bg=C["bg"])
            self._screens[name] = f
            f.place(relx=0, rely=0, relwidth=1, relheight=1)

        self._build_login()
        self._build_menu()
        self._build_submenu()
        self._build_cmd()
        self._build_report()
        self._show("login")

    def _show(self, name):
        for f in self._screens.values():
            f.lower()
        self._screens[name].lift()

    # ──────────────────────────────────────────────
    #  NOTIFICATIONS
    # ──────────────────────────────────────────────
    def _notify(self, msg, error=False):
        color = C["red"] if error else C["green"]
        n = tk.Label(self.root, text=msg,
                     fg=color, bg=C["statusbar"],
                     font=("Courier New", 9),
                     highlightbackground=color, highlightthickness=1,
                     padx=12, pady=8)
        n.place(relx=1.0, rely=1.0, anchor="se", x=-18, y=-18)
        self.root.after(3400, n.destroy)

    # ══════════════════════════════════════════════
    #  ÉCRAN LOGIN
    # ══════════════════════════════════════════════
    def _build_login(self):
        f = self._screens["login"]
        wrap = tk.Frame(f, bg=C["bg"])
        wrap.place(relx=0.5, rely=0.5, anchor="center")

        ASCII = (
            "⠀⠀⠀⠀⠀⢸⠓⢄⡀⠀⠀⠀⠀⠀⠀⠀\n"
            "⠀⠀⠀⠀⠀⢸⠀⠀⠑⢤⡀⠀⠀⠀⠀⠀\n"
            "⠀⠀⠀⠀⠀⢸⡆⠀⠀⠀⠙⢤⡷⣤⣦⣀\n"
            "⣠⡿⠢⢄⡀⠀⡇⠀⠀⠀⠀⠀⠉⠀⠀⠀\n"
            "⢸⣃⠀⠀⠉⠳⣷⠞⠁⠀⠀⠀⠀⠀⠀⠀\n"
            "⠀⠘⣆⠀⠀⠀⠁⠀⢀⡄⠀⠀⠀⠀⠀⠀\n"
            "⠀⠀⠘⣦⠆⠀⠀⢀⡎⢹⡀⠀⠀⠀⠀⠀"
        )
        tk.Label(wrap, text=ASCII, fg=C["green_dim"], bg=C["bg"],
                 font=("Courier New", 10), justify="center").pack()

        tk.Label(wrap, text="MDOS", fg=C["green"], bg=C["bg"],
                 font=("Courier New", 32, "bold"), pady=4).pack()

        tk.Label(wrap,
                 text="Multitool OSINT & Detection Operations System",
                 fg=C["text_dim"], bg=C["bg"],
                 font=("Courier New", 8)).pack(pady=(0, 22))

        # ── Box login ──
        box = tk.Frame(wrap, bg=C["panel"],
                       highlightbackground=C["border"], highlightthickness=1)
        box.pack(ipadx=0, ipady=0)

        inner = tk.Frame(box, bg=C["panel"])
        inner.pack(padx=32, pady=24, fill="x")

        # Pseudo
        tk.Label(inner, text="// IDENTIFIANT",
                 fg=C["text_dim"], bg=C["panel"],
                 font=("Courier New", 8), anchor="w").pack(anchor="w", pady=(0, 4))
        self._inp_pseudo = tk.Entry(inner,
                                    bg=C["entry_bg"], fg=C["green"],
                                    insertbackground=C["green"],
                                    font=("Courier New", 13),
                                    relief="flat",
                                    highlightbackground=C["green_dim"],
                                    highlightthickness=1, width=30)
        self._inp_pseudo.pack(fill="x", pady=(0, 14))

        # TOTP
        tk.Label(inner, text="// TOTP CODE (Google Authenticator)",
                 fg=C["text_dim"], bg=C["panel"],
                 font=("Courier New", 8), anchor="w").pack(anchor="w", pady=(0, 4))
        self._inp_totp = tk.Entry(inner,
                                   bg=C["entry_bg"], fg=C["green"],
                                   insertbackground=C["green"],
                                   font=("Courier New", 20, "bold"),
                                   justify="center",
                                   relief="flat",
                                   highlightbackground=C["green_dim"],
                                   highlightthickness=1, width=30)
        self._inp_totp.pack(fill="x", pady=(0, 4))
        self._inp_totp.bind("<Return>", lambda e: self._do_login())

        # Barre de progression
        self._pbar_wrap = tk.Frame(inner, bg=C["border"], height=2)
        self._pbar_wrap.pack(fill="x", pady=(4, 4))
        self._pbar_fill = tk.Frame(self._pbar_wrap, bg=C["green"], width=0, height=2)
        self._pbar_fill.pack(side="left")

        self._login_err = tk.Label(inner, text="", fg=C["red"], bg=C["panel"],
                                    font=("Courier New", 9), pady=2)
        self._login_err.pack()

        green_btn(inner, "▶   ACCESS_GRANT", self._do_login).pack(
            fill="x", pady=(8, 0))

    def _do_login(self):
        p = self._inp_pseudo.get().strip()
        t = self._inp_totp.get().strip()

        if not p:
            self._login_err.config(text="⚠  PSEUDO REQUIS"); return
        if len(t) != 6 or not t.isdigit():
            self._login_err.config(
                text="⚠  CODE TOTP INVALIDE — 6 chiffres requis"); return

        self._login_err.config(text="")

        # Vérification TOTP réelle (pyotp si dispo, sinon on accepte)
        def verify():
            ok = False
            try:
                auth_file = Path.home() / ".google_authenticator"
                if auth_file.exists():
                    import pyotp  # type: ignore
                    secret = auth_file.read_text(
                        encoding="utf-8", errors="ignore"
                    ).splitlines()[0].strip().replace(" ", "")
                    ok = pyotp.TOTP(secret).verify(t, valid_window=1)
                else:
                    ok = True   # pas de fichier 2FA → on passe
            except Exception:
                ok = True       # pyotp absent → on passe
            self.root.after(0, lambda: self._after_verify(p, ok))

        self._animate_pbar(0, done_cb=lambda: threading.Thread(
            target=verify, daemon=True).start())

    def _animate_pbar(self, step=0, done_cb=None):
        total = 28
        if step > total:
            self._pbar_fill.config(width=0)
            if done_cb:
                done_cb()
            return
        w = int((self._pbar_wrap.winfo_width() or 300) * step / total)
        self._pbar_fill.config(width=max(w, 0))
        self.root.after(35, lambda: self._animate_pbar(step + 1, done_cb))

    def _after_verify(self, pseudo, ok):
        if not ok:
            self._login_err.config(text="⛔  CODE INVALIDE — ACCÈS REFUSÉ")
            return

        self.pseudo = pseudo
        self._status_var.set(pseudo.upper())
        self._menu_user_lbl.config(text=pseudo.upper())
        now = datetime.datetime.now().strftime("%H:%M:%S")
        self._menu_info_lbl.config(
            text=f"HOST: {pseudo.lower()}-machine\n"
                 f"RESULTS: ./MDOS_RESULTS/\n"
                 f"SESSION: {now}")
        self._notify(f"✅  Authentification réussie. Bienvenue {pseudo} !")
        self._show("menu")

    # ══════════════════════════════════════════════
    #  ÉCRAN MENU PRINCIPAL
    # ══════════════════════════════════════════════
    def _build_menu(self):
        f = self._screens["menu"]

        hdr = tk.Frame(f, bg=C["bg"])
        hdr.pack(fill="x", pady=(0, 10))

        left = tk.Frame(hdr, bg=C["bg"])
        left.pack(side="left")
        tk.Label(left, text="// Session active",
                 fg=C["text_dim"], bg=C["bg"],
                 font=("Courier New", 8)).pack(anchor="w")
        self._menu_user_lbl = tk.Label(left, text="",
                                        fg=C["green"], bg=C["bg"],
                                        font=("Courier New", 20, "bold"))
        self._menu_user_lbl.pack(anchor="w")

        self._menu_info_lbl = tk.Label(hdr, text="",
                                        fg=C["text_dim"], bg=C["bg"],
                                        font=("Courier New", 8),
                                        justify="right")
        self._menu_info_lbl.pack(side="right", anchor="ne")

        make_sep(f, pady=(0, 12))

        grid = tk.Frame(f, bg=C["bg"])
        grid.pack(fill="both", expand=True)
        grid.columnconfigure(0, weight=1)
        grid.columnconfigure(1, weight=1)

        for idx, (num, key, title, tag, color) in enumerate(MENU_CARDS):
            row, col = divmod(idx, 2)
            card = self._make_card(grid, num, key, title, tag, color)
            card.grid(row=row, column=col, sticky="ew", padx=5, pady=5)

    def _make_card(self, parent, num, key, title, tag, color):
        is_quit  = (key == "quit")
        bdr_norm = C["border"] if not is_quit else "#3a0a15"
        bg_hover = "#0d2017" if not is_quit else "#1a0a10"
        bdr_hov  = C["green_dim"] if not is_quit else C["red"]

        outer = tk.Frame(parent, bg=C["panel"],
                         highlightbackground=bdr_norm, highlightthickness=1,
                         cursor="hand2")
        inner = tk.Frame(outer, bg=C["panel"], pady=13, padx=16)
        inner.pack(fill="both", expand=True)

        num_lbl = tk.Label(inner,
                           text=num,
                           fg=C["green_dim"] if not is_quit else "#7a1530",
                           bg=C["panel"],
                           font=("Courier New", 15, "bold"), width=3)
        num_lbl.pack(side="left", anchor="center")

        txt = tk.Frame(inner, bg=C["panel"])
        txt.pack(side="left", fill="both", expand=True)

        row1 = tk.Frame(txt, bg=C["panel"])
        row1.pack(anchor="w")
        title_lbl = tk.Label(row1, text=title.upper(),
                              fg=C["text"], bg=C["panel"],
                              font=("Courier New", 11, "bold"))
        title_lbl.pack(side="left")
        if tag:
            tk.Label(row1, text=f" [{tag}]",
                     fg=color, bg=C["panel"],
                     font=("Courier New", 8)).pack(side="left")

        if key in SUBMENUS:
            tk.Label(txt, text=SUBMENUS[key]["desc"],
                     fg=C["text_dim"], bg=C["panel"],
                     font=("Courier New", 8)).pack(anchor="w")

        arr = tk.Label(inner,
                       text="▶" if not is_quit else "✕",
                       fg=C["text_dim"] if not is_quit else C["red"],
                       bg=C["panel"], font=("Courier New", 11))
        arr.pack(side="right", anchor="center")

        # Hover
        all_w = [outer, inner, txt, row1, num_lbl, title_lbl, arr]
        for lbl in row1.winfo_children():
            all_w.append(lbl)

        def on_enter(e):
            outer.config(highlightbackground=bdr_hov)
            for w in all_w:
                try: w.config(bg=bg_hover)
                except Exception: pass
        def on_leave(e):
            outer.config(highlightbackground=bdr_norm)
            for w in all_w:
                try: w.config(bg=C["panel"])
                except Exception: pass

        for w in all_w + [outer]:
            w.bind("<Enter>", on_enter)
            w.bind("<Leave>", on_leave)
            w.bind("<Button-1>", lambda e, k=key: self._card_click(k))

        return outer

    def _card_click(self, key):
        if key == "quit":
            self._do_quit()
        elif key == "report":
            self._show_report()
        else:
            self._load_submenu(key)

    # ══════════════════════════════════════════════
    #  ÉCRAN SOUS-MENU
    # ══════════════════════════════════════════════
    def _build_submenu(self):
        f = self._screens["submenu"]

        hdr = tk.Frame(f, bg=C["bg"])
        hdr.pack(fill="x", pady=(0, 10))
        back_btn(hdr, self._back_to_menu).pack(side="left")
        self._sub_title = tk.Label(hdr, text="TOOLS",
                                   fg=C["green"], bg=C["bg"],
                                   font=("Courier New", 13, "bold"), padx=14)
        self._sub_title.pack(side="left")

        make_sep(f, pady=(0, 8))

        sf = ScrollableFrame(f)
        sf.pack(fill="both", expand=True)
        self._sub_inner = sf.inner

    def _load_submenu(self, key):
        self.current_key = key
        cfg = SUBMENUS[key]
        self._sub_title.config(text=cfg["title"])

        for w in self._sub_inner.winfo_children():
            w.destroy()

        for idx, item in enumerate(cfg["items"]):
            bdr_norm = C["border"]
            row = tk.Frame(self._sub_inner, bg=C["panel"],
                           highlightbackground=bdr_norm, highlightthickness=1,
                           cursor="hand2")
            row.pack(fill="x", pady=4, padx=2)

            inner = tk.Frame(row, bg=C["panel"], pady=11, padx=16)
            inner.pack(fill="x")

            tk.Label(inner, text=f"{idx+1:02d}",
                     fg=C["green_dim"], bg=C["panel"],
                     font=("Courier New", 9, "bold"), width=3).pack(side="left")
            tk.Label(inner, text=item["label"].upper(),
                     fg=C["text"], bg=C["panel"],
                     font=("Courier New", 10, "bold"),
                     anchor="w").pack(side="left", fill="x", expand=True)
            tk.Label(inner, text=item["badge"],
                     fg=C["text_dim"], bg=C["panel"],
                     font=("Courier New", 8),
                     highlightbackground=C["border"], highlightthickness=1,
                     padx=6, pady=2).pack(side="right")

            all_w = [row, inner] + list(inner.winfo_children())

            def on_enter(e, r=row, i=inner):
                r.config(highlightbackground=C["green_dim"])
                for w in [r, i] + list(i.winfo_children()):
                    try: w.config(bg="#0d2017")
                    except Exception: pass
            def on_leave(e, r=row, i=inner):
                r.config(highlightbackground=C["border"])
                for w in [r, i] + list(i.winfo_children()):
                    try: w.config(bg=C["panel"])
                    except Exception: pass

            for w in all_w:
                w.bind("<Enter>", on_enter)
                w.bind("<Leave>", on_leave)
                w.bind("<Button-1>", lambda e, k=key, n=idx: self._open_cmd(k, n))

        self._show("submenu")

    def _back_to_menu(self):
        self._show("menu")

    # ══════════════════════════════════════════════
    #  ÉCRAN COMMANDE
    # ══════════════════════════════════════════════
    def _build_cmd(self):
        f = self._screens["cmd"]

        hdr = tk.Frame(f, bg=C["bg"])
        hdr.pack(fill="x", pady=(0, 10))
        back_btn(hdr, self._back_to_sub).pack(side="left")
        self._cmd_title = tk.Label(hdr, text="EXECUTE",
                                   fg=C["green"], bg=C["bg"],
                                   font=("Courier New", 13, "bold"), padx=14)
        self._cmd_title.pack(side="left")

        make_sep(f, pady=(0, 8))

        sf = ScrollableFrame(f)
        sf.pack(fill="both", expand=True)
        self._cmd_inner = sf.inner
        self._cmd_inner.columnconfigure(0, weight=1)

    def _open_cmd(self, key, idx):
        self.current_key  = key
        self.current_item = SUBMENUS[key]["items"][idx]
        item = self.current_item
        self._cmd_title.config(text=item["label"].upper())
        self.field_vars = []

        for w in self._cmd_inner.winfo_children():
            w.destroy()

        # ── Panneau champs ──
        if item.get("fields"):
            panel = LabelPanel(self._cmd_inner, "INPUT_PARAMS")
            panel.pack(fill="x", pady=(4, 12), padx=2)
            ip = panel.inner_pad()

            for fid, flabel in item["fields"]:
                tk.Label(ip, text=f"// {flabel.upper()}",
                         fg=C["text_dim"], bg=C["panel"],
                         font=("Courier New", 8),
                         anchor="w").pack(anchor="w", pady=(4, 2))
                var = tk.StringVar()
                var.trace_add("write", lambda *a: self._refresh_preview())
                self.field_vars.append(var)
                e = tk.Entry(ip, textvariable=var,
                             bg=C["entry_bg"], fg=C["green"],
                             insertbackground=C["green"],
                             font=("Courier New", 12),
                             relief="flat",
                             highlightbackground=C["border"],
                             highlightthickness=1)
                e.pack(fill="x", pady=(0, 4))

            if item.get("hint"):
                tk.Label(ip, text=f"⚠  {item['hint']}",
                         fg=C["yellow"], bg=C["panel"],
                         font=("Courier New", 8)).pack(anchor="w", pady=(4, 0))

        # ── Panneau preview ──
        prev_panel = LabelPanel(self._cmd_inner, "CMD_PREVIEW")
        prev_panel.pack(fill="x", pady=(0, 10), padx=2)
        pp = prev_panel.inner_pad()

        tk.Label(pp, text="// Commande générée",
                 fg=C["text_dim"], bg=C["panel"],
                 font=("Courier New", 8)).pack(anchor="w", pady=(0, 4))

        self._preview_lbl = tk.Label(pp, text="—",
                                     fg=C["cyan"], bg=C["entry_bg"],
                                     font=("Courier New", 11),
                                     wraplength=780, justify="left",
                                     anchor="w",
                                     highlightbackground=C["border"],
                                     highlightthickness=1,
                                     padx=12, pady=9)
        self._preview_lbl.pack(fill="x", pady=(0, 10))

        btns = tk.Frame(pp, bg=C["panel"])
        btns.pack(anchor="w")
        green_btn(btns, "▶   EXÉCUTER", self._execute).pack(side="left")
        sec_btn(btns,   "⎘  COPIER",    self._copy_cmd).pack(side="left", padx=(10, 0))

        # ── Terminal output ──
        term_panel = LabelPanel(self._cmd_inner, "OUTPUT")
        term_panel.pack(fill="x", pady=(0, 8), padx=2)
        tp = term_panel.inner_pad()

        self._terminal = tk.Text(tp, bg=C["term_bg"], fg=C["green_dim"],
                                 font=("Courier New", 10),
                                 insertbackground=C["green"],
                                 relief="flat", height=16,
                                 wrap="word", state="disabled",
                                 highlightthickness=0)
        self._terminal.pack(fill="both")
        self._terminal.tag_config("success", foreground=C["green"])
        self._terminal.tag_config("error",   foreground=C["red"])
        self._terminal.tag_config("warn",    foreground=C["yellow"])
        self._terminal.tag_config("info",    foreground=C["cyan"])

        self._term_clear()
        self._refresh_preview()
        self._show("cmd")

    def _refresh_preview(self):
        item = self.current_item
        if not item:
            return
        vals = [v.get().strip() for v in self.field_vars]
        try:
            if not item.get("fields"):
                cmd = item["cmd"]()
            elif all(vals):
                cmd = item["cmd"](*vals)
            else:
                ph = [vals[i] if vals[i] else f"<{item['fields'][i][0]}>"
                      for i in range(len(item["fields"]))]
                cmd = item["cmd"](*ph)
        except Exception:
            cmd = "— erreur de génération —"
        self._preview_lbl.config(text=cmd)

    def _build_cmd_str(self):
        item = self.current_item
        if not item:
            return None
        vals = [v.get().strip() for v in self.field_vars]
        if item.get("fields") and not all(vals):
            return None
        try:
            return item["cmd"](*vals) if item.get("fields") else item["cmd"]()
        except Exception:
            return None

    def _copy_cmd(self):
        cmd = self._preview_lbl.cget("text")
        try:
            import pyperclip  # type: ignore
            pyperclip.copy(cmd)
            self._notify("⎘  Commande copiée dans le presse-papier")
        except Exception:
            self.root.clipboard_clear()
            self.root.clipboard_append(cmd)
            self._notify("⎘  Commande copiée (clipboard)")

    def _execute(self):
        item = self.current_item
        vals = [v.get().strip() for v in self.field_vars]

        if item.get("fields") and not all(vals):
            self._notify("⚠  Tous les champs sont requis", error=True)
            return

        # URL → navigateur
        if item.get("url"):
            webbrowser.open(item["url"])
            self._term_add(f"▶ Ouverture navigateur : {item['url']}", "info")
            export_json(item["label"], item.get("cat", "misc"),
                        item["url"], item["cmd"](), 0, "Opened in browser")
            self.session_log.append({
                "tool": item["label"], "cat": item.get("cat", "misc"),
                "target": item["url"], "cmd": item["cmd"](),
                "rc": 0, "time": datetime.datetime.now().strftime("%H:%M:%S")
            })
            return

        cmd = self._build_cmd_str()
        if not cmd:
            return

        self._term_clear()
        self._term_add(f"$ {cmd}", "info")
        self._term_add("")

        def run():
            try:
                proc = subprocess.Popen(
                    cmd, shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True
                )
                full_output = []
                for line in proc.stdout:
                    line = line.rstrip()
                    full_output.append(line)
                    tag = ("success" if line.startswith(("[+]", "✅"))
                           else "error" if line.startswith(("[-]", "ERR"))
                           else "warn"  if line.startswith(("[*]", "[!]"))
                           else "")
                    self.root.after(0, lambda l=line, t=tag: self._term_add(l, t))
                rc = proc.wait()
                output_str = "\n".join(full_output)

                # Export JSON
                out_file = export_json(
                    cmd.split()[0], item.get("cat", "misc"),
                    vals[0] if vals else "—", cmd, rc, output_str
                )
                self.session_log.append({
                    "tool": item["label"], "cat": item.get("cat", "misc"),
                    "target": vals[0] if vals else "—", "cmd": cmd,
                    "rc": rc, "time": datetime.datetime.now().strftime("%H:%M:%S")
                })
                msg1 = f"✅ Export JSON: {out_file}"
                msg2 = f"✅ Global JSON: {GLOBAL_JSON}"
                self.root.after(0, lambda: self._term_add("", ""))
                self.root.after(0, lambda: self._term_add(msg1, "success"))
                self.root.after(0, lambda: self._term_add(msg2, "success"))
            except Exception as ex:
                self.root.after(0, lambda: self._term_add(f"ERREUR: {ex}", "error"))

        threading.Thread(target=run, daemon=True).start()

    def _term_clear(self):
        self._terminal.config(state="normal")
        self._terminal.delete("1.0", "end")
        self._terminal.insert("end", "▶ OUTPUT\n" + "─" * 70 + "\n", "")
        self._terminal.config(state="disabled")

    def _term_add(self, text, tag=""):
        self._terminal.config(state="normal")
        self._terminal.insert("end", text + "\n", tag)
        self._terminal.see("end")
        self._terminal.config(state="disabled")

    def _back_to_sub(self):
        if self.current_key:
            self._load_submenu(self.current_key)

    # ══════════════════════════════════════════════
    #  ÉCRAN RAPPORT
    # ══════════════════════════════════════════════
    def _build_report(self):
        f = self._screens["report"]

        hdr = tk.Frame(f, bg=C["bg"])
        hdr.pack(fill="x", pady=(0, 10))
        back_btn(hdr, lambda: self._show("menu")).pack(side="left")
        tk.Label(hdr, text="RAPPORT DE SESSION",
                 fg=C["green"], bg=C["bg"],
                 font=("Courier New", 13, "bold"), padx=14).pack(side="left")

        make_sep(f, pady=(0, 8))

        sf = ScrollableFrame(f)
        sf.pack(fill="both", expand=True)
        self._report_inner = sf.inner

    def _show_report(self):
        for w in self._report_inner.winfo_children():
            w.destroy()

        if not self.session_log:
            tk.Label(self._report_inner,
                     text="\n⚠  AUCUN RÉSULTAT EN SESSION\n\n"
                          "Exécute des commandes pour les voir ici.",
                     fg=C["text_dim"], bg=C["bg"],
                     font=("Courier New", 10),
                     justify="center").pack(pady=40)
        else:
            for e in self.session_log:
                row = tk.Frame(self._report_inner, bg=C["panel"],
                               highlightbackground=C["border"], highlightthickness=1)
                row.pack(fill="x", pady=3, padx=2)
                inner = tk.Frame(row, bg=C["panel"], padx=14, pady=10)
                inner.pack(fill="x")

                tk.Label(inner, text=e["tool"][:18].upper(),
                         fg=C["cyan"], bg=C["panel"],
                         font=("Courier New", 9, "bold"),
                         width=20, anchor="w").pack(side="left")

                mid = tk.Frame(inner, bg=C["panel"])
                mid.pack(side="left", fill="x", expand=True)
                tk.Label(mid, text=e["target"],
                         fg=C["text"], bg=C["panel"],
                         font=("Courier New", 10)).pack(anchor="w")
                tk.Label(mid, text=e["cmd"],
                         fg=C["text_dim"], bg=C["panel"],
                         font=("Courier New", 8),
                         wraplength=500).pack(anchor="w")

                right = tk.Frame(inner, bg=C["panel"])
                right.pack(side="right")
                tk.Label(right, text=e["time"],
                         fg=C["text_dim"], bg=C["panel"],
                         font=("Courier New", 8)).pack(anchor="e")
                rc_ok = (e["rc"] == 0)
                tk.Label(right,
                         text="✓ OK" if rc_ok else "✗ ERR",
                         fg=C["green"] if rc_ok else C["red"],
                         bg=C["panel"],
                         font=("Courier New", 9)).pack(anchor="e")

        self._show("report")

    # ══════════════════════════════════════════════
    #  QUIT
    # ══════════════════════════════════════════════
    def _do_quit(self):
        self._notify(f"👋  Bye {self.pseudo} ! Session fermée.")
        self.root.after(1300, self.root.quit)

    # ══════════════════════════════════════════════
    #  LANCEMENT
    # ══════════════════════════════════════════════
    def run(self):
        self.root.mainloop()


# ══════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    app = MDOSApp()
    app.run()
