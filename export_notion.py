#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MDOS — Multitool OSINT & Detection Operations System
Interface graphique Python (tkinter) — style terminal hacker vert/noir
Fusion complète : logique mdos.txt + design mdos_gui.html
VERSION DYNAMIQUE — s'adapte automatiquement à la taille de l'écran
"""
import tkinter as tk
from tkinter import font as tkfont
from tkinter import filedialog, messagebox
import subprocess
import threading
import datetime
import webbrowser
import json
import shlex
import socket
import getpass
import os
import re
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

ANSI_RE = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')

def clean_ansi(text: str) -> str:
    """Retire les codes ANSI couleurs/style."""
    return ANSI_RE.sub('', text or '')

def parse_nmap(raw: str) -> dict:
    """Parse une sortie nmap pour extraire ports, services, OS, host status."""
    res = {"hosts": [], "ports": [], "os": [], "services": [], "summary": ""}
    if not raw:
        return res
    current_host = None
    for line in raw.splitlines():
        line = line.rstrip()
        # Host up
        m = re.match(r'Nmap scan report for\s+(.+)', line)
        if m:
            current_host = m.group(1).strip()
            res["hosts"].append(current_host)
            continue
        m = re.match(r'Host is (up|down)(?:.*?\(([\d.]+)s latency\))?', line)
        if m:
            res["host_status"] = m.group(1)
            if m.group(2):
                res["latency_sec"] = m.group(2)
            continue
        # Ports : "22/tcp open  ssh" ou "22/tcp  open  ssh    OpenSSH 7.6"
        m = re.match(r'(\d+)/(tcp|udp)\s+(open|closed|filtered|open\|filtered)\s+(\S+)\s*(.*)?', line)
        if m:
            port_info = {
                "port": int(m.group(1)),
                "protocol": m.group(2),
                "state": m.group(3),
                "service": m.group(4),
            }
            ver = (m.group(5) or "").strip()
            if ver:
                port_info["version"] = ver
            res["ports"].append(port_info)
            if port_info["state"] == "open":
                svc = port_info["service"]
                if ver:
                    svc = f"{svc} ({ver})"
                res["services"].append(f"{port_info['port']}/{port_info['protocol']} — {svc}")
            continue
        # OS detection
        m = re.match(r'OS details?:\s*(.+)', line)
        if m:
            res["os"].append(m.group(1).strip()); continue
        m = re.match(r'Running:\s*(.+)', line)
        if m:
            res["os_running"] = m.group(1).strip(); continue
        m = re.match(r'Aggressive OS guesses?:\s*(.+)', line)
        if m:
            res["os"].append(m.group(1).strip()); continue
        # MAC
        m = re.match(r'MAC Address:\s*([0-9A-F:]+)\s*\((.+)\)', line, re.I)
        if m:
            res["mac_address"] = m.group(1)
            res["mac_vendor"]  = m.group(2)
            continue
        # Footer
        m = re.search(r'(\d+)\s+IP address.*scanned in\s+([\d.]+)\s+seconds', line)
        if m:
            res["ips_scanned"] = int(m.group(1))
            res["duration_sec"] = float(m.group(2))
    res["open_ports_count"] = sum(1 for p in res["ports"] if p["state"] == "open")
    res["total_ports_found"] = len(res["ports"])
    return res

def parse_hping3(raw: str) -> dict:
    """Extrait paquets envoyés/reçus, ports répondus."""
    res = {"ports_responded": [], "summary": {}}
    if not raw:
        return res
    for line in raw.splitlines():
        # "len=46 ip=1.2.3.4 ttl=64 ... sport=22 flags=SA"
        m = re.search(r'sport=(\d+).*?flags=(\S+)', line)
        if m:
            res["ports_responded"].append({
                "port": int(m.group(1)),
                "flags": m.group(2)
            })
        # Stats finales
        m = re.search(r'(\d+) packets t?ra?n?smitted, (\d+) (?:packets )?received', line)
        if m:
            res["summary"]["sent"]     = int(m.group(1))
            res["summary"]["received"] = int(m.group(2))
        m = re.search(r'round-trip min/avg/max\s*=\s*([\d./]+) ms', line)
        if m:
            parts = m.group(1).split('/')
            if len(parts) == 3:
                res["summary"]["rtt_min_ms"] = float(parts[0])
                res["summary"]["rtt_avg_ms"] = float(parts[1])
                res["summary"]["rtt_max_ms"] = float(parts[2])
    return res

def parse_traceroute(raw: str) -> dict:
    hops = []
    if not raw:
        return {"hops": hops}
    for line in raw.splitlines():
        m = re.match(r'\s*(\d+)\s+(.+)', line)
        if m:
            hops.append({"hop": int(m.group(1)), "info": m.group(2).strip()})
    return {"hops": hops, "total_hops": len(hops)}

def parse_nikto(raw: str) -> dict:
    findings = []
    server = None
    if not raw:
        return {"findings": findings}
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("+ Server:"):
            server = line.split(":", 1)[1].strip()
        elif line.startswith("+ ") and ":" in line:
            findings.append(line[2:].strip())
    return {"server": server, "findings": findings, "findings_count": len(findings)}

def parse_theharvester(raw: str) -> dict:
    emails, hosts = [], []
    if not raw:
        return {"emails": emails, "hosts": hosts}
    section = None
    for line in raw.splitlines():
        ls = line.strip()
        if "Emails found" in ls or "[*] Emails" in ls:
            section = "emails"; continue
        if "Hosts found" in ls or "[*] Hosts" in ls:
            section = "hosts"; continue
        if not ls or ls.startswith("---") or ls.startswith("[*]"):
            continue
        if section == "emails" and "@" in ls:
            emails.append(ls)
        elif section == "hosts" and ("." in ls):
            hosts.append(ls)
    return {"emails": list(dict.fromkeys(emails)),
            "hosts":  list(dict.fromkeys(hosts)),
            "emails_count": len(set(emails)),
            "hosts_count":  len(set(hosts))}

def parse_tool_output(tool: str, command: str, raw: str) -> dict:
    """Dispatch vers le parser approprié selon l'outil."""
    raw = clean_ansi(raw)
    tool_l = (tool or "").lower()
    cmd_l  = (command or "").lower()
    parsed = {"parser": "generic"}
    try:
        if tool_l.startswith("nmap") or "nmap" in cmd_l:
            parsed = parse_nmap(raw); parsed["parser"] = "nmap"
        elif "hping3" in cmd_l:
            parsed = parse_hping3(raw); parsed["parser"] = "hping3"
        elif "traceroute" in cmd_l:
            parsed = parse_traceroute(raw); parsed["parser"] = "traceroute"
        elif "nikto" in cmd_l:
            parsed = parse_nikto(raw); parsed["parser"] = "nikto"
        elif "theharvester" in cmd_l:
            parsed = parse_theharvester(raw); parsed["parser"] = "theHarvester"
        else:
            # générique : compte juste des lignes pertinentes
            lines = [l for l in raw.splitlines() if l.strip()]
            parsed = {"parser": "generic",
                      "lines_count": len(lines),
                      "preview": lines[:5]}
    except Exception as ex:
        parsed = {"parser": "error", "error": str(ex)}
    return parsed

def export_json(tool, category, target, command, rc, output):
    safe_mkdir(RESULTS_DIR / category)
    out_file = RESULTS_DIR / category / f"{tool}_{ts_filename()}.json"
    cleaned = clean_ansi(output or "")
    parsed  = parse_tool_output(tool, command, cleaned)
    entry = {
        "tool": tool,
        "category": category,
        "target": target,
        "date": now_iso(),
        "user": getpass.getuser(),
        "host": socket.gethostname(),
        "command": command,
        "returncode": rc,
        "status": "success" if rc == 0 else "error",
        "parsed": parsed,
        "raw_output": cleaned,
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
            {"label": "UnicornScan — OS (TTL)",         "badge": "TTL",   "cat": "scans",
             "fields": [("ip", "Adresse IP cible")],
             "cmd": lambda ip: f"unicornscan {shlex.quote(ip)} -Iv",
             "hint": "Linux/FreeBSD=64  Windows=128  Cisco=255"},
            {"label": "SX — Scan ARP réseau local",     "badge": "ARP",   "cat": "scans",
             "fields": [("target", "IP ou CIDR cible")],
             "cmd": lambda t: f"sx arp {shlex.quote(t)}"},
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
#  GESTIONNAIRE DE TAILLES DYNAMIQUES
# ══════════════════════════════════════════════════════════════════════
class Scale:
    """Calcule les tailles de police et espacements en fonction de la taille de l'écran."""
    def __init__(self, root):
        self.root = root
        # Taille de l'écran
        sw = root.winfo_screenwidth()
        sh = root.winfo_screenheight()
        # Facteur d'échelle basé sur la résolution (référence 1920x1080)
        # On prend le plus petit pour ne pas dépasser
        self.factor = min(sw / 1920, sh / 1080)
        # Bornes : pas trop petit ni trop grand
        self.factor = max(0.75, min(self.factor, 2.0))
        # Si l'écran est petit (Kali en VM par ex.), on booste un peu
        if sw < 1366 or sh < 768:
            self.factor = max(self.factor, 0.9)
        self.sw = sw
        self.sh = sh

    def font(self, base):
        """Retourne une taille de police adaptée."""
        return max(7, int(round(base * self.factor)))

    def px(self, base):
        """Retourne un nombre de pixels adapté."""
        return max(1, int(round(base * self.factor)))

    def update_from_window(self, w, h):
        """Recalcule le facteur basé sur la taille de la fenêtre courante."""
        # Référence : fenêtre 1020x740 (taille initiale du design)
        wf = w / 1020
        hf = h / 740
        new_factor = min(wf, hf)
        new_factor = max(0.75, min(new_factor, 2.0))
        # Ne mettre à jour que si changement significatif (évite spam)
        if abs(new_factor - self.factor) > 0.05:
            self.factor = new_factor
            return True
        return False

# ══════════════════════════════════════════════════════════════════════
#  WIDGETS HELPERS
# ══════════════════════════════════════════════════════════════════════
def make_sep(parent, color=None, height=1, pady=0):
    f = tk.Frame(parent, bg=color or C["border"], height=height)
    f.pack(fill="x", pady=pady)
    return f

# ══════════════════════════════════════════════════════════════════════
#  APPLICATION PRINCIPALE
# ══════════════════════════════════════════════════════════════════════
class MDOSApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("MDOS — Access Terminal  v2.0.0")
        self.root.configure(bg=C["bg"])

        # ── Échelle dynamique
        self.scale = Scale(self.root)

        # ── Dimensionner la fenêtre à 80% de l'écran (centrée)
        sw = self.scale.sw
        sh = self.scale.sh
        win_w = int(sw * 0.80)
        win_h = int(sh * 0.85)
        # Garde-fous
        win_w = max(900, min(win_w, sw - 40))
        win_h = max(650, min(win_h, sh - 80))
        x = (sw - win_w) // 2
        y = (sh - win_h) // 2
        self.root.geometry(f"{win_w}x{win_h}+{x}+{y}")
        self.root.minsize(880, 600)

        # ── Registres pour mises à jour dynamiques
        self._font_widgets = []   # liste de (widget, key) pour adaptation police
        self._fonts = {}          # cache des polices nommées
        self._init_named_fonts()

        self.pseudo      = ""
        self.session_log = []
        self.field_vars  = []
        self.current_item = None
        self.current_key  = None

        self._build_statusbar()
        self._build_screens()
        self._tick()

        # Liaison resize → recalcule polices
        self.root.bind("<Configure>", self._on_resize)
        self._resize_after_id = None

    # ──────────────────────────────────────────────
    #  GESTION POLICES NOMMÉES (mises à jour globales)
    # ──────────────────────────────────────────────
    def _init_named_fonts(self):
        s = self.scale
        # On crée des polices nommées qu'on peut mettre à jour partout d'un coup
        self._fonts = {
            "tiny":    tkfont.Font(family="Courier New", size=s.font(8)),
            "small":   tkfont.Font(family="Courier New", size=s.font(9)),
            "base":    tkfont.Font(family="Courier New", size=s.font(10)),
            "base_b":  tkfont.Font(family="Courier New", size=s.font(10), weight="bold"),
            "med":     tkfont.Font(family="Courier New", size=s.font(11)),
            "med_b":   tkfont.Font(family="Courier New", size=s.font(11), weight="bold"),
            "big":     tkfont.Font(family="Courier New", size=s.font(13)),
            "big_b":   tkfont.Font(family="Courier New", size=s.font(13), weight="bold"),
            "xl":      tkfont.Font(family="Courier New", size=s.font(15), weight="bold"),
            "xxl":     tkfont.Font(family="Courier New", size=s.font(20), weight="bold"),
            "huge":    tkfont.Font(family="Courier New", size=s.font(32), weight="bold"),
            "entry":   tkfont.Font(family="Courier New", size=s.font(12)),
            "entry_l": tkfont.Font(family="Courier New", size=s.font(13)),
            "totp":    tkfont.Font(family="Courier New", size=s.font(20), weight="bold"),
        }

    def _refresh_fonts(self):
        """Met à jour toutes les polices nommées d'après le facteur courant."""
        s = self.scale
        mapping = {
            "tiny":    (8, "normal"),
            "small":   (9, "normal"),
            "base":    (10, "normal"),
            "base_b":  (10, "bold"),
            "med":     (11, "normal"),
            "med_b":   (11, "bold"),
            "big":     (13, "normal"),
            "big_b":   (13, "bold"),
            "xl":      (15, "bold"),
            "xxl":     (20, "bold"),
            "huge":    (32, "bold"),
            "entry":   (12, "normal"),
            "entry_l": (13, "normal"),
            "totp":    (20, "bold"),
        }
        for key, (base, w) in mapping.items():
            self._fonts[key].configure(size=s.font(base), weight=w)

    def _on_resize(self, event):
        # Ignore les events qui ne viennent pas de la racine
        if event.widget is not self.root:
            return
        # Debounce
        if self._resize_after_id:
            self.root.after_cancel(self._resize_after_id)
        self._resize_after_id = self.root.after(120, self._do_resize)

    def _do_resize(self):
        w = self.root.winfo_width()
        h = self.root.winfo_height()
        if self.scale.update_from_window(w, h):
            self._refresh_fonts()

    # ──────────────────────────────────────────────
    #  HELPERS BOUTONS (utilisent polices nommées)
    # ──────────────────────────────────────────────
    def green_btn(self, parent, text, cmd, width=None):
        s = self.scale
        kw = {"width": width} if width else {}
        b = tk.Button(parent, text=text, command=cmd,
                      fg=C["green"], bg=C["bg"],
                      activeforeground=C["bg"], activebackground=C["green"],
                      font=self._fonts["base_b"],
                      relief="flat",
                      highlightbackground=C["green"], highlightthickness=1,
                      padx=s.px(18), pady=s.px(8), cursor="hand2", **kw)
        return b

    def sec_btn(self, parent, text, cmd):
        s = self.scale
        b = tk.Button(parent, text=text, command=cmd,
                      fg=C["text_dim"], bg=C["bg"],
                      activeforeground=C["green_dim"], activebackground=C["bg2"],
                      font=self._fonts["small"],
                      relief="flat",
                      highlightbackground=C["border"], highlightthickness=1,
                      padx=s.px(14), pady=s.px(8), cursor="hand2")
        return b

    def back_btn(self, parent, cmd):
        s = self.scale
        return tk.Button(parent, text="◀  RETOUR", command=cmd,
                         fg=C["text_dim"], bg=C["bg"],
                         activeforeground=C["green"], activebackground=C["bg"],
                         font=self._fonts["small"],
                         relief="flat",
                         highlightbackground=C["border"], highlightthickness=1,
                         padx=s.px(12), pady=s.px(6), cursor="hand2")

    def label_panel(self, parent, label_text):
        """Panneau avec label flottant."""
        s = self.scale
        outer = tk.Frame(parent, bg=C["panel"],
                         highlightbackground=C["border"], highlightthickness=1)
        lbl = tk.Label(outer, text=f" {label_text} ",
                       fg=C["green_dim"], bg=C["bg"],
                       font=self._fonts["tiny"])
        lbl.place(x=s.px(12), y=-s.px(9))
        inner = tk.Frame(outer, bg=C["panel"])
        inner.pack(fill="both", expand=True,
                   padx=s.px(16), pady=(s.px(14), s.px(14)))
        return outer, inner

    def scrollable(self, parent):
        """Frame scrollable verticalement."""
        wrap = tk.Frame(parent, bg=C["bg"])
        canvas = tk.Canvas(wrap, bg=C["bg"], highlightthickness=0)
        sb = tk.Scrollbar(wrap, orient="vertical", command=canvas.yview,
                          bg=C["bg2"], troughcolor=C["bg"])
        inner = tk.Frame(canvas, bg=C["bg"])
        inner_id = canvas.create_window((0, 0), window=inner, anchor="nw")

        def on_inner_config(e):
            canvas.configure(scrollregion=canvas.bbox("all"))
        def on_canvas_config(e):
            canvas.itemconfig(inner_id, width=e.width)
        inner.bind("<Configure>", on_inner_config)
        canvas.bind("<Configure>", on_canvas_config)
        canvas.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        # Mousewheel — Linux et autres
        def _on_wheel(e):
            if hasattr(e, 'delta') and e.delta:
                canvas.yview_scroll(int(-1*(e.delta/120)), "units")
            elif getattr(e, 'num', None) == 4:
                canvas.yview_scroll(-1, "units")
            elif getattr(e, 'num', None) == 5:
                canvas.yview_scroll(1, "units")
        # Bind sur le canvas et ses enfants
        for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            canvas.bind_all(seq, _on_wheel)
        return wrap, inner

    # ──────────────────────────────────────────────
    #  STATUSBAR
    # ──────────────────────────────────────────────
    def _build_statusbar(self):
        s = self.scale
        bar = tk.Frame(self.root, bg=C["statusbar"], height=s.px(28))
        bar.pack(fill="x", side="top")
        bar.pack_propagate(False)
        left = tk.Frame(bar, bg=C["statusbar"])
        left.pack(side="left", padx=s.px(12))
        self._dot_canvas = tk.Canvas(left, width=s.px(8), height=s.px(8),
                                     bg=C["statusbar"], highlightthickness=0)
        self._dot_canvas.pack(side="left", padx=(0, s.px(6)))
        self._dot_id = self._dot_canvas.create_oval(
            1, 1, s.px(8)-1, s.px(8)-1,
            fill=C["green"], outline="")
        self._blink_dot()
        tk.Label(left,
                 text="MDOS SYSTEM ONLINE  |  v2.0.0  |  SECURE CHANNEL",
                 fg=C["text_dim"], bg=C["statusbar"],
                 font=self._fonts["tiny"]).pack(side="left")
        right = tk.Frame(bar, bg=C["statusbar"])
        right.pack(side="right", padx=s.px(12))
        self._clock_var  = tk.StringVar(value="--:--:--")
        self._status_var = tk.StringVar(value="NOT_AUTH")
        tk.Label(right, textvariable=self._clock_var,
                 fg=C["green"], bg=C["statusbar"],
                 font=self._fonts["tiny"]).pack(side="right", padx=(s.px(12), 0))
        tk.Label(right, textvariable=self._status_var,
                 fg=C["text_dim"], bg=C["statusbar"],
                 font=self._fonts["tiny"]).pack(side="right")

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
        s = self.scale
        self._container = tk.Frame(self.root, bg=C["bg"])
        self._container.pack(fill="both", expand=True,
                             padx=s.px(24), pady=(s.px(38), s.px(10)))
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
        s = self.scale
        color = C["red"] if error else C["green"]
        n = tk.Label(self.root, text=msg,
                     fg=color, bg=C["statusbar"],
                     font=self._fonts["small"],
                     highlightbackground=color, highlightthickness=1,
                     padx=s.px(12), pady=s.px(8))
        n.place(relx=1.0, rely=1.0, anchor="se",
                x=-s.px(18), y=-s.px(18))
        self.root.after(3400, n.destroy)

    # ══════════════════════════════════════════════
    #  ÉCRAN LOGIN
    # ══════════════════════════════════════════════
    def _build_login(self):
        s = self.scale
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
                 font=self._fonts["base"], justify="center").pack()
        tk.Label(wrap, text="MDOS", fg=C["green"], bg=C["bg"],
                 font=self._fonts["huge"], pady=s.px(4)).pack()
        tk.Label(wrap,
                 text="Multitool OSINT & Detection Operations System",
                 fg=C["text_dim"], bg=C["bg"],
                 font=self._fonts["tiny"]).pack(pady=(0, s.px(22)))

        box = tk.Frame(wrap, bg=C["panel"],
                       highlightbackground=C["border"], highlightthickness=1)
        box.pack()
        inner = tk.Frame(box, bg=C["panel"])
        inner.pack(padx=s.px(32), pady=s.px(24), fill="x")

        tk.Label(inner, text="// IDENTIFIANT",
                 fg=C["text_dim"], bg=C["panel"],
                 font=self._fonts["tiny"], anchor="w").pack(anchor="w", pady=(0, s.px(4)))
        self._inp_pseudo = tk.Entry(inner,
                                    bg=C["entry_bg"], fg=C["green"],
                                    insertbackground=C["green"],
                                    font=self._fonts["entry_l"],
                                    relief="flat",
                                    highlightbackground=C["green_dim"],
                                    highlightthickness=1, width=30)
        self._inp_pseudo.pack(fill="x", pady=(0, s.px(14)))

        tk.Label(inner, text="// TOTP CODE (Google Authenticator)",
                 fg=C["text_dim"], bg=C["panel"],
                 font=self._fonts["tiny"], anchor="w").pack(anchor="w", pady=(0, s.px(4)))
        self._inp_totp = tk.Entry(inner,
                                   bg=C["entry_bg"], fg=C["green"],
                                   insertbackground=C["green"],
                                   font=self._fonts["totp"],
                                   justify="center",
                                   relief="flat",
                                   highlightbackground=C["green_dim"],
                                   highlightthickness=1, width=30)
        self._inp_totp.pack(fill="x", pady=(0, s.px(4)))
        self._inp_totp.bind("<Return>", lambda e: self._do_login())

        self._pbar_wrap = tk.Frame(inner, bg=C["border"], height=2)
        self._pbar_wrap.pack(fill="x", pady=(s.px(4), s.px(4)))
        self._pbar_fill = tk.Frame(self._pbar_wrap, bg=C["green"], width=0, height=2)
        self._pbar_fill.pack(side="left")

        self._login_err = tk.Label(inner, text="", fg=C["red"], bg=C["panel"],
                                    font=self._fonts["small"], pady=s.px(2))
        self._login_err.pack()

        self.green_btn(inner, "▶   ACCESS_GRANT", self._do_login).pack(
            fill="x", pady=(s.px(8), 0))

    def _do_login(self):
        p = self._inp_pseudo.get().strip()
        t = self._inp_totp.get().strip()
        if not p:
            self._login_err.config(text="⚠  PSEUDO REQUIS"); return
        if len(t) != 6 or not t.isdigit():
            self._login_err.config(
                text="⚠  CODE TOTP INVALIDE — 6 chiffres requis"); return
        self._login_err.config(text="")

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
                    ok = True
            except Exception:
                ok = True
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
        s = self.scale
        f = self._screens["menu"]
        hdr = tk.Frame(f, bg=C["bg"])
        hdr.pack(fill="x", pady=(0, s.px(10)))
        left = tk.Frame(hdr, bg=C["bg"])
        left.pack(side="left")
        tk.Label(left, text="// Session active",
                 fg=C["text_dim"], bg=C["bg"],
                 font=self._fonts["tiny"]).pack(anchor="w")
        self._menu_user_lbl = tk.Label(left, text="",
                                        fg=C["green"], bg=C["bg"],
                                        font=self._fonts["xxl"])
        self._menu_user_lbl.pack(anchor="w")
        self._menu_info_lbl = tk.Label(hdr, text="",
                                        fg=C["text_dim"], bg=C["bg"],
                                        font=self._fonts["tiny"],
                                        justify="right")
        self._menu_info_lbl.pack(side="right", anchor="ne")
        make_sep(f, pady=(0, s.px(12)))

        # Container scrollable pour le menu
        wrap, inner = self.scrollable(f)
        wrap.pack(fill="both", expand=True)

        grid = tk.Frame(inner, bg=C["bg"])
        grid.pack(fill="both", expand=True)
        grid.columnconfigure(0, weight=1)
        grid.columnconfigure(1, weight=1)

        for idx, (num, key, title, tag, color) in enumerate(MENU_CARDS):
            row, col = divmod(idx, 2)
            card = self._make_card(grid, num, key, title, tag, color)
            card.grid(row=row, column=col, sticky="ew",
                      padx=s.px(5), pady=s.px(5))

    def _make_card(self, parent, num, key, title, tag, color):
        s = self.scale
        is_quit  = (key == "quit")
        bdr_norm = C["border"] if not is_quit else "#3a0a15"
        bg_hover = "#0d2017" if not is_quit else "#1a0a10"
        bdr_hov  = C["green_dim"] if not is_quit else C["red"]
        outer = tk.Frame(parent, bg=C["panel"],
                         highlightbackground=bdr_norm, highlightthickness=1,
                         cursor="hand2")
        inner = tk.Frame(outer, bg=C["panel"],
                         pady=s.px(13), padx=s.px(16))
        inner.pack(fill="both", expand=True)
        num_lbl = tk.Label(inner,
                           text=num,
                           fg=C["green_dim"] if not is_quit else "#7a1530",
                           bg=C["panel"],
                           font=self._fonts["xl"], width=3)
        num_lbl.pack(side="left", anchor="center")
        txt = tk.Frame(inner, bg=C["panel"])
        txt.pack(side="left", fill="both", expand=True)
        row1 = tk.Frame(txt, bg=C["panel"])
        row1.pack(anchor="w")
        title_lbl = tk.Label(row1, text=title.upper(),
                              fg=C["text"], bg=C["panel"],
                              font=self._fonts["med_b"])
        title_lbl.pack(side="left")
        if tag:
            tk.Label(row1, text=f" [{tag}]",
                     fg=color, bg=C["panel"],
                     font=self._fonts["tiny"]).pack(side="left")
        if key in SUBMENUS:
            tk.Label(txt, text=SUBMENUS[key]["desc"],
                     fg=C["text_dim"], bg=C["panel"],
                     font=self._fonts["tiny"]).pack(anchor="w")
        arr = tk.Label(inner,
                       text="▶" if not is_quit else "✕",
                       fg=C["text_dim"] if not is_quit else C["red"],
                       bg=C["panel"], font=self._fonts["med"])
        arr.pack(side="right", anchor="center")
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
        s = self.scale
        f = self._screens["submenu"]
        hdr = tk.Frame(f, bg=C["bg"])
        hdr.pack(fill="x", pady=(0, s.px(10)))
        self.back_btn(hdr, self._back_to_menu).pack(side="left")
        self._sub_title = tk.Label(hdr, text="TOOLS",
                                   fg=C["green"], bg=C["bg"],
                                   font=self._fonts["big_b"], padx=s.px(14))
        self._sub_title.pack(side="left")
        make_sep(f, pady=(0, s.px(8)))
        wrap, inner = self.scrollable(f)
        wrap.pack(fill="both", expand=True)
        self._sub_inner = inner

    def _load_submenu(self, key):
        s = self.scale
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
            row.pack(fill="x", pady=s.px(4), padx=s.px(2))
            inner = tk.Frame(row, bg=C["panel"],
                             pady=s.px(11), padx=s.px(16))
            inner.pack(fill="x")
            tk.Label(inner, text=f"{idx+1:02d}",
                     fg=C["green_dim"], bg=C["panel"],
                     font=self._fonts["small"], width=3).pack(side="left")
            tk.Label(inner, text=item["label"].upper(),
                     fg=C["text"], bg=C["panel"],
                     font=self._fonts["base_b"],
                     anchor="w").pack(side="left", fill="x", expand=True)
            tk.Label(inner, text=item["badge"],
                     fg=C["text_dim"], bg=C["panel"],
                     font=self._fonts["tiny"],
                     highlightbackground=C["border"], highlightthickness=1,
                     padx=s.px(6), pady=s.px(2)).pack(side="right")
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
            for w in [row, inner] + list(inner.winfo_children()):
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
        s = self.scale
        f = self._screens["cmd"]
        hdr = tk.Frame(f, bg=C["bg"])
        hdr.pack(fill="x", pady=(0, s.px(10)))
        self.back_btn(hdr, self._back_to_sub).pack(side="left")
        self._cmd_title = tk.Label(hdr, text="EXECUTE",
                                   fg=C["green"], bg=C["bg"],
                                   font=self._fonts["big_b"], padx=s.px(14))
        self._cmd_title.pack(side="left")
        make_sep(f, pady=(0, s.px(8)))
        wrap, inner = self.scrollable(f)
        wrap.pack(fill="both", expand=True)
        self._cmd_inner = inner

    def _open_cmd(self, key, idx):
        s = self.scale
        self.current_key  = key
        self.current_item = SUBMENUS[key]["items"][idx]
        item = self.current_item
        self._cmd_title.config(text=item["label"].upper())
        self.field_vars = []
        for w in self._cmd_inner.winfo_children():
            w.destroy()

        # ── Panneau champs
        if item.get("fields"):
            panel, ip = self.label_panel(self._cmd_inner, "INPUT_PARAMS")
            panel.pack(fill="x", pady=(s.px(4), s.px(12)), padx=s.px(2))
            for fid, flabel in item["fields"]:
                tk.Label(ip, text=f"// {flabel.upper()}",
                         fg=C["text_dim"], bg=C["panel"],
                         font=self._fonts["tiny"],
                         anchor="w").pack(anchor="w", pady=(s.px(4), s.px(2)))
                var = tk.StringVar()
                var.trace_add("write", lambda *a: self._refresh_preview())
                self.field_vars.append(var)
                e = tk.Entry(ip, textvariable=var,
                             bg=C["entry_bg"], fg=C["green"],
                             insertbackground=C["green"],
                             font=self._fonts["entry"],
                             relief="flat",
                             highlightbackground=C["border"],
                             highlightthickness=1)
                e.pack(fill="x", pady=(0, s.px(4)))
            if item.get("hint"):
                tk.Label(ip, text=f"⚠  {item['hint']}",
                         fg=C["yellow"], bg=C["panel"],
                         font=self._fonts["tiny"]).pack(anchor="w", pady=(s.px(4), 0))

        # ── Panneau preview
        prev_panel, pp = self.label_panel(self._cmd_inner, "CMD_PREVIEW")
        prev_panel.pack(fill="x", pady=(0, s.px(10)), padx=s.px(2))
        tk.Label(pp, text="// Commande générée",
                 fg=C["text_dim"], bg=C["panel"],
                 font=self._fonts["tiny"]).pack(anchor="w", pady=(0, s.px(4)))
        self._preview_lbl = tk.Label(pp, text="—",
                                     fg=C["cyan"], bg=C["entry_bg"],
                                     font=self._fonts["med"],
                                     wraplength=self.root.winfo_width() - s.px(160),
                                     justify="left",
                                     anchor="w",
                                     highlightbackground=C["border"],
                                     highlightthickness=1,
                                     padx=s.px(12), pady=s.px(9))
        self._preview_lbl.pack(fill="x", pady=(0, s.px(10)))
        btns = tk.Frame(pp, bg=C["panel"])
        btns.pack(anchor="w")
        self.green_btn(btns, "▶   EXÉCUTER", self._execute).pack(side="left")
        self.sec_btn(btns,   "⎘  COPIER",    self._copy_cmd).pack(
            side="left", padx=(s.px(10), 0))

        # ── Terminal
        term_panel, tp = self.label_panel(self._cmd_inner, "OUTPUT")
        term_panel.pack(fill="both", expand=True, pady=(0, s.px(8)), padx=s.px(2))
        # Terminal occupe maintenant tout l'espace restant
        term_frame = tk.Frame(tp, bg=C["term_bg"])
        term_frame.pack(fill="both", expand=True)
        self._terminal = tk.Text(term_frame, bg=C["term_bg"], fg=C["green_dim"],
                                 font=self._fonts["base"],
                                 insertbackground=C["green"],
                                 relief="flat",
                                 wrap="word", state="disabled",
                                 highlightthickness=0)
        term_sb = tk.Scrollbar(term_frame, command=self._terminal.yview,
                               bg=C["bg2"], troughcolor=C["bg"])
        self._terminal.configure(yscrollcommand=term_sb.set)
        term_sb.pack(side="right", fill="y")
        self._terminal.pack(side="left", fill="both", expand=True)
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
        # Met à jour wraplength dynamiquement
        try:
            w = max(400, self.root.winfo_width() - self.scale.px(160))
            self._preview_lbl.config(text=cmd, wraplength=w)
        except Exception:
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
        if item.get("url"):
            webbrowser.open(item["url"])
            self._term_add(f"▶ Ouverture navigateur : {item['url']}", "info")
            export_json(item["label"], item.get("cat", "misc"),
                        item["url"], item["cmd"](), 0, "Opened in browser")
            self.session_log.append({
                "tool": item["label"], "cat": item.get("cat", "misc"),
                "target": item["url"], "cmd": item["cmd"](),
                "rc": 0, "time": datetime.datetime.now().strftime("%H:%M:%S"),
                "raw": "Opened in browser",
                "parsed": {"parser": "url"},
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
                out_file = export_json(
                    cmd.split()[0], item.get("cat", "misc"),
                    vals[0] if vals else "—", cmd, rc, output_str
                )
                parsed_data = parse_tool_output(cmd.split()[0], cmd, clean_ansi(output_str))
                self.session_log.append({
                    "tool": item["label"], "cat": item.get("cat", "misc"),
                    "target": vals[0] if vals else "—", "cmd": cmd,
                    "rc": rc, "time": datetime.datetime.now().strftime("%H:%M:%S"),
                    "raw": clean_ansi(output_str),
                    "parsed": parsed_data,
                    "json_file": str(out_file),
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
        s = self.scale
        f = self._screens["report"]
        hdr = tk.Frame(f, bg=C["bg"])
        hdr.pack(fill="x", pady=(0, s.px(10)))
        self.back_btn(hdr, lambda: self._show("menu")).pack(side="left")
        tk.Label(hdr, text="RAPPORT DE SESSION",
                 fg=C["green"], bg=C["bg"],
                 font=self._fonts["big_b"], padx=s.px(14)).pack(side="left")
        # Boutons d'export à droite
        self.green_btn(hdr, "⬇  EXPORT PDF", self._export_session_pdf).pack(
            side="right", padx=(s.px(6), 0))
        self.sec_btn(hdr, "⬇  EXPORT JSON", self._export_session_json).pack(
            side="right", padx=(s.px(6), 0))
        # Bouton Notion en violet/cyan
        b_notion = tk.Button(hdr, text="◈  EXPORT NOTION",
                             command=self._export_session_notion,
                             fg=C["purple"], bg=C["bg"],
                             activeforeground=C["bg"],
                             activebackground=C["purple"],
                             font=self._fonts["base_b"],
                             relief="flat",
                             highlightbackground=C["purple"],
                             highlightthickness=1,
                             padx=s.px(14), pady=s.px(8), cursor="hand2")
        b_notion.pack(side="right", padx=(s.px(6), 0))
        make_sep(f, pady=(0, s.px(8)))
        wrap, inner = self.scrollable(f)
        wrap.pack(fill="both", expand=True)
        self._report_inner = inner

    def _show_report(self):
        s = self.scale
        for w in self._report_inner.winfo_children():
            w.destroy()
        if not self.session_log:
            tk.Label(self._report_inner,
                     text="\n⚠  AUCUN RÉSULTAT EN SESSION\n\n"
                          "Exécute des commandes pour les voir ici.",
                     fg=C["text_dim"], bg=C["bg"],
                     font=self._fonts["base"],
                     justify="center").pack(pady=s.px(40))
        else:
            for e in self.session_log:
                row = tk.Frame(self._report_inner, bg=C["panel"],
                               highlightbackground=C["border"], highlightthickness=1)
                row.pack(fill="x", pady=s.px(3), padx=s.px(2))
                inner = tk.Frame(row, bg=C["panel"],
                                 padx=s.px(14), pady=s.px(10))
                inner.pack(fill="x")
                tk.Label(inner, text=e["tool"][:18].upper(),
                         fg=C["cyan"], bg=C["panel"],
                         font=self._fonts["small"],
                         width=20, anchor="w").pack(side="left")
                mid = tk.Frame(inner, bg=C["panel"])
                mid.pack(side="left", fill="x", expand=True)
                tk.Label(mid, text=e["target"],
                         fg=C["text"], bg=C["panel"],
                         font=self._fonts["base"]).pack(anchor="w")
                tk.Label(mid, text=e["cmd"],
                         fg=C["text_dim"], bg=C["panel"],
                         font=self._fonts["tiny"],
                         wraplength=max(400, self.root.winfo_width()-s.px(280))
                         ).pack(anchor="w")
                right = tk.Frame(inner, bg=C["panel"])
                right.pack(side="right")
                tk.Label(right, text=e["time"],
                         fg=C["text_dim"], bg=C["panel"],
                         font=self._fonts["tiny"]).pack(anchor="e")
                rc_ok = (e["rc"] == 0)
                tk.Label(right,
                         text="✓ OK" if rc_ok else "✗ ERR",
                         fg=C["green"] if rc_ok else C["red"],
                         bg=C["panel"],
                         font=self._fonts["small"]).pack(anchor="e")
        self._show("report")

    # ══════════════════════════════════════════════
    #  EXPORT SESSION (PDF & JSON)
    # ══════════════════════════════════════════════
    def _export_session_json(self):
        if not self.session_log:
            self._notify("⚠  Aucun résultat à exporter", error=True)
            return
        default = f"MDOS_session_{ts_filename()}.json"
        path = filedialog.asksaveasfilename(
            title="Exporter la session en JSON",
            defaultextension=".json",
            initialfile=default,
            initialdir=str(RESULTS_DIR),
            filetypes=[("JSON", "*.json")]
        )
        if not path:
            return
        try:
            data = {
                "session": {
                    "user": self.pseudo,
                    "host": socket.gethostname(),
                    "date": now_iso(),
                    "results_count": len(self.session_log),
                },
                "results": self.session_log,
            }
            Path(path).write_text(json.dumps(data, ensure_ascii=False, indent=2),
                                  encoding="utf-8")
            self._notify(f"✅ JSON exporté : {Path(path).name}")
        except Exception as ex:
            self._notify(f"⛔ Erreur JSON : {ex}", error=True)

    def _export_session_pdf(self):
        if not self.session_log:
            self._notify("⚠  Aucun résultat à exporter", error=True)
            return
        default = f"MDOS_session_{ts_filename()}.pdf"
        path = filedialog.asksaveasfilename(
            title="Exporter la session en PDF",
            defaultextension=".pdf",
            initialfile=default,
            initialdir=str(RESULTS_DIR),
            filetypes=[("PDF", "*.pdf")]
        )
        if not path:
            return
        # Génération en thread pour ne pas geler l'UI
        threading.Thread(target=self._generate_pdf,
                         args=(path,), daemon=True).start()
        self._notify("⏳ Génération du PDF en cours…")

    def _generate_pdf(self, path: str):
        try:
            ok = self._pdf_reportlab(path)
            if not ok:
                ok = self._pdf_fpdf(path)
            if not ok:
                # fallback HTML
                html_path = Path(path).with_suffix(".html")
                self._pdf_html_fallback(html_path)
                self.root.after(0, lambda: self._notify(
                    f"⚠ reportlab/fpdf2 absents — HTML créé : {html_path.name}",
                    error=True))
                return
            self.root.after(0, lambda: self._notify(
                f"✅ PDF exporté : {Path(path).name}"))
        except Exception as ex:
            self.root.after(0, lambda: self._notify(
                f"⛔ Erreur PDF : {ex}", error=True))

    # ── ReportLab (plus pro) ──────────────────────────────
    def _pdf_reportlab(self, path: str) -> bool:
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import cm
            from reportlab.lib import colors
            from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                            Table, TableStyle, PageBreak,
                                            KeepTogether)
            from reportlab.lib.enums import TA_LEFT
        except Exception:
            return False

        doc = SimpleDocTemplate(path, pagesize=A4,
                                leftMargin=1.6*cm, rightMargin=1.6*cm,
                                topMargin=1.6*cm, bottomMargin=1.6*cm,
                                title="MDOS Session Report",
                                author=self.pseudo or "MDOS")

        styles = getSampleStyleSheet()
        # Style hacker vert/noir-ish mais lisible imprimé
        H1 = ParagraphStyle("H1", parent=styles["Heading1"],
                            textColor=colors.HexColor("#0a7a3a"),
                            fontName="Helvetica-Bold", fontSize=20,
                            spaceAfter=10)
        H2 = ParagraphStyle("H2", parent=styles["Heading2"],
                            textColor=colors.HexColor("#0a7a3a"),
                            fontName="Helvetica-Bold", fontSize=13,
                            spaceBefore=14, spaceAfter=6)
        H3 = ParagraphStyle("H3", parent=styles["Heading3"],
                            textColor=colors.HexColor("#333333"),
                            fontName="Helvetica-Bold", fontSize=11,
                            spaceBefore=8, spaceAfter=4)
        BODY = ParagraphStyle("BODY", parent=styles["BodyText"],
                              fontName="Helvetica", fontSize=10,
                              leading=13, alignment=TA_LEFT)
        MONO = ParagraphStyle("MONO", parent=styles["BodyText"],
                              fontName="Courier", fontSize=8,
                              leading=10, leftIndent=6,
                              textColor=colors.HexColor("#222222"))
        SMALL = ParagraphStyle("SMALL", parent=styles["BodyText"],
                               fontName="Helvetica", fontSize=8,
                               textColor=colors.HexColor("#666666"))

        def esc(t):
            return (str(t).replace("&", "&amp;")
                          .replace("<", "&lt;")
                          .replace(">", "&gt;"))

        story = []
        # ── En-tête
        story.append(Paragraph("MDOS — Rapport de Session", H1))
        meta = [
            ["Utilisateur", self.pseudo or "—"],
            ["Hôte",        socket.gethostname()],
            ["Date",        now_iso()],
            ["Commandes",   str(len(self.session_log))],
            ["Réussies",    str(sum(1 for e in self.session_log if e.get("rc") == 0))],
            ["Échouées",    str(sum(1 for e in self.session_log if e.get("rc") != 0))],
        ]
        t = Table(meta, colWidths=[3.5*cm, 13*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (0,-1), colors.HexColor("#e8f5ec")),
            ("TEXTCOLOR",  (0,0), (0,-1), colors.HexColor("#0a7a3a")),
            ("FONTNAME",   (0,0), (-1,-1), "Helvetica"),
            ("FONTSIZE",   (0,0), (-1,-1), 9),
            ("GRID",       (0,0), (-1,-1), 0.4, colors.HexColor("#cccccc")),
            ("VALIGN",     (0,0), (-1,-1), "TOP"),
            ("LEFTPADDING",  (0,0), (-1,-1), 6),
            ("RIGHTPADDING", (0,0), (-1,-1), 6),
            ("TOPPADDING",   (0,0), (-1,-1), 4),
            ("BOTTOMPADDING",(0,0), (-1,-1), 4),
        ]))
        story.append(t)
        story.append(Spacer(1, 0.6*cm))

        # ── Sommaire des commandes (tableau)
        story.append(Paragraph("Sommaire", H2))
        head = ["#", "Heure", "Outil", "Cible", "Status"]
        rows = [head]
        for i, e in enumerate(self.session_log, 1):
            rows.append([
                str(i),
                e.get("time", ""),
                esc(e.get("tool", ""))[:36],
                esc(e.get("target", ""))[:30],
                "OK" if e.get("rc") == 0 else "ERR"
            ])
        summary = Table(rows, colWidths=[0.8*cm, 2.2*cm, 7*cm, 5.5*cm, 1.5*cm],
                        repeatRows=1)
        summary.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#0a7a3a")),
            ("TEXTCOLOR",  (0,0), (-1,0), colors.white),
            ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",   (0,0), (-1,-1), 8),
            ("GRID",       (0,0), (-1,-1), 0.3, colors.HexColor("#cccccc")),
            ("ROWBACKGROUNDS", (0,1), (-1,-1),
                [colors.white, colors.HexColor("#f4faf6")]),
            ("VALIGN",     (0,0), (-1,-1), "TOP"),
            ("LEFTPADDING",  (0,0), (-1,-1), 4),
            ("RIGHTPADDING", (0,0), (-1,-1), 4),
        ]))
        # Couleur status colonne
        for ri, e in enumerate(self.session_log, 1):
            col = colors.HexColor("#0a7a3a") if e.get("rc") == 0 else colors.HexColor("#cc1133")
            summary.setStyle(TableStyle([("TEXTCOLOR", (4,ri), (4,ri), col),
                                         ("FONTNAME",  (4,ri), (4,ri), "Helvetica-Bold")]))
        story.append(summary)
        story.append(PageBreak())

        # ── Détails de chaque exécution
        story.append(Paragraph("Détails des exécutions", H1))
        story.append(Spacer(1, 0.3*cm))

        for i, e in enumerate(self.session_log, 1):
            block = []
            block.append(Paragraph(f"#{i} — {esc(e.get('tool',''))}", H2))
            meta2 = [
                ["Catégorie", esc(e.get("cat", "—"))],
                ["Cible",     esc(e.get("target", "—"))],
                ["Heure",     esc(e.get("time", "—"))],
                ["Status",    "✓ OK" if e.get("rc") == 0 else f"✗ ERR (rc={e.get('rc')})"],
            ]
            t2 = Table(meta2, colWidths=[3*cm, 13.5*cm])
            t2.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (0,-1), colors.HexColor("#e8f5ec")),
                ("FONTSIZE",   (0,0), (-1,-1), 9),
                ("GRID",       (0,0), (-1,-1), 0.3, colors.HexColor("#cccccc")),
                ("VALIGN",     (0,0), (-1,-1), "TOP"),
                ("LEFTPADDING",  (0,0), (-1,-1), 5),
                ("RIGHTPADDING", (0,0), (-1,-1), 5),
            ]))
            block.append(t2)
            block.append(Spacer(1, 0.2*cm))

            # Commande
            block.append(Paragraph("Commande", H3))
            block.append(Paragraph(f"<font face='Courier'>$ {esc(e.get('cmd',''))}</font>",
                                   MONO))
            block.append(Spacer(1, 0.15*cm))

            # Données structurées (parsed) — partie LISIBLE
            parsed = e.get("parsed") or {}
            if parsed and parsed.get("parser") not in (None, "generic", "url"):
                block.append(Paragraph(
                    f"Résultats analysés ({parsed.get('parser','')})", H3))
                ptable = self._parsed_to_table(parsed, esc)
                if ptable:
                    block.append(ptable)
                    block.append(Spacer(1, 0.2*cm))

            # Sortie brute (limitée pour ne pas exploser le PDF)
            raw = (e.get("raw") or "").strip()
            if raw:
                block.append(Paragraph("Sortie brute (extrait)", H3))
                lines = raw.splitlines()
                snippet = "\n".join(lines[:80])
                if len(lines) > 80:
                    snippet += f"\n[… {len(lines)-80} lignes supplémentaires tronquées …]"
                for ln in snippet.splitlines():
                    block.append(Paragraph(esc(ln) if ln else "&nbsp;", MONO))
            block.append(Spacer(1, 0.4*cm))
            try:
                story.append(KeepTogether(block))
            except Exception:
                story.extend(block)

        # ── Footer numérotation
        def _on_page(canvas, doc_):
            canvas.saveState()
            canvas.setFont("Helvetica", 8)
            canvas.setFillColor(colors.HexColor("#888888"))
            canvas.drawString(1.6*cm, 1*cm,
                              f"MDOS Session Report · {self.pseudo or ''}")
            canvas.drawRightString(A4[0] - 1.6*cm, 1*cm,
                                   f"Page {doc_.page}")
            canvas.restoreState()

        doc.build(story, onFirstPage=_on_page, onLaterPages=_on_page)
        return True

    def _parsed_to_table(self, parsed: dict, esc):
        """Convertit la sortie parsée en Table reportlab lisible."""
        try:
            from reportlab.platypus import Table, TableStyle, Paragraph
            from reportlab.lib import colors
            from reportlab.lib.units import cm
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            BODY = ParagraphStyle("B", parent=getSampleStyleSheet()["BodyText"],
                                  fontSize=9, leading=11)
        except Exception:
            return None
        rows = []
        parser = parsed.get("parser", "")
        if parser == "nmap":
            ports = parsed.get("ports", [])
            if ports:
                rows.append(["Port", "Proto", "État", "Service", "Version"])
                for p in ports:
                    rows.append([
                        str(p.get("port", "")),
                        p.get("protocol", ""),
                        p.get("state", ""),
                        p.get("service", ""),
                        (p.get("version", "") or "")[:50],
                    ])
                cw = [1.6*cm, 1.6*cm, 2*cm, 3*cm, 8.3*cm]
            extras = []
            if parsed.get("hosts"):
                extras.append(["Hôtes",     ", ".join(parsed["hosts"])[:200]])
            if parsed.get("os"):
                extras.append(["OS",        " | ".join(parsed["os"])[:200]])
            if parsed.get("os_running"):
                extras.append(["Running",   str(parsed["os_running"])[:200]])
            if parsed.get("mac_address"):
                extras.append(["MAC",       f"{parsed['mac_address']} ({parsed.get('mac_vendor','?')})"])
            if "open_ports_count" in parsed:
                extras.append(["Ports ouverts", str(parsed["open_ports_count"])])
            if parsed.get("duration_sec"):
                extras.append(["Durée (s)", str(parsed["duration_sec"])])

            result = []
            if extras:
                tt = Table(extras, colWidths=[3.5*cm, 13*cm])
                tt.setStyle(TableStyle([
                    ("BACKGROUND", (0,0), (0,-1), colors.HexColor("#e8f5ec")),
                    ("FONTSIZE",   (0,0), (-1,-1), 9),
                    ("GRID",       (0,0), (-1,-1), 0.3, colors.HexColor("#cccccc")),
                    ("VALIGN",     (0,0), (-1,-1), "TOP"),
                    ("LEFTPADDING",(0,0),(-1,-1), 5),
                    ("RIGHTPADDING",(0,0),(-1,-1), 5),
                ]))
                result.append(tt)
            if rows:
                pt = Table(rows, colWidths=cw, repeatRows=1)
                pt.setStyle(TableStyle([
                    ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#0a7a3a")),
                    ("TEXTCOLOR",  (0,0), (-1,0), colors.white),
                    ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
                    ("FONTSIZE",   (0,0), (-1,-1), 8),
                    ("GRID",       (0,0), (-1,-1), 0.3, colors.HexColor("#cccccc")),
                    ("ROWBACKGROUNDS", (0,1), (-1,-1),
                        [colors.white, colors.HexColor("#f4faf6")]),
                    ("VALIGN",     (0,0), (-1,-1), "TOP"),
                ]))
                if result:
                    from reportlab.platypus import Spacer
                    result.append(Spacer(1, 0.15*cm))
                result.append(pt)
            if not result:
                return None
            # Wrap dans une table-conteneur pour rester ensemble
            wrap = Table([[result]], colWidths=[16.5*cm])
            wrap.setStyle(TableStyle([("LEFTPADDING",(0,0),(-1,-1),0),
                                      ("RIGHTPADDING",(0,0),(-1,-1),0),
                                      ("TOPPADDING",(0,0),(-1,-1),0),
                                      ("BOTTOMPADDING",(0,0),(-1,-1),0)]))
            return wrap

        elif parser == "hping3":
            r = parsed.get("ports_responded", [])
            summary = parsed.get("summary", {})
            data = [["Métrique", "Valeur"]]
            for k, v in summary.items():
                data.append([k, str(v)])
            data.append(["Ports ayant répondu", str(len(r))])
            if r[:20]:
                data.append(["Détail (max 20)",
                             ", ".join(f"{x['port']}({x['flags']})" for x in r[:20])])
            tt = Table(data, colWidths=[4*cm, 12.5*cm], repeatRows=1)
            tt.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#0a7a3a")),
                ("TEXTCOLOR",  (0,0), (-1,0), colors.white),
                ("FONTSIZE",   (0,0), (-1,-1), 9),
                ("GRID",       (0,0), (-1,-1), 0.3, colors.HexColor("#cccccc")),
            ]))
            return tt

        elif parser == "traceroute":
            hops = parsed.get("hops", [])
            data = [["Hop", "Info"]]
            for h in hops:
                data.append([str(h["hop"]), h["info"][:90]])
            tt = Table(data, colWidths=[1.5*cm, 15*cm], repeatRows=1)
            tt.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#0a7a3a")),
                ("TEXTCOLOR",  (0,0), (-1,0), colors.white),
                ("FONTSIZE",   (0,0), (-1,-1), 8),
                ("GRID",       (0,0), (-1,-1), 0.3, colors.HexColor("#cccccc")),
            ]))
            return tt

        elif parser == "nikto":
            data = [["Champ", "Valeur"]]
            data.append(["Server", parsed.get("server", "—") or "—"])
            data.append(["Findings", str(parsed.get("findings_count", 0))])
            for f in (parsed.get("findings") or [])[:25]:
                data.append(["•", f[:120]])
            tt = Table(data, colWidths=[3*cm, 13.5*cm], repeatRows=1)
            tt.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#0a7a3a")),
                ("TEXTCOLOR",  (0,0), (-1,0), colors.white),
                ("FONTSIZE",   (0,0), (-1,-1), 8),
                ("GRID",       (0,0), (-1,-1), 0.3, colors.HexColor("#cccccc")),
            ]))
            return tt

        elif parser == "theHarvester":
            data = [["Type", "Valeur"]]
            for em in parsed.get("emails", [])[:50]:
                data.append(["Email", em])
            for h in parsed.get("hosts", [])[:50]:
                data.append(["Host", h])
            if len(data) == 1:
                return None
            tt = Table(data, colWidths=[2.5*cm, 14*cm], repeatRows=1)
            tt.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#0a7a3a")),
                ("TEXTCOLOR",  (0,0), (-1,0), colors.white),
                ("FONTSIZE",   (0,0), (-1,-1), 8),
                ("GRID",       (0,0), (-1,-1), 0.3, colors.HexColor("#cccccc")),
            ]))
            return tt
        return None

    # ── FPDF (fallback léger) ─────────────────────────────
    def _pdf_fpdf(self, path: str) -> bool:
        try:
            from fpdf import FPDF
        except Exception:
            return False

        class MDOSPdf(FPDF):
            def header(self_p):
                self_p.set_font("Helvetica", "B", 13)
                self_p.set_text_color(10, 122, 58)
                self_p.cell(0, 8, "MDOS - Rapport de Session", ln=1)
                self_p.set_draw_color(10, 122, 58)
                self_p.line(10, 22, 200, 22)
                self_p.ln(4)
            def footer(self_p):
                self_p.set_y(-12)
                self_p.set_font("Helvetica", "", 8)
                self_p.set_text_color(120, 120, 120)
                self_p.cell(0, 6, f"Page {self_p.page_no()}", align="C")

        pdf = MDOSPdf(format="A4")
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(0, 0, 0)
        pdf.multi_cell(0, 6,
            f"Utilisateur : {self.pseudo}\n"
            f"Hote        : {socket.gethostname()}\n"
            f"Date        : {now_iso()}\n"
            f"Commandes   : {len(self.session_log)}\n")
        pdf.ln(4)

        for i, e in enumerate(self.session_log, 1):
            pdf.set_font("Helvetica", "B", 11)
            pdf.set_text_color(10, 122, 58)
            pdf.multi_cell(0, 6, f"#{i} - {e.get('tool','')}")
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Helvetica", "", 9)
            pdf.multi_cell(0, 5,
                f"Cible : {e.get('target','')}\n"
                f"Heure : {e.get('time','')}\n"
                f"Status: {'OK' if e.get('rc')==0 else 'ERR'}\n")
            pdf.set_font("Courier", "", 8)
            pdf.multi_cell(0, 4, f"$ {e.get('cmd','')}")
            pdf.ln(1)
            parsed = e.get("parsed") or {}
            if parsed.get("parser") == "nmap":
                pdf.set_font("Helvetica", "B", 9)
                pdf.multi_cell(0, 5, "Ports ouverts:")
                pdf.set_font("Courier", "", 8)
                for p in parsed.get("ports", []):
                    pdf.multi_cell(0, 4,
                        f"  {p.get('port')}/{p.get('protocol')}  "
                        f"{p.get('state')}  {p.get('service')}  "
                        f"{p.get('version','')[:60]}")
            raw = (e.get("raw") or "").strip()
            if raw:
                pdf.set_font("Helvetica", "B", 9)
                pdf.multi_cell(0, 5, "Sortie:")
                pdf.set_font("Courier", "", 7)
                for ln in raw.splitlines()[:60]:
                    # FPDF ne gère pas l'unicode étendu sans police custom
                    safe = ln.encode("latin-1", "replace").decode("latin-1")
                    pdf.multi_cell(0, 3.5, safe)
            pdf.ln(3)
        pdf.output(path)
        return True

    # ── Fallback HTML ─────────────────────────────────────
    def _pdf_html_fallback(self, path: Path):
        def esc(t):
            return (str(t).replace("&","&amp;").replace("<","&lt;")
                          .replace(">","&gt;"))
        rows = []
        for i, e in enumerate(self.session_log, 1):
            parsed = e.get("parsed") or {}
            ptable = ""
            if parsed.get("parser") == "nmap" and parsed.get("ports"):
                rrows = "".join(
                    f"<tr><td>{p.get('port')}</td><td>{p.get('protocol')}</td>"
                    f"<td>{p.get('state')}</td><td>{esc(p.get('service',''))}</td>"
                    f"<td>{esc(p.get('version',''))}</td></tr>"
                    for p in parsed["ports"])
                ptable = (f"<table class='p'><thead><tr><th>Port</th><th>Proto</th>"
                          f"<th>État</th><th>Service</th><th>Version</th></tr></thead>"
                          f"<tbody>{rrows}</tbody></table>")
            rows.append(f"""
<section>
  <h2>#{i} — {esc(e.get('tool',''))}</h2>
  <p><b>Cible :</b> {esc(e.get('target',''))} &nbsp;
     <b>Heure :</b> {esc(e.get('time',''))} &nbsp;
     <b>Status :</b> {'OK' if e.get('rc')==0 else 'ERR'}</p>
  <pre class='cmd'>$ {esc(e.get('cmd',''))}</pre>
  {ptable}
  <pre class='out'>{esc(e.get('raw',''))[:6000]}</pre>
</section>""")
        html = f"""<!doctype html><html><head><meta charset='utf-8'>
<title>MDOS Report</title>
<style>
body{{font-family:Helvetica,Arial,sans-serif;color:#222;max-width:900px;margin:24px auto;padding:0 16px}}
h1{{color:#0a7a3a}} h2{{color:#0a7a3a;border-bottom:1px solid #ccc;padding-bottom:4px}}
.cmd{{background:#f0f7f2;padding:8px;border-left:3px solid #0a7a3a;font-family:Courier,monospace;font-size:12px}}
.out{{background:#fafafa;border:1px solid #eee;padding:8px;font-family:Courier,monospace;font-size:11px;white-space:pre-wrap;max-height:400px;overflow:auto}}
table.p{{border-collapse:collapse;margin:8px 0;font-size:12px}}
table.p th{{background:#0a7a3a;color:#fff;padding:4px 8px;text-align:left}}
table.p td{{border:1px solid #ddd;padding:3px 8px}}
</style></head><body>
<h1>MDOS — Rapport de Session</h1>
<p><b>Utilisateur :</b> {esc(self.pseudo)} &nbsp; <b>Hôte :</b> {esc(socket.gethostname())}
   &nbsp; <b>Date :</b> {esc(now_iso())} &nbsp; <b>Commandes :</b> {len(self.session_log)}</p>
{"".join(rows)}
</body></html>"""
        Path(path).write_text(html, encoding="utf-8")

    # ══════════════════════════════════════════════
    #  EXPORT NOTION
    # ══════════════════════════════════════════════
    def _load_notion_env(self):
        """Charge .env depuis cwd ou répertoire du script. Retourne (token, db_id)."""
        token = os.environ.get("NOTION_TOKEN")
        db_id = os.environ.get("NOTION_DATABASE_ID")
        if token and db_id:
            return token, db_id
        # Cherche un .env
        candidates = [
            Path.cwd() / ".env",
            Path(__file__).resolve().parent / ".env",
            Path.home() / ".mdos.env",
        ]
        for envp in candidates:
            if envp.exists():
                try:
                    for ln in envp.read_text(encoding="utf-8").splitlines():
                        ln = ln.strip()
                        if not ln or ln.startswith("#") or "=" not in ln:
                            continue
                        k, v = ln.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip('"').strip("'")
                        if k == "NOTION_TOKEN" and not token:
                            token = v
                        elif k == "NOTION_DATABASE_ID" and not db_id:
                            db_id = v
                    if token and db_id:
                        return token, db_id
                except Exception:
                    pass
        return token, db_id

    def _prompt_notion_credentials(self):
        """Popup pour saisir token + database_id si manquants."""
        s = self.scale
        result = {"token": None, "db": None, "save": False}
        dlg = tk.Toplevel(self.root)
        dlg.title("Configuration Notion")
        dlg.configure(bg=C["bg"])
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.geometry(f"{s.px(520)}x{s.px(320)}")

        tk.Label(dlg, text="◈  CONFIGURATION NOTION",
                 fg=C["purple"], bg=C["bg"],
                 font=self._fonts["big_b"]).pack(pady=(s.px(14), s.px(4)))
        tk.Label(dlg,
                 text="Aucun .env trouvé. Entre tes credentials Notion :",
                 fg=C["text_dim"], bg=C["bg"],
                 font=self._fonts["small"]).pack(pady=(0, s.px(10)))

        frm = tk.Frame(dlg, bg=C["bg"])
        frm.pack(padx=s.px(20), pady=s.px(4), fill="x")

        tk.Label(frm, text="// NOTION_TOKEN (secret_… )",
                 fg=C["text_dim"], bg=C["bg"],
                 font=self._fonts["tiny"]).pack(anchor="w")
        e_tok = tk.Entry(frm, bg=C["entry_bg"], fg=C["green"],
                         insertbackground=C["green"],
                         font=self._fonts["entry"], relief="flat",
                         highlightbackground=C["border"], highlightthickness=1,
                         show="•")
        e_tok.pack(fill="x", pady=(s.px(2), s.px(8)))

        tk.Label(frm, text="// NOTION_DATABASE_ID",
                 fg=C["text_dim"], bg=C["bg"],
                 font=self._fonts["tiny"]).pack(anchor="w")
        e_db = tk.Entry(frm, bg=C["entry_bg"], fg=C["green"],
                        insertbackground=C["green"],
                        font=self._fonts["entry"], relief="flat",
                        highlightbackground=C["border"], highlightthickness=1)
        e_db.pack(fill="x", pady=(s.px(2), s.px(8)))

        save_var = tk.BooleanVar(value=True)
        tk.Checkbutton(frm,
                       text="Sauvegarder dans ~/.mdos.env (recommandé)",
                       variable=save_var,
                       fg=C["text_dim"], bg=C["bg"],
                       selectcolor=C["bg"],
                       activebackground=C["bg"],
                       activeforeground=C["green"],
                       font=self._fonts["small"]).pack(anchor="w", pady=s.px(4))

        btns = tk.Frame(dlg, bg=C["bg"])
        btns.pack(pady=s.px(10))

        def ok():
            result["token"] = e_tok.get().strip()
            result["db"]    = e_db.get().strip()
            result["save"]  = save_var.get()
            dlg.destroy()
        def cancel():
            dlg.destroy()

        self.green_btn(btns, "▶  CONFIRMER", ok).pack(side="left", padx=s.px(4))
        self.sec_btn(btns, "✕  ANNULER", cancel).pack(side="left", padx=s.px(4))
        e_tok.focus_set()
        self.root.wait_window(dlg)
        # Sauvegarde optionnelle
        if result["token"] and result["db"] and result["save"]:
            try:
                envp = Path.home() / ".mdos.env"
                envp.write_text(
                    f"NOTION_TOKEN={result['token']}\n"
                    f"NOTION_DATABASE_ID={result['db']}\n",
                    encoding="utf-8")
                try:
                    os.chmod(envp, 0o600)
                except Exception:
                    pass
            except Exception:
                pass
        return result["token"], result["db"]

    def _export_session_notion(self):
        if not self.session_log:
            self._notify("⚠  Aucun résultat à exporter", error=True)
            return
        token, db_id = self._load_notion_env()
        if not token or not db_id:
            token, db_id = self._prompt_notion_credentials()
            if not token or not db_id:
                self._notify("⛔ Export Notion annulé", error=True)
                return
        self._notify("⏳ Envoi vers Notion en cours…")
        threading.Thread(target=self._push_to_notion,
                         args=(token, db_id), daemon=True).start()

    # ── Notion API helpers (adaptés du script fourni) ─────
    @staticmethod
    def _notion_split(text, max_length=1900):
        if not isinstance(text, str):
            text = str(text)
        return [text[i:i+max_length] for i in range(0, max(len(text), 1), max_length)]

    @staticmethod
    def _notion_paragraph(text):
        return {
            "object": "block", "type": "paragraph",
            "paragraph": {
                "rich_text": [{"type": "text", "text": {"content": text[:1900]}}]
            }
        }

    @classmethod
    def _notion_code_blocks(cls, text, language="plain text"):
        valid = ["bash","json","python","plain text","javascript","html","css","sql"]
        if language not in valid:
            language = "plain text"
        blocks = []
        for chunk in cls._notion_split(text or "—"):
            blocks.append({
                "object": "block", "type": "code",
                "code": {
                    "rich_text": [{"type": "text", "text": {"content": chunk}}],
                    "language": language
                }
            })
        return blocks

    @staticmethod
    def _notion_toggle(title, children):
        return {
            "object": "block", "type": "toggle",
            "toggle": {
                "rich_text": [{"type": "text", "text": {"content": title[:200]}}],
                "children": children
            }
        }

    @staticmethod
    def _notion_clean(t):
        if not isinstance(t, str):
            t = str(t)
        return t.replace("**", "").replace("__", "").strip()

    def _push_to_notion(self, token, db_id):
        try:
            import requests
        except ImportError:
            self.root.after(0, lambda: self._notify(
                "⛔ Module 'requests' manquant — pip install requests",
                error=True))
            return
        headers = {
            "Authorization": f"Bearer {token}",
            "Notion-Version": "2022-06-28",
            "Content-Type": "application/json",
        }
        title = f"Rapport MDOS — {self.pseudo} — {datetime.datetime.now().strftime('%d-%m-%Y %H:%M')}"

        # ── Création de la page (props défensives : Type optionnel)
        payload_full = {
            "parent": {"database_id": db_id},
            "properties": {
                "Name": {"title": [{"text": {"content": title}}]},
                "Type": {"select": {"name": "MDOS"}},
            }
        }
        payload_minimal = {
            "parent": {"database_id": db_id},
            "properties": {
                "Name": {"title": [{"text": {"content": title}}]},
            }
        }
        try:
            r = requests.post("https://api.notion.com/v1/pages",
                              headers=headers, json=payload_full, timeout=30)
            if r.status_code != 200:
                # Réessaye sans Type (si la DB n'a pas cette propriété)
                r = requests.post("https://api.notion.com/v1/pages",
                                  headers=headers, json=payload_minimal, timeout=30)
            if r.status_code != 200:
                msg = f"⛔ Notion: {r.status_code} {r.text[:200]}"
                self.root.after(0, lambda m=msg: self._notify(m, error=True))
                return
            page_id = r.json()["id"]
        except Exception as ex:
            self.root.after(0, lambda: self._notify(f"⛔ Notion: {ex}", error=True))
            return

        # ── Organiser par catégorie
        categories = {}
        for entry in self.session_log:
            cat = (entry.get("cat") or "AUTRE").upper()
            categories.setdefault(cat, []).append(entry)

        total_blocks = 0
        # ── Une requête PATCH par catégorie (toggle parent)
        for cat, entries in categories.items():
            cat_children = []
            for entry in entries:
                tool   = self._notion_clean(entry.get("tool", ""))
                target = self._notion_clean(entry.get("target", "—"))
                date_s = self._notion_clean(entry.get("time", "")) or now_iso()
                cmd    = self._notion_clean(entry.get("cmd", ""))
                raw    = entry.get("raw", "") or ""
                parsed = entry.get("parsed") or {}
                rc     = entry.get("rc", 0)
                status = "✓ OK" if rc == 0 else f"✗ ERR (rc={rc})"

                entry_children = [
                    self._notion_paragraph(f"🔹 Outil : {tool}"),
                    self._notion_paragraph(f"🔹 Cible : {target}"),
                    self._notion_paragraph(f"🔹 Heure : {date_s}"),
                    self._notion_paragraph(f"🔹 Status : {status}"),
                    self._notion_paragraph("🔹 Commande :"),
                ]
                entry_children.extend(self._notion_code_blocks(cmd, "bash"))

                # ── Données analysées (lisibles) si parser réussi
                if parsed and parsed.get("parser") not in (None, "generic", "url", "error"):
                    entry_children.append(self._notion_paragraph(
                        f"📊 Données analysées ({parsed.get('parser')})"))
                    parsed_json = json.dumps(parsed, ensure_ascii=False, indent=2)
                    entry_children.extend(self._notion_code_blocks(parsed_json, "json"))

                # ── Sortie brute
                if raw.strip():
                    entry_children.append(self._notion_paragraph("📄 Sortie brute :"))
                    # Limite la sortie pour éviter spam Notion
                    raw_limited = raw if len(raw) < 8000 else (
                        raw[:8000] + f"\n[… {len(raw)-8000} caractères tronqués …]")
                    entry_children.extend(
                        self._notion_code_blocks(raw_limited, "plain text"))

                # Notion limite à 100 enfants par bloc dans une création nested
                # On découpe si trop d'enfants
                if len(entry_children) > 95:
                    entry_children = entry_children[:95] + [
                        self._notion_paragraph("… (contenu tronqué)")
                    ]

                cat_children.append(self._notion_toggle(
                    f"🛠️  {tool} → {target} [{status}]", entry_children))
                total_blocks += 1

            # Découpe si trop de toggles dans la catégorie
            for i in range(0, len(cat_children), 90):
                chunk = cat_children[i:i+90]
                wrap_title = f"📂 {cat}" + (f" (suite {i//90+1})" if i else "")
                block_payload = {"children": [self._notion_toggle(wrap_title, chunk)]}
                try:
                    r = requests.patch(
                        f"https://api.notion.com/v1/blocks/{page_id}/children",
                        headers=headers, json=block_payload, timeout=30)
                    if r.status_code != 200:
                        msg = f"⚠ Notion bloc '{cat}': {r.status_code} {r.text[:150]}"
                        self.root.after(0, lambda m=msg: self._notify(m, error=True))
                except Exception as ex:
                    self.root.after(0, lambda e=ex: self._notify(
                        f"⛔ Notion réseau: {e}", error=True))

        # ── URL de la page créée
        page_url = f"https://www.notion.so/{page_id.replace('-', '')}"
        self.root.after(0, lambda: self._notify(
            f"✅ Rapport envoyé sur Notion ({total_blocks} exécutions)"))

        # Petit popup avec le lien cliquable
        def show_link():
            s = self.scale
            dlg = tk.Toplevel(self.root)
            dlg.title("Notion — Page créée")
            dlg.configure(bg=C["bg"])
            dlg.transient(self.root)
            tk.Label(dlg, text="✅  RAPPORT NOTION CRÉÉ",
                     fg=C["green"], bg=C["bg"],
                     font=self._fonts["big_b"]).pack(padx=s.px(24),
                                                      pady=(s.px(16), s.px(6)))
            tk.Label(dlg, text=f"Titre : {title}",
                     fg=C["text"], bg=C["bg"],
                     font=self._fonts["small"]).pack(padx=s.px(24))
            tk.Label(dlg, text=f"{total_blocks} exécution(s) dans {len(categories)} catégorie(s)",
                     fg=C["text_dim"], bg=C["bg"],
                     font=self._fonts["small"]).pack(padx=s.px(24), pady=(s.px(2), s.px(10)))
            link = tk.Label(dlg, text=page_url,
                            fg=C["cyan"], bg=C["bg"],
                            font=self._fonts["small"],
                            cursor="hand2")
            link.pack(padx=s.px(24))
            link.bind("<Button-1>", lambda e: webbrowser.open(page_url))
            btns = tk.Frame(dlg, bg=C["bg"])
            btns.pack(pady=s.px(14))
            self.green_btn(btns, "🌐  OUVRIR",
                           lambda: webbrowser.open(page_url)).pack(side="left",
                                                                    padx=s.px(4))
            self.sec_btn(btns, "✕  FERMER", dlg.destroy).pack(side="left",
                                                               padx=s.px(4))
        self.root.after(0, show_link)

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

def create_notion_report(global_json):
    print("CLI Notion export...")
    print(f"Source : {global_json}")

    # TODO : reprendre ta logique Notion ici
    return True
