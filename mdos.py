#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import time
import shlex
import getpass
import socket
import webbrowser
import subprocess
from datetime import datetime
from pathlib import Path
import extract_users
import export_pdf
import export_notion

# -------------------------
#  Styling (ANSI)
# -------------------------
BOLD = "\033[1m"
UNDERLINE = "\033[4m"
BLINK = "\033[5m"
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
PURPLE = "\033[35m"
RESET = "\033[0m"

# -------------------------
#  Paths / Results
# -------------------------
RESULTS_DIR = Path.cwd() / "MDOS_RESULTS"
GLOBAL_JSON = RESULTS_DIR / "mdos_global.json"

def safe_mkdir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def pause(msg="Appuyez sur [Entrée] pour continuer..."):
    input(msg)


def center_text(text: str) -> str:
    # Best effort centering
    cols = 80
    try:
        cols = os.get_terminal_size().columns
    except OSError:
        pass
    pad = max((cols - len(text)) // 2, 0)
    return " " * pad + text


def spinner_loading(msg: str, loops: int = 5):
    frames = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
    for _ in range(loops):
        for f in frames:
            print(f"\r{f} {msg}", end="", flush=True)
            time.sleep(0.05)
    print("")


def init_global_json():
    safe_mkdir(RESULTS_DIR)
    if not GLOBAL_JSON.exists():
        GLOBAL_JSON.write_text("[]", encoding="utf-8")


def append_global_json(entry: dict):
    init_global_json()
    data = json.loads(GLOBAL_JSON.read_text(encoding="utf-8"))
    data.append(entry)
    GLOBAL_JSON.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def now_iso():
    # ISO 8601 with local offset
    return datetime.now().astimezone().isoformat(timespec="seconds")


def timestamp_for_filename():
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def run_cmd(cmd: str, capture=True) -> tuple[int, str]:
    """
    Run system command and return (returncode, combined_output).
    """
    try:
        p = subprocess.run(
            cmd if isinstance(cmd, list) else shlex.split(cmd),
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.STDOUT if capture else None,
            text=True,
            check=False
        )
        return p.returncode, (p.stdout or "")
    except FileNotFoundError:
        return 127, f"Command not found: {cmd}\n"
    except Exception as e:
        return 1, f"Error running command: {e}\n"


def export_json(tool: str, category: str, target: str, command: str, rc: int, output: str, extra: dict | None = None) -> Path:
    """
    Write one JSON file + append to global.
    """
    safe_mkdir(RESULTS_DIR / category)
    out_file = RESULTS_DIR / category / f"{tool}_{timestamp_for_filename()}.json"

    entry = {
        "tool": tool,
        "category": category,
        "target": target,
        "date": now_iso(),
        "user": getpass.getuser(),
        "host": socket.gethostname(),
        "command": command,
        "returncode": rc,
        "raw_output": output
    }
    if extra:
        entry["extra"] = extra

    out_file.write_text(json.dumps(entry, ensure_ascii=False, indent=2), encoding="utf-8")
    append_global_json(entry)
    try:
        export_notion.export_to_notion(entry)
    except Exception:
        pass
    return out_file


# -------------------------
#  2FA TOTP (Google Auth)
# -------------------------
def google_2fa_or_exit(require_2fa: bool = True):
    if not require_2fa:
        return

    auth_file = Path.home() / ".google_authenticator"
    print(f"\n{PURPLE}{BOLD}🔐 Authentification Google Authenticator requise{RESET}")

    if not auth_file.exists():
        print(f"{RED}{BOLD}Erreur:{RESET} fichier 2FA introuvable : {auth_file}")
        print("Génère-le avec : google-authenticator -t")
        sys.exit(1)

    # Read secret as first line
    secret = auth_file.read_text(encoding="utf-8", errors="ignore").splitlines()[0].strip().replace(" ", "")

    # Use pyotp if installed; otherwise fallback to oathtool if available
    otp = input("Code Google Authenticator (6 chiffres) : ").strip()

    # Try pyotp
    try:
        import pyotp  # type: ignore
        totp = pyotp.TOTP(secret)
        ok = totp.verify(otp, valid_window=1)
    except Exception:
        # Fallback: oathtool
        rc, out = run_cmd(f"oathtool --totp -b --window=1 {shlex.quote(secret)}", capture=True)
        ok = (rc == 0 and otp in out.split())

    if ok:
        print(f"{GREEN}{BOLD}✅ Authentification réussie.{RESET}")
        time.sleep(1)
    else:
        print(f"{RED}{BOLD}❌ Code incorrect. Fermeture du programme.{RESET}")
        time.sleep(1)
        sys.exit(1)


# -------------------------
#  UI
# -------------------------
def banner(require_2fa=True) -> str:
    clear()
    print(f"{RED}{BOLD}")
    print(center_text("Bienvenue !"))
    print(f"{RESET}\n")
    spinner_loading("Chargement de MDOS !", 6)
    pseudo = input(f"{BOLD}Quelle est ton Pseudo : {RESET}").strip()
    print("")
    print(f"Bienvenue, Welcome, مرحب, 欢迎你来 {RED}{pseudo}{RESET} !")
    time.sleep(1)
    google_2fa_or_exit(require_2fa=require_2fa)
    return pseudo


def ascii_intro():
    clear()
    print(f"{YELLOW}{BOLD}")
    print(r"""
.        *        .        *        .        *

        ⠀⠀⠀⠀⠀⢸⠓⢄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⠀⠀⠀⢸⠀⠀⠑⢤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⠀⠀⠀⢸⡆⠀⠀⠀⠙⢤⡷⣤⣦⣀⠤⠖⠚⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⣠⡿⠢⢄⡀⠀⡇⠀⠀⠀⠀⠀⠉⠀⠀⠀⠀⠀⠸⠷⣶⠂⠀⠀⠀⣀⣀⠀⠀⠀
        ⢸⣃⠀⠀⠉⠳⣷⠞⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠉⠉⠉⠉⠉⢉⡭⠋
        ⠀⠘⣆⠀⠀⠀⠁⠀⢀⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡴⠋⠀⠀
        ⠀⠀⠘⣦⠆⠀⠀⢀⡎⢹⡀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⡀⣠⠔⠋⠀⠀⠀⠀
        ⠀⠀⠀⡏⠀⠀⣆⠘⣄⠸⢧⠀⠀⠀⠀⢀⣠⠖⢻⠀⠀⠀⣿⢥⣄⣀⣀⣀⠀⠀
        ⠀⠀⢸⠁⠀⠀⡏⢣⣌⠙⠚⠀⠀⠠⣖⡛⠀⣠⠏⠀⠀⠀⠇⠀⠀⠀⠀⢙⣣⠄
        ⠀⠀⢸⡀⠀⠀⠳⡞⠈⢻⠶⠤⣄⣀⣈⣉⣉⣡⡔⠀⠀⢀⠀⠀⣀⡤⠖⠚⠀⠀
        ⠀⠀⡼⣇⠀⠀⠀⠙⠦⣞⡀⠀⢀⡏⠀⢸⣣⠞⠀⠀⠀⡼⠚⠋⠁⠀⠀⠀⠀⠀
        ⠀⢰⡇⠙⠀⠀⠀⠀⠀⠀⠉⠙⠚⠒⠚⠉⠀⠀⠀⠀⡼⠁⠀⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⢧⡀⠀⢠⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⣞⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⠀⠙⣶⣶⣿⠢⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⠀⠀⠀⠉⠀⠀⠀⠙⢿⣳⠞⠳⡄⠀⠀⠀⢀⡞⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠀⠀⠹⣄⣀⡤⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀

    .        *        .        *        .        *
""")
    time.sleep(0.8)
    print(f"{PURPLE}{BOLD}")
    print(r"""
    ███╗   ███╗██████╗  ██████╗ ███████╗
    ████╗ ████║██╔══██╗██╔═══██╗██╔════╝
    ██╔████╔██║██║  ██║██║   ██║███████╗
    ██║╚██╔╝██║██║  ██║██║   ██║╚════██║
    ██║ ╚═╝ ██║██████╔╝╚██████╔╝███████║
    ╚═╝     ╚═╝╚═════╝  ╚═════╝ ╚══════╝
            [  M  D  O  S  ]
        access granted ▓▓▓▓▓▓▓▓▓
""")
    time.sleep(0.8)
    print(RESET)


def menu(prompt: str, options: list[tuple[str, str]]) -> str:
    """
    options: list of (key, label)
    returns selected key
    """
    while True:
        clear()
        print(f"{BOLD}{prompt}{RESET}")
        print(f"{PURPLE}{'-'*37}{RESET}")
        for k, label in options:
            print(f"{k}. {label}")
        print(f"{PURPLE}{'-'*37}{RESET}\n")
        choice = input("Entrez votre choix : ").strip()
        keys = {k for k, _ in options}
        if choice in keys:
            return choice
        print("Choix non valide.")
        time.sleep(1)


# -------------------------
#  Actions helpers
# -------------------------
def do_command(tool: str, category: str, target: str, command: str, extra: dict | None = None, show_live=False):
    print("")
    print(f"{BOLD}Exécution :{RESET} {command}\n")

    if show_live:
        # Live mode: do not capture; still create json with placeholder output
        rc, out = run_cmd(command, capture=False)
        out = "(live output not captured)"
    else:
        rc, out = run_cmd(command, capture=True)

    out_file = export_json(tool=tool, category=category, target=target, command=command, rc=rc, output=out, extra=extra)
    print(f"{GREEN}{BOLD}✅ Export JSON:{RESET} {out_file}")
    print(f"{GREEN}{BOLD}✅ Global JSON:{RESET} {GLOBAL_JSON}\n")
    pause()

def get_clipboard():
    try:
        # Linux (xclip)
        rc, out = run_cmd("xclip -selection clipboard -o")
        if rc == 0 and out.strip():
            return out.strip()
    except Exception:
        pass

    try:
        # Wayland (wl-clipboard)
        rc, out = run_cmd("wl-paste")
        if rc == 0 and out.strip():
            return out.strip()
    except Exception:
        pass

    return ""

def prompt_manual_entry(source: str):
    print(f"\n{YELLOW}{BOLD}📝 Ajouter un résultat au rapport ? (y/n){RESET}")
    choice = input(">>> ").strip().lower()

    if choice != "y":
        return

    title = input("Titre : ").strip()

    print(f"\n{YELLOW}👉 Appuie sur Entrée pour utiliser le presse-papier automatiquement{RESET}")
    print(f"{YELLOW}👉 Ou colle manuellement puis Entrée{RESET}")

    content_input = input("Contenu : ").strip()

    # 🔥 si rien tapé → on récupère le clipboard
    if not content_input:
        clipboard = get_clipboard()
        if clipboard:
            content = clipboard
            print(f"{GREEN}📋 Contenu récupéré depuis le presse-papier !{RESET}")
        else:
            print(f"{RED}⛔ Presse-papier vide et aucun contenu saisi.{RESET}")
            time.sleep(1)
            return
    else:
        content = content_input

    if not title or not content.strip():
        print(f"{RED}⛔ Entrée vide, rien sauvegardé.{RESET}")
        time.sleep(1)
        return

    export_json(
        tool="manual",
        category="notes",
        target=source,
        command="manual_entry",
        rc=0,
        output=content,
        extra={"title": title}
    )

    print(f"{GREEN}{BOLD}✅ Ajouté au rapport !{RESET}")
    time.sleep(1)

# -------------------------
#  Main program
# -------------------------
def main():
    require_2fa = True
    if "--no-2fa" in sys.argv:
        require_2fa = False

    # Optional: custom results dir
    for i, arg in enumerate(sys.argv):
        if arg == "--results-dir" and i + 1 < len(sys.argv):
            global RESULTS_DIR, GLOBAL_JSON
            RESULTS_DIR = Path(sys.argv[i + 1]).expanduser()
            GLOBAL_JSON = RESULTS_DIR / "mdos_global.json"

    safe_mkdir(RESULTS_DIR)
    init_global_json()

    pseudo = banner(require_2fa=require_2fa)
    ascii_intro()

    while True:
        choice = menu(
            "Bienvenue dans MDOS",
            [
                ("1", "Network Scan"),
                ("2", "Footprinting and Reconnaissance"),
                ("3", "Enumeration"),
                ("4", "Analyse de vulnérabilité"),
                ("5", "Sniffing"),
                ("6", "Hacking Web Servers"),
                ("7", "Generate PDF Report"),
                ("8", "Quitter"),
            ],
        )

        # ---------------- Network Scan ----------------
        if choice == "1":
            scan_tool = menu(
                "Outils de scan disponibles",
                [("1", "Nmap"), ("2", "UnicornScan"), ("3", "Hping3"), ("4", "Retour")],
            )
            if scan_tool == "1":
                nmap_choice = menu(
                    "Commandes Nmap disponibles",
                    [
                        ("1", "Scanner les ports ouverts sur une adresse IP"),
                        ("2", "Scanner les ports ouverts sur un sous-réseau"),
                        ("3", "Scanner les services en exécution sur une adresse IP"),
                        ("4", "Scanner les systèmes d'exploitation en exécution sur une adresse IP"),
                        ("5", "Faire un scan agressif"),
                        ("6", "Retour"),
                    ],
                )
                if nmap_choice == "6":
                    continue

                if nmap_choice == "1":
                    ip = input("Entrez l'adresse IP à scanner : ").strip()
                    do_command("nmap", "scans", ip, f"nmap -p- {shlex.quote(ip)}")
                elif nmap_choice == "2":
                    subnet = input("Entrez le sous-réseau à scanner : ").strip()
                    do_command("nmap", "scans", subnet, f"nmap -p- {shlex.quote(subnet)}")
                elif nmap_choice == "3":
                    ip = input("Entrez l'adresse IP à scanner : ").strip()
                    do_command("nmap", "scans", ip, f"nmap -sV {shlex.quote(ip)}")
                elif nmap_choice == "4":
                    ip = input("Entrez l'adresse IP à scanner : ").strip()
                    do_command("nmap", "scans", ip, f"nmap -O {shlex.quote(ip)}")
                elif nmap_choice == "5":
                    ip = input("Entrez l'adresse IP à scanner : ").strip()
                    do_command("nmap", "scans", ip, f"nmap -A {shlex.quote(ip)}")

            elif scan_tool == "2":
                u_choice = menu("Commandes UnicornScan disponibles", [("1", "Découverte OS (TTL)"), ("2", "Retour")])
                if u_choice == "1":
                    ip = input("Entrez l'adresse IP à scanner : ").strip()
                    print("\nRappel TTL : Linux/FreeBSD=64, Windows=128, Cisco/OpenBSD/Solaris=255\n")
                    # NOTE: in bash you installed package; in python we won't auto-install.
                    do_command("unicornscan", "scans", ip, f"unicornscan {shlex.quote(ip)} -Iv", extra={"ttl_hint": True})
                else:
                    continue

            elif scan_tool == "3":
                h_choice = menu(
                    "Commandes Hping3 disponibles",
                    [
                        ("1", "Scan SYN (0-100) verbose"),
                        ("2", "Scan plage de ports"),
                        ("3", "ICMP (rand-dest) sur interface"),
                        ("4", "UDP test sur port 80 (5 paquets)"),
                        ("5", "Retour"),
                    ],
                )
                if h_choice == "1":
                    ip = input("Entrez l'adresse IP à scanner : ").strip()
                    do_command("hping3", "scans", ip, f"hping3 -8 0-100 -S {shlex.quote(ip)} -V")
                elif h_choice == "2":
                    ip = input("Entrez l'adresse IP à scanner : ").strip()
                    ports = input("Entrez la range de port [0-65536] : ").strip()
                    do_command("hping3", "scans", ip, f"hping3 --scan {shlex.quote(ports)} -S {shlex.quote(ip)}")
                elif h_choice == "3":
                    ip = input("Entrez l'adresse IP à scanner : ").strip()
                    do_command("hping3", "scans", ip, f"hping3 -1 {shlex.quote(ip)} --rand-dest -I eth0 -c 10")
                elif h_choice == "4":
                    ip = input("Entrez l'adresse IP à scanner : ").strip()
                    do_command("hping3", "scans", ip, f"hping3 -2 {shlex.quote(ip)} -p 80 -c 5")
                else:
                    continue

            else:
                continue

        # ---------------- Footprinting ----------------
        elif choice == "2":
            fp = menu(
                "Outils de Footprinting and Reconnaissance disponibles",
                [
                    ("1", "Infos vidéo YouTube (mattw.io)"),
                    ("2", "Recherche FTP (SearchFTPS)"),
                    ("3", "Liste emails (theHarvester)"),
                    ("4", "OS sur Censys"),
                    ("5", "LinkedIn entreprise (theHarvester)"),
                    ("6", "Infos sur une personne (Sherlock)"),
                    ("7", "Wordlist site (CEWL)"),
                    ("8", "Whois (DomainTools)"),
                    ("9", "Traceroute"),
                    ("10", "Vérif domaines existants (domainfy)"),
                    ("11", "Détails utilisateur sur réseaux (searchfy)"),
                    ("12", "Wordpress extract users"),
                    ("13", "Retour"),
                ],
            )
            if fp == "1":
                url = "https://mattw.io/youtube-metadata/"
                webbrowser.open(url)
                input("Appuie sur Entrée après ta recherche...")
                prompt_manual_entry(url)

            elif fp == "2":
                url = "https://www.searchftps.net/"
                webbrowser.open(url)
                input("Appuie sur Entrée après ta recherche...")
                prompt_manual_entry(url)

            elif fp == "3":
                target = input("Entrez le nom de la cible : ").strip()
                do_command("theHarvester", "footprinting", target, f"theHarvester -d {shlex.quote(target)} -l 200 -b google")

            elif fp == "4":
                url = "https://search.censys.io/?q"
                webbrowser.open(url)
                input("Appuie sur Entrée après ta recherche...")
                prompt_manual_entry(url)

            elif fp == "5":
                target = input("Entrez le nom de la cible : ").strip()
                do_command("theHarvester", "footprinting", target, f"theHarvester -d {shlex.quote(target)} -l 200 -b linkedin")

            elif fp == "6":
                name = input("Entrez le nom de la cible : ").strip()
                do_command("sherlock", "footprinting", name, f"python3 sherlock {shlex.quote(name)}")

            elif fp == "7":
                site = input("Entrez le site web cible : ").strip()
                do_command("cewl", "footprinting", site, f"cewl -w wordlist.txt -d 2 -m 5 {shlex.quote(site)}")

            elif fp == "8":
                url = "http://whois.domaintools.com"
                webbrowser.open(url)
                input("Appuie sur Entrée après ta recherche...")
                prompt_manual_entry(url)

            elif fp == "9":
                target = input("Entrez la cible (ip/domaine) : ").strip()
                do_command("traceroute", "footprinting", target, f"traceroute {shlex.quote(target)}")

            elif fp == "10":
                dom = input("Entrez le nom de domaine : ").strip()
                do_command("domainfy", "footprinting", dom, f"domainfy -n {shlex.quote(dom)} -t all")

            elif fp == "11":
                name = input("Entrez le nom de la cible : ").strip()
                do_command("searchfy", "footprinting", name, f"searchfy -q {shlex.quote(name)}")

            elif fp == "12":
                url = input("Entrez l'url de la cible : ").strip()
                endpoint = extract_users.normalize(url)
                result = extract_users.enumerate_users(
                    endpoint,
                    export_func=export_json
                )
                pause()

            else:
                continue

        # ---------------- Enumeration ----------------
        elif choice == "3":
            en = menu(
                "Outils d'Enumeration disponibles",
                [
                    ("1", "NetBIOS (Nmap NSE nbstat)"),
                    ("2", "SNMP"),
                    ("3", "LDAP"),
                    ("4", "NFS/RPC (RPCScan)"),
                    ("5", "DNS"),
                    ("6", "SMTP"),
                    ("7", "RPC/SMB/FTP (scan et focus port)"),
                    ("8", "Retour"),
                ],
            )
            if en == "1":
                ip = input("Entrez l'IP de la cible : ").strip()
                do_command("nmap", "enumeration", ip, f"nmap -sV -v --script nbstat.nse {shlex.quote(ip)}")
            elif en == "2":
                sn = menu("Outils SNMP disponibles", [("1","snmp-check"),("2","snmpwalk"),("3","nmap snmp-processes (UDP)"),("4","Retour")])
                if sn == "1":
                    ip = input("Entrez l'IP de la cible : ").strip()
                    do_command("snmp-check", "enumeration", ip, f"snmp-check {shlex.quote(ip)}")
                elif sn == "2":
                    ip = input("Entrez l'IP de la cible : ").strip()
                    do_command("snmpwalk", "enumeration", ip, f"snmpwalk -v2c -c public {shlex.quote(ip)}")
                elif sn == "3":
                    ip = input("Entrez l'IP de la cible : ").strip()
                    port = input("Entrez le port : ").strip()
                    do_command("nmap", "enumeration", ip, f"nmap -sU -p {shlex.quote(port)} --script=snmp-processes {shlex.quote(ip)}")
                else:
                    continue
            elif en == "3":
                ip = input("Entrez l'IP du serveur LDAP cible : ").strip()
                do_command("ldapsearch", "enumeration", ip, f"ldapsearch -h {shlex.quote(ip)} -x -s base namingcontexts")
            elif en == "4":
                print("\nTODO: recoller ton bloc RPCScan (cd RPCScan + python3 rpc-scan.py ...)\n")
                export_json("rpcscan", "enumeration", "N/A", "TODO", 0, "TODO: rpcscan not implemented", extra={"todo": True})
                pause()
            elif en == "5":
                dom = input("Entrez le nom de domaine cible : ").strip()
                do_command("nmap", "enumeration", dom, f"nmap --script=broadcast-dns-service-discovery {shlex.quote(dom)}")
                do_command("nmap", "enumeration", dom, f"nmap -T4 -p 53 --script dns-brute {shlex.quote(dom)}")
            elif en == "6":
                ip = input("Entrez l'IP du serveur SMTP cible : ").strip()
                do_command("nmap", "enumeration", ip, f"nmap -p 25 --script=smtp-enum-users {shlex.quote(ip)}")
                do_command("nmap", "enumeration", ip, f"nmap -p 25 --script=smtp-open-relay {shlex.quote(ip)}")
            elif en == "7":
                print("\nTODO: recoller ton bloc RPC/SMB/FTP multi-ports (scan général + focus port)\n")
                export_json("rpc_smb_ftp", "enumeration", "N/A", "TODO", 0, "TODO: not implemented", extra={"todo": True})
                pause()
            else:
                continue

        # ---------------- Vuln Analysis ----------------
        elif choice == "4":
            va = menu(
                "Outils d'Analyse de vulnérabilité disponibles",
                [("1","CWE (MITRE)"),("2","CVE (MITRE)"),("3","NVD (NIST)"),("4","Nikto (scan web)"),("5","Retour")],
            )

            if va == "1":
                url = "https://cwe.mitre.org/"
                webbrowser.open(url)
                input("Appuie sur Entrée après ta recherche...")
                prompt_manual_entry(url)

            elif va == "2":
                url = "https://cve.mitre.org/"
                webbrowser.open(url)
                input("Appuie sur Entrée après ta recherche...")
                prompt_manual_entry(url)

            elif va == "3":
                url = "https://nvd.nist.gov/"
                webbrowser.open(url)
                input("Appuie sur Entrée après ta recherche...")
                prompt_manual_entry(url)

            elif va == "4":
                site = input("Entrer le site web ou le serveur web cible : ").strip()
                do_command("nikto", "vuln", site, f"nikto -h {shlex.quote(site)} -Tuning x")

                # 🔥 AJOUT ICI
                prompt_manual_entry(site)

            else:
                continue

        # ---------------- Sniffing ----------------
        elif choice == "5":
            sn = menu(
                "Outils de Sniffing disponibles",
                [("1","MAC flooding (macof)"),("2","ARP spoof (arpspoof)"),("3","MAC spoof (macchanger)"),("4","Retour")],
            )
            if sn == "1":
                iface = input("Interface (souvent eth0) : ").strip()
                nb = input("Nombre de paquets : ").strip()
                do_command("macof", "sniffing", iface, f"macof -i {shlex.quote(iface)} -n {shlex.quote(nb)}")
            elif sn == "2":
                ip_cible = input("IP cible : ").strip()
                gw = input("IP passerelle / point d'accès : ").strip()
                print(f"\n{RED}{BOLD}CTRL+C pour arrêter{RESET}\n")
                # arpspoof is long-running; run live
                do_command("arpspoof", "sniffing", ip_cible, f"arpspoof -i eth0 -t {shlex.quote(gw)} {shlex.quote(ip_cible)}", show_live=True)
            elif sn == "3":
                iface = input("Interface réseau : ").strip()
                # Needs privileges; keep as-is
                cmd = f"sudo ifconfig {shlex.quote(iface)} down && sudo macchanger -a {shlex.quote(iface)} && sudo macchanger -r {shlex.quote(iface)} && sudo ifconfig {shlex.quote(iface)} up && ifconfig"
                do_command("macchanger", "sniffing", iface, cmd)
            else:
                continue

        # ---------------- Hacking Web Servers ----------------
        elif choice == "6":
            hw = menu(
                "Outils Web Servers disponibles",
                [("1","Nmap scripts HTTP"),("2","Uniscan (simple)"),("3","Uniscan (dynamique)"),("4","FTP brute force (placeholder)"),("5","Retour")],
            )
            if hw == "1":
                nhttp = menu(
                    "Nmap HTTP Scripts",
                    [("1","http-enum"),("2","hostmap-bfk"),("3","http-trace"),("4","http-waf-detect"),("5","Retour")],
                )
                if nhttp == "5":
                    continue
                target = input("Cible (domaine/ip) : ").strip()
                if nhttp == "1":
                    do_command("nmap", "web", target, f"nmap -sV --script=http-enum {shlex.quote(target)}")
                elif nhttp == "2":
                    do_command("nmap", "web", target, f"nmap --script hostmap-bfk --script-args hostmap-bfk.prefix=hostmap- {shlex.quote(target)}")
                elif nhttp == "3":
                    do_command("nmap", "web", target, f"nmap --script http-trace -d {shlex.quote(target)}")
                elif nhttp == "4":
                    do_command("nmap", "web", target, f"nmap -p80 --script http-waf-detect {shlex.quote(target)}")

            elif hw == "2":
                target = input("Cible (domaine/ip) : ").strip()
                do_command("uniscan", "web", target, f"uniscan -u {shlex.quote(target)} -q")
            elif hw == "3":
                target = input("Cible (domaine/ip) : ").strip()
                print(f"\n{RED}{BOLD}Scan long{RESET}\n")
                do_command("uniscan", "web", target, f"uniscan -u {shlex.quote(target)} -d")
            elif hw == "4":
                print("\nTODO: recoller ici ton bloc FTP brute force depuis ton script original.\n")
                export_json("ftp_bruteforce", "web", "N/A", "TODO", 0, "TODO: not implemented", extra={"todo": True})
                pause()
            else:
                continue

        elif choice == "7":
            print(f"\n{YELLOW}{BOLD}Génération du rapport PDF...{RESET}\n")
            export_pdf.generate_pdf()

            print(f"\n{YELLOW}{BOLD}Génération du rapport Notion...{RESET}\n")
            export_notion.create_notion_report(GLOBAL_JSON)

            print(f"\n{RED}{BOLD}Reset des résultats en cours...{RESET}")

            try:
                GLOBAL_JSON.write_text("[]", encoding="utf-8")
                for sub in RESULTS_DIR.iterdir():
                    if sub.is_dir():
                        for file in sub.glob("*.json"):
                            file.unlink()

                print(f"{GREEN}{BOLD}✅ Reset terminé.{RESET}")

            except Exception as e:
                print(f"{RED}Erreur lors du reset : {e}{RESET}")

            pause()
        # ---------------- Quit ----------------
        elif choice == "8":
            print(f"\n{GREEN}{BOLD}Bye {pseudo} 👋{RESET}")
            print(f"Résultats: {RESULTS_DIR}")
            sys.exit(0)


if __name__ == "__main__":
    main()
