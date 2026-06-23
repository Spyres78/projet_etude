# MDOS — Multitool OSINT & Detection Operations System

```
███╗   ███╗██████╗  ██████╗ ███████╗
████╗ ████║██╔══██╗██╔═══██╗██╔════╝
██╔████╔██║██║  ██║██║   ██║███████╗
██║╚██╔╝██║██║  ██║██║   ██║╚════██║
██║ ╚═╝ ██║██████╔╝╚██████╔╝███████║
╚═╝     ╚═╝╚═════╝  ╚═════╝ ╚══════╝
        [  M  D  O  S  ]
    access granted ▓▓▓▓▓▓▓▓▓
```

> **MDOS** est un outil toolbox, disponible en interface CLI et GUI (tkinter), avec authentification 2FA, exécution de commandes intégrée et export des résultats en JSON, PDF ou Notion.

> ⚠️ **Usage légal uniquement.** Cet outil est destiné aux tests d'intrusion autorisés, à la formation en cybersécurité et aux environnements de lab. Toute utilisation sur des systèmes sans autorisation explicite est illégale.

---

## Fichiers du projet

| Fichier | Description |
|---|---|
| `mdos.py` | Interface CLI (terminal ANSI) |
| `mdos_gui.py` | Interface graphique tkinter (style terminal hacker) |
| `mdos_gui.html` | Prototype HTML de l'interface GUI |
| `export_pdf.py` | Génération de rapports PDF via ReportLab |
| `export_notion.py` | Export des résultats vers Notion |
| `extract_users.py` | Enumération d'utilisateurs WordPress via l'API REST |

---

## Fonctionnalités

### Authentification 2FA (TOTP)
- Vérifie un code Google Authenticator (6 chiffres) à chaque lancement
- Lit le secret depuis `~/.google_authenticator`
- Utilise `pyotp` (avec fallback `oathtool`)
- En CLI : option `--no-2fa` pour désactiver

### 6 modules de sécurité

**01 — Network Scan**
Nmap (ports, services, OS, scan agressif), UnicornScan (OS via TTL), SX (ARP local), Hping3 (SYN, UDP, ICMP, port range)

**02 — Footprinting & Reconnaissance**
theHarvester (emails Google/LinkedIn), Sherlock (profils réseaux sociaux), CEWL (wordlist), Traceroute, domainfy, searchfy, WordPress user enumeration, et ouverture de ressources web (Censys, DomainTools Whois, SearchFTPS, mattw.io)

**03 — Enumeration**
NetBIOS (nbstat NSE), SNMP (snmp-check, snmpwalk, nmap UDP), LDAP (ldapsearch), DNS (broadcast discovery, brute force), SMTP (enum-users, open-relay)

**04 — Analyse de vulnérabilité**
Nikto (scan web), liens vers CWE/CVE MITRE et NVD NIST

**05 — Sniffing**
MAC Flooding (macof), ARP Spoofing (arpspoof), MAC Spoofing (macchanger)

**06 — Hacking Web Servers**
Nmap scripts HTTP (http-enum, hostmap-bfk, http-trace, WAF detect), Uniscan (simple et dynamique)

### Parsers de sortie
Les sorties des outils sont automatiquement parsées et structurées en JSON :
- **nmap** : ports ouverts, services, OS, latence, adresse MAC
- **hping3** : ports répondus, stats RTT
- **traceroute** : liste des hops
- **nikto** : findings, serveur détecté
- **theHarvester** : emails et hosts trouvés

### Export des résultats
- **JSON** : un fichier par commande + fichier global `MDOS_RESULTS/mdos_global.json`
- **PDF** : rapport mis en page via ReportLab (fallback fpdf2, puis HTML)
- **Notion** : export vers une base de données Notion via l'API
- **Notes manuelles** : ajout de notes avec récupération automatique depuis le presse-papier

---

## Prérequis

### Système
- Linux (Kali recommandé)
- Python 3.10+
- `tkinter` (pour la version GUI)

### Outils système à installer
```bash
sudo apt install nmap hping3 unicornscan macof arpspoof macchanger \
                 nikto traceroute ldap-utils snmp uniscan cewl
pip install sherlock
```

### Dépendances Python
```bash
pip install pyotp reportlab fpdf2 requests pyperclip
```

Pour l'export Notion :
```bash
pip install notion-client  # ou selon l'implémentation dans export_notion.py
```

---

## Installation

```bash
git clone <url-du-repo>
cd mdos

pip install pyotp reportlab fpdf2 requests pyperclip
```

### Configurer Google Authenticator (2FA)

> ⚠️ **IMPORTANT** — La 2FA nécessite l'installation de Google Authenticator sur le système d'exploitation. À faire **une seule fois**, avec l'utilisateur qui lancera le script (pas nécessairement root).

**Étape 1 — Installer les dépendances système**
```bash
sudo apt update
sudo apt install -y libpam-google-authenticator oathtool qrencode
```

**Étape 2 — Générer ton secret (OBLIGATOIRE)**
```bash
google-authenticator -t
```

Cette commande va :
- Générer un secret (clé secrète TOTP)
- Créer le fichier `~/.google_authenticator`
- Afficher un QR code à scanner avec l'application Google Authenticator sur ton téléphone

Suis les instructions à l'écran et scanne le QR code avec l'app **Google Authenticator** (iOS / Android). À chaque lancement de MDOS, tu devras saisir le code à 6 chiffres affiché dans l'application.

---

## Lancement

### Interface CLI
```bash
python3 mdos.py
# Sans 2FA (dev/lab uniquement)
python3 mdos.py --no-2fa
# Dossier de résultats personnalisé
python3 mdos.py --results-dir /chemin/vers/resultats
```

### Interface GUI (tkinter)
```bash
python3 mdos_gui.py
```

### Générer un rapport PDF manuellement
```bash
python3 export_pdf.py
# Lit MDOS_RESULTS/mdos_global.json et génère ~/MDOS_Report_YYYY-MM-DD.pdf
```

---

## Structure des résultats

```
MDOS_RESULTS/
├── mdos_global.json          # Toutes les actions de toutes les sessions
├── scans/
│   └── nmap_2025-01-01_12-00-00.json
├── footprinting/
│   └── theHarvester_...json
├── enumeration/
├── vuln/
├── sniffing/
├── web/
└── notes/
```

Chaque fichier JSON contient :
```json
{
  "tool": "nmap",
  "category": "scans",
  "target": "192.168.1.1",
  "date": "2025-01-01T12:00:00+01:00",
  "user": "kali",
  "host": "kali-machine",
  "command": "nmap -sV 192.168.1.1",
  "returncode": 0,
  "status": "success",
  "parsed": { "parser": "nmap", "ports": [...], "os": [...] },
  "raw_output": "..."
}
```

---

## Interface GUI

L'interface graphique (`mdos_gui.py`) reprend le design du prototype HTML avec :
- Thème terminal hacker (vert `#00ff88` sur fond noir `#020c06`)
- Barre de statut avec horloge temps réel et point clignotant
- Écrans : Login → Menu principal → Sous-menu → Exécution → Rapport de session
- Mise à l'échelle dynamique selon la résolution (référence 1920×1080, min 880×600)
- Terminal intégré avec coloration syntaxique (succès/erreur/warning/info)
- Export PDF, JSON et Notion depuis l'écran rapport

---

## Configuration Notion (optionnel)

Renseignez votre clé d'API et l'ID de votre base de données Notion dans `export_notion.py` :

```python
NOTION_TOKEN = "secret_xxx"
NOTION_DATABASE_ID = "xxx"
```

---

## Avertissement légal

MDOS est un outil destiné exclusivement à :
- Des tests d'intrusion sur des systèmes dont vous avez l'autorisation écrite
- Des environnements de lab / CTF / formation
- De la recherche en cybersécurité

Toute utilisation malveillante ou non autorisée est strictement interdite et engage la seule responsabilité de l'utilisateur.
