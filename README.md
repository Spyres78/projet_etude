# MDOS — Framework de Pentest en CLI

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

> **MDOS** est un outil CLI de pentest et d'audit de sécurité qui centralise les outils d'analyse réseau, de reconnaissance, d'énumération, de sniffing et de scan web dans une interface interactive avec export JSON/PDF/Notion.

---

## Fonctionnalités

### Authentification 2FA
Connexion sécurisée via Google Authenticator (TOTP). Compatible avec `pyotp` ou `oathtool` en fallback.

### Modules disponibles

| # | Catégorie | Outils intégrés |
|---|-----------|-----------------|
| 1 | **Network Scan** | Nmap, UnicornScan, Hping3 |
| 2 | **Footprinting & Reconnaissance** | theHarvester, Sherlock, CEWL, traceroute, domainfy, searchfy, WordPress user enum |
| 3 | **Enumeration** | Nmap NSE (NetBIOS, DNS, SMTP), snmp-check, snmpwalk, ldapsearch |
| 4 | **Analyse de vulnérabilité** | Nikto, CWE/CVE/NVD (navigateur) |
| 5 | **Sniffing** | macof (MAC flooding), arpspoof (ARP spoofing), macchanger |
| 6 | **Hacking Web Servers** | Nmap HTTP scripts (http-enum, http-waf-detect, http-trace…), Uniscan |
| 7 | **Rapport** | Export PDF + export Notion, reset des résultats |

### Export automatique
Chaque commande exécutée génère :
- Un fichier JSON horodaté dans `MDOS_RESULTS/<catégorie>/`
- Une entrée dans le fichier global `MDOS_RESULTS/mdos_global.json`
- Une synchronisation Notion (si configurée)

---

## Prérequis

### Système
- Linux (Kali, Parrot OS ou toute distribution Debian-based recommandée)
- Python 3.10+

### Outils système (selon modules utilisés)
```bash
sudo apt install nmap hping3 unicornscan theharvester sherlock cewl \
                 nikto macof dsniff macchanger ldap-utils snmp-check \
                 snmpwalk traceroute uniscan
```

### Dépendances Python
```bash
pip install pyotp fpdf2 notion-client requests
```

> Les modules internes `extract_users`, `export_pdf` et `export_notion` doivent être présents dans le même répertoire que `main.py`.

---

## Installation

```bash
git clone https://github.com/Spyres78/projet_etude
cd projet_etude
```

### Configuration 2FA — Google Authenticator sur Kali Linux

#### Prérequis
- Kali Linux à jour
- Accès `sudo`
- Application Google Authenticator installée sur smartphone

#### 1. Installation des dépendances

```bash
sudo apt update
sudo apt install -y libpam-google-authenticator oathtool qrencode
```

#### 2. Génération du secret (à faire une seule fois)

Lancer avec l'utilisateur qui utilisera le script :

```bash
google-authenticator -t
```

Réponses recommandées :

| Question | Réponse |
|----------|---------|
| Tokens basés sur le temps | `y` |
| Mise à jour du fichier | `y` |
| Interdire la réutilisation des tokens | `y` |
| Fenêtre de temps étendue | `n` |
| Activer le rate limiting | `y` |

#### 3. Scanner le QR Code

Un QR Code s'affiche dans le terminal. Dans Google Authenticator sur le téléphone : **Ajouter un compte → Scanner le QR Code**.

#### 4. Vérification

```bash
# Vérifier que le fichier existe
ls -la ~/.google_authenticator

# Tester un code (remplacer VOTRE_SECRET par la clé affichée)
oathtool --totp -b "VOTRE_SECRET"
```

Le code généré doit correspondre à celui affiché dans l'application.

#### 5. Sécurité

```bash
chmod 600 ~/.google_authenticator
```

> **Important :** ne jamais partager `~/.google_authenticator`. Conserver les codes de secours en lieu sûr.

#### Fonctionnement dans MDOS

1. MDOS lit le secret dans `~/.google_authenticator`
2. L'utilisateur saisit le code affiché dans son application
3. Le code est vérifié via `pyotp` (ou `oathtool` en fallback)
4. Code valide → MDOS démarre / Code invalide → fermeture immédiate

### Configuration Notion (optionnel)
Dans `export_notion.py`, renseigne ton token d'intégration et l'ID de ta database Notion.

---

## Utilisation

```bash
python3 main.py
```

### Options CLI

| Option | Description |
|--------|-------------|
| `--no-2fa` | Désactive l'authentification Google Authenticator |
| `--results-dir <chemin>` | Définit un répertoire personnalisé pour les résultats |

**Exemple :**
```bash
python3 main.py --no-2fa --results-dir ~/pentest/resultats
```

---

## Structure des résultats

```
MDOS_RESULTS/
├── mdos_global.json          # Toutes les entrées agrégées
├── scans/
│   └── nmap_2025-01-01_12-00-00.json
├── footprinting/
│   └── theHarvester_2025-01-01_12-05-00.json
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
  "host": "machine",
  "command": "nmap -p- 192.168.1.1",
  "returncode": 0,
  "raw_output": "..."
}
```

---

## Avertissement légal

> **MDOS est un outil de sécurité offensive destiné exclusivement à des fins d'apprentissage, de tests sur des systèmes vous appartenant, ou dans le cadre d'une mission d'audit avec autorisation écrite explicite.**
>
> Toute utilisation non autorisée sur des systèmes tiers est illégale et peut entraîner des poursuites pénales. Les auteurs déclinent toute responsabilité en cas d'usage malveillant.

---

## Licence

Ce projet est distribué sous licence MIT. Voir le fichier `LICENSE` pour plus de détails.