import requests
import json
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv
import os

# ========================
# LOAD ENV
# ========================
load_dotenv()
NOTION_TOKEN = os.getenv("NOTION_TOKEN")
NOTION_DATABASE_ID = os.getenv("NOTION_DATABASE_ID")

HEADERS = {
    "Authorization": f"Bearer {NOTION_TOKEN}",
    "Notion-Version": "2022-06-28",
    "Content-Type": "application/json",
}

# ========================
# UTILS
# ========================
def clean_text(text):
    """Supprime les caractères Markdown inutiles"""
    if not isinstance(text, str):
        text = str(text)
    text = text.replace("**", "").replace("__", "").strip()
    return text

def create_paragraph_block(text):
    """Crée un bloc paragraph simple"""
    return {
        "object": "block",
        "type": "paragraph",
        "paragraph": {
            "rich_text": [{"type": "text", "text": {"content": text}}]
        }
    }

def create_code_block(text, language=None):
    """Crée un bloc code avec un langage valide Notion"""
    valid_languages = [
        "bash","json","python","plain text","javascript","html","css","sql"
    ]
    if language not in valid_languages:
        language = "plain text"
    return {
        "object": "block",
        "type": "code",
        "code": {
            "rich_text": [{"type": "text", "text": {"content": text}}],
            "language": language
        }
    }

def create_toggle_block(title, children):
    """Crée un bloc toggle pour Notion"""
    return {
        "object": "block",
        "type": "toggle",
        "toggle": {
            "rich_text": [{"type": "text", "text": {"content": title}}],
            "children": children
        }
    }

# ========================
# FONCTION PRINCIPALE
# ========================
def create_notion_report(json_path):
    json_path = Path(json_path)
    if not json_path.exists():
        print("❌ Fichier JSON introuvable")
        return

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Créer la page Notion
    title = f"Rapport MDOS {datetime.now().strftime('%d-%m-%Y %H:%M')}"
    payload = {
        "parent": {"database_id": NOTION_DATABASE_ID},
        "properties": {
            "Name": {"title": [{"text": {"content": title}}]},
            "Type": {"select": {"name": "MDOS"}}
        }
    }

    r = requests.post("https://api.notion.com/v1/pages", headers=HEADERS, json=payload)
    if r.status_code != 200:
        print("❌ Erreur création page:", r.text)
        return

    page_id = r.json()["id"]
    print(f"✅ Page Notion créée: {title}")

    # Organiser par catégorie
    categories = {}
    for entry in data:
        cat = entry.get("category", "AUTRE").upper()
        categories.setdefault(cat, []).append(entry)

    # Ajouter le contenu par catégorie avec toggle
    for cat, entries in categories.items():
        category_children = []
        for entry in entries:
            tool = clean_text(entry.get("tool", ""))
            target = clean_text(entry.get("target", ""))
            date = clean_text(entry.get("date", ""))
            command = clean_text(entry.get("command", ""))
            raw_output = entry.get("raw_output", "")

            # Transformer JSON en string joliment formaté si possible
            if isinstance(raw_output, (dict, list)):
                pretty_output = json.dumps(raw_output, indent=2, ensure_ascii=False)
                code_language = "json"
            else:
                pretty_output = str(raw_output)
                code_language = "plain text"

            entry_children = [
                create_paragraph_block(f"🔹 Outil: {tool}"),
                create_paragraph_block(f"🔹 Cible: {target}"),
                create_paragraph_block(f"🔹 Date: {date}"),
                create_paragraph_block("🔹 Commande:"),
                create_code_block(command, language="bash"),
                create_paragraph_block("📄 Résultat:"),
                create_code_block(pretty_output, language=code_language)
            ]

            # Ajouter un toggle par entrée
            category_children.append(create_toggle_block(f"📂 {tool} → {target}", entry_children))

        # Ajouter un toggle pour la catégorie
        block_payload = {"children": [create_toggle_block(f"📂 {cat}", category_children)]}

        r = requests.patch(f"https://api.notion.com/v1/blocks/{page_id}/children",
                           headers=HEADERS, json=block_payload)
        if r.status_code != 200:
            print("❌ Erreur ajout contenu:", r.text)
            return

    print("✅ Rapport envoyé sur Notion")