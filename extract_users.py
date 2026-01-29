import requests
import json
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def normalize(url: str) -> str:
    url = url.strip()
    if not url.startswith("http"):
        url = "http://" + url
    return url.rstrip("/") + "/wp-json/wp/v2/users/"

def enumerate_users(endpoint: str) -> dict:
    """
    Retourne:
    {
        "users": [
            {"id": 1, "username": "admin", "name": "Admin"},
            ...
        ]
    }
    """

    headers = {
        "User-Agent": "Mozilla/5.0"
    }

    r = requests.get(
        endpoint,
        headers=headers,
        verify=False,
        timeout=5
    )

    if r.status_code != 200:
        return {
            "error": f"HTTP {r.status_code}",
            "raw": r.text
        }

    try:
        data = r.json()
    except Exception:
        return {
            "error": "Invalid JSON response",
            "raw": r.text
        }

    if not isinstance(data, list):
        return {
            "error": "Unexpected format",
            "raw": data
        }

    users = []
    for u in data:
        users.append({
            "id": u.get("id"),
            "username": u.get("slug"),
            "name": u.get("name")
        })
    return {
        "users": users
    }
