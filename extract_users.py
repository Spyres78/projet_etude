import requests
import urllib3
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def normalize(url: str) -> str:
    url = url.strip()
    if not url.startswith("http"):
        url = "http://" + url
    return url.rstrip("/") + "/wp-json/wp/v2/users/"


def enumerate_users(endpoint: str, export_func=None) -> dict:
    """
    Retourne et exporte :
    {
        "users": [
            {"id": 1, "username": "admin", "name": "Admin"}
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
        result = {
            "error": f"HTTP {r.status_code}",
            "raw": r.text
        }
    else:
        try:
            data = r.json()
        except Exception:
            result = {
                "error": "Invalid JSON response",
                "raw": r.text
            }
        else:
            if not isinstance(data, list):
                result = {
                    "error": "Unexpected format",
                    "raw": data
                }
            else:
                users = []
                for u in data:
                    users.append({
                        "id": u.get("id"),
                        "username": u.get("slug"),
                        "name": u.get("name")
                    })

                result = {
                    "users": users
                }

    # ✅ EXPORT DANS mdos_global.json
    if export_func:
        export_func(
            tool="wp-user-enum",
            category="footprinting",
            target=endpoint,
            command=f"GET {endpoint}",
            rc=0 if "users" in result else 1,
            output=result,
            extra={"module": "wordpress-users"}
        )

    return result
