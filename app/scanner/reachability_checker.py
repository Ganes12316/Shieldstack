import requests
from urllib.parse import urlparse

ALLOWED_HOSTS = ("localhost", "127.0.0.1")

def _is_localhost(base_url: str) -> bool:
    host = urlparse(base_url).hostname
    return host in ALLOWED_HOSTS

def check_route_reachability(base_url: str, path: str, method: str) -> dict:
    """
    Sends a non-destructive OPTIONS request to check whether a route challenges
    for authentication. Never sends the actual method (DELETE/PUT/PATCH) and
    never sends a body/payload — this confirms auth enforcement exists or
    doesn't, without ever performing the destructive action itself.

    Restricted to localhost/127.0.0.1 by design — this is meant to verify
    YOUR OWN locally running app, not to probe arbitrary remote targets.
    """
    if not _is_localhost(base_url):
        return {
            "checked": False,
            "reason": "Reachability checks are restricted to localhost/127.0.0.1 only.",
        }

    # normalize <param> placeholders from static analysis into a harmless dummy value
    test_path = path.replace("<param>", "1")
    url = base_url.rstrip("/") + test_path

    try:
        resp = requests.options(url, timeout=3)
    except requests.exceptions.ConnectionError:
        return {"checked": False, "reason": "Could not connect — is the app running on this URL?"}
    except requests.exceptions.Timeout:
        return {"checked": False, "reason": "Request timed out."}
    except Exception as e:
        return {"checked": False, "reason": f"Request failed: {e}"}

    status = resp.status_code
    if status in (401, 403):
        verdict = "Auth appears enforced — server challenged the unauthenticated request."
        likely_vulnerable = False
    elif status in (404, 405):
        verdict = "Route did not respond as expected to OPTIONS — inconclusive, verify manually."
        likely_vulnerable = None
    else:
        verdict = "No auth challenge observed — consistent with the static analysis finding."
        likely_vulnerable = True

    return {
        "checked": True,
        "url": url,
        "status_code": status,
        "verdict": verdict,
        "likely_vulnerable": likely_vulnerable,
    }