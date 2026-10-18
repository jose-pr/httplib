from __future__ import annotations


def disable_insecure_request_warnings() -> None:
    """Silence urllib3's InsecureRequestWarning if urllib3 is importable.

    No-op when urllib3 is absent (the session toolkit's optional dependency)."""
    try:
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        return
