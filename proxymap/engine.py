from __future__ import annotations
from typing import Any

def inspect_map(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "sni": obj.get("sni"),
        "client_cn": obj.get("client_cn"),
        "upstream": obj.get("upstream"),
        "strip_headers": obj.get("strip_headers"),
        "nonce": obj.get("nonce"),
    }

def admit_map(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "sni": obj.get("sni")}
