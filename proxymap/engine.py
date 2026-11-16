from __future__ import annotations
import base64
import hashlib
import hmac
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


def _deny(reason_codes: list[str], sni: Any) -> dict:
    return {"decision": "deny", "reason_codes": reason_codes, "sni": sni}


def _decode_secret(secret: Any) -> bytes | None:
    if not isinstance(secret, str):
        return None
    try:
        return bytes.fromhex(secret)
    except ValueError:
        return secret.encode("utf-8")


def admit_map(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    sni = obj.get("sni")

    iat = obj.get("iat")
    if not isinstance(iat, int) or isinstance(iat, bool):
        return _deny(["malformed_map"], sni)

    string_fields = ("kid", "sni", "client_cn", "upstream", "nonce", "sig")
    if any(not isinstance(obj.get(field), str) or obj.get(field) == "" for field in string_fields) \
            or not isinstance(obj.get("strip_headers"), list) \
            or not all(isinstance(header, str) and header != "" for header in obj.get("strip_headers", [])):
        return _deny(["malformed_map"], sni)

    kid = obj["kid"]
    client_cn = obj["client_cn"]
    upstream = obj["upstream"]
    strip_headers = obj["strip_headers"]
    nonce = obj["nonce"]

    reasons: list[str] = []

    routes = policy.get("routes", {})
    route = routes.get(sni)
    if route is None:
        reasons.append("sni_not_routed")
    else:
        if not client_cn.endswith(route.get("cn_suffix", "")):
            reasons.append("cn_suffix_mismatch")

        if upstream not in route.get("upstreams", []):
            reasons.append("upstream_not_allowed")

        if policy.get("require_https_upstream", False) and not upstream.startswith("https://"):
            reasons.append("upstream_not_https")

        if any(part in upstream for part in policy.get("upstream_deny_substrings", [])):
            reasons.append("upstream_denied_substring")

        if not set(route.get("must_strip", [])) <= set(strip_headers):
            reasons.append("missing_strip_header")

    key_entry = keys.get("keys", {}).get(kid)
    if key_entry is None:
        reasons.append("unknown_kid")
    else:
        if key_entry.get("status") != "active":
            reasons.append("key_revoked")

        secret = _decode_secret(key_entry.get("secret"))
        signing_input = "|".join([
            "v1", kid, sni, client_cn, upstream,
            ",".join(strip_headers), str(iat), nonce,
        ]).encode("utf-8")
        if secret is None:
            reasons.append("bad_signature")
        else:
            expected = base64.urlsafe_b64encode(
                hmac.new(secret, signing_input, hashlib.sha256).digest()
            ).rstrip(b"=").decode("ascii")
            if not hmac.compare_digest(expected, obj["sig"]):
                reasons.append("bad_signature")

    skew = policy.get("clock_skew_seconds", 0)
    max_age = policy.get("max_age_seconds", 0)
    if not (now_unix - skew <= iat <= now_unix + max_age):
        reasons.append("iat_outside_window")

    if nonce in store.get("items", {}):
        reasons.append("nonce_replay")

    if reasons:
        return _deny(reasons, sni)

    store.setdefault("items", {})[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "sni": sni}
