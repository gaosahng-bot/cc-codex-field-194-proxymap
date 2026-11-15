# proxymap admit rules

## Signing input
`v1|{kid}|{sni}|{client_cn}|{upstream}|{strip_headers_csv}|{iat}|{nonce}`

## Route bind
sni ∈ routes; client_cn endswith routes[sni].cn_suffix; upstream ∈ routes[sni].upstreams;
if require_https_upstream: upstream startswith https://; reject upstream deny substrings;
set(must_strip) ⊆ set(strip_headers); HMAC+revoke; time; nonce allow-only.
