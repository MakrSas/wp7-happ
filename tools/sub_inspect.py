#!/usr/bin/env python3
"""
Показывает, какие протоколы в подписке, не раскрывая ключей.
UUID, пароли и пути с токенами заменяются на ***, адрес сервера сокращается.

  python3 tools/sub_inspect.py 'https://…ссылка-на-подписку…'
  python3 tools/sub_inspect.py < файл-с-подпиской
"""
import base64
import json
import sys
import urllib.parse
import urllib.request
from collections import Counter

SECRET_KEYS = {"id", "uuid", "password", "pass", "path", "serviceName", "host", "key", "authority"}
SHOW_KEYS = ["type", "security", "flow", "encryption", "sni", "fp", "alpn", "pbk", "sid", "spx",
             "headerType", "mode", "allowInsecure", "method", "plugin"]


def b64(s):
    s = s.strip().replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4)).decode("utf-8", "replace")


def short_host(h):
    if not h:
        return "?"
    parts = h.split(".")
    if all(p.isdigit() for p in parts):
        return parts[0] + ".*.*." + parts[-1]
    return "*." + ".".join(parts[-2:]) if len(parts) > 2 else h


def fetch(src):
    if src.startswith("http"):
        req = urllib.request.Request(src, headers={"User-Agent": "v2rayN/6.0"})
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.read().decode("utf-8", "replace")
    return src


def links(text):
    text = text.strip()
    if "://" not in text.split("\n")[0]:
        try:
            text = b64(text)
        except Exception:
            pass
    if text.startswith("{") or text.startswith("["):
        print("подписка в формате JSON (xray/sing-box), не ссылками")
        data = json.loads(text)
        for ob in (data if isinstance(data, list) else [data]):
            for o in ob.get("outbounds", []):
                s = o.get("streamSettings", {})
                print(" ", o.get("protocol"), "| network", s.get("network"), "| security", s.get("security"),
                      "| flow", (o.get("settings", {}).get("vnext") or [{}])[0].get("users", [{}])[0].get("flow"))
        return []
    return [l.strip() for l in text.splitlines() if "://" in l]


def describe(link):
    scheme = link.split("://", 1)[0].lower()
    if scheme == "vmess":
        j = json.loads(b64(link[8:]))
        return "vmess", short_host(j.get("add")), j.get("port"), {
            "type": j.get("net"), "security": j.get("tls"), "sni": j.get("sni"), "fp": j.get("fp"), "alpn": j.get("alpn")}
    u = urllib.parse.urlsplit(link)
    q = dict(urllib.parse.parse_qsl(u.query))
    if scheme == "ss":
        try:
            userinfo = b64(urllib.parse.unquote(u.username or ""))
            q["method"] = userinfo.split(":", 1)[0]
        except Exception:
            q["method"] = "?"
    return scheme, short_host(u.hostname), u.port, {k: v for k, v in q.items() if k not in SECRET_KEYS}


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else sys.stdin.read()
    items = links(fetch(src))
    if not items:
        return
    kinds = Counter()
    for l in items:
        try:
            scheme, host, port, q = describe(l)
        except Exception as e:
            print("не разобрал ссылку:", l.split("://", 1)[0], e)
            continue
        params = " ".join("%s=%s" % (k, q[k]) for k in SHOW_KEYS if q.get(k))
        kinds[(scheme, q.get("type"), q.get("security"), q.get("flow"))] += 1
        print("%-7s %-22s :%-5s %s" % (scheme, host, port, params))
    print("\nитого:")
    for (scheme, t, sec, flow), n in kinds.most_common():
        print("  %d × %s, транспорт %s, защита %s%s" % (n, scheme, t or "tcp", sec or "нет", ", flow " + flow if flow else ""))


if __name__ == "__main__":
    main()
