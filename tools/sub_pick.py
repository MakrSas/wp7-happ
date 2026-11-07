#!/usr/bin/env python3
"""
Для проверки ядра с компьютера: из JSON-подписки (Xray, как её отдаёт панель приложению)
достаёт Trojan-серверы. Секреты не печатает.

  sub_pick.py list FILE            — номера и названия Trojan-серверов
  sub_pick.py args FILE N          — аргументы для happd (с паролем; только для подстановки в команду)
"""
import json
import shlex
import sys


def trojans(path):
    data = json.load(open(path, encoding="utf-8"))
    out = []
    for cfg in data if isinstance(data, list) else [data]:
        for o in cfg.get("outbounds", []):
            if o.get("protocol") != "trojan":
                continue
            srv = o["settings"]["servers"][0]
            s = o.get("streamSettings", {}) or {}
            tls = s.get("tlsSettings", {}) or {}
            out.append({
                "name": cfg.get("remarks", "?"),
                "host": srv["address"], "port": srv["port"], "password": srv["password"],
                "sni": tls.get("serverName", ""), "insecure": bool(tls.get("allowInsecure")),
                "net": s.get("network", "tcp"),
            })
    return out


def main():
    cmd, path = sys.argv[1], sys.argv[2]
    items = trojans(path)
    if cmd == "list":
        for i, t in enumerate(items):
            print(i, t["name"], "| порт", t["port"], "| сеть", t["net"], "| insecure" if t["insecure"] else "")
    else:
        t = items[int(sys.argv[3])]
        args = ["--server", t["host"], "--sport", str(t["port"]), "--password", t["password"]]
        if t["sni"]:
            args += ["--sni", t["sni"]]
        if t["insecure"]:
            args.append("--insecure")
        print(" ".join(shlex.quote(a) for a in args))


if __name__ == "__main__":
    main()
