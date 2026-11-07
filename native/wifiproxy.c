/*
 * Прокси Wi-Fi автоматически.
 *
 * WP7 хранит прокси сети в HKLM\Comm\PROXYDATABASE\<имя сети в hex>\1 (Server, Port, Flags = 2 …);
 * когда прокси в настройках выключают, ключ удаляется целиком.
 *
 * Happ запоминает записи, которые указывают на него (наш порт), в HKLM\Software\HappWP\WifiProxy\<сеть>,
 * при включении VPN восстанавливает их с текущим адресом телефона, при выключении — удаляет.
 * Сеть, где прокси ещё ни разу не включали руками, Happ не трогает.
 */
#include <stdio.h>
#include <windows.h>

#include "happ_reg.h"
#include "plat.h"
#include "wifiproxy.h"

#define DB_KEY    L"Comm\\PROXYDATABASE"
#define SAVED_KEY L"Software\\HappWP\\WifiProxy"

/* Скопировать все значения из ключа src в ключ dst. */
static int copy_values(HKEY src, HKEY dst)
{
    DWORD i, nlen, dlen, type;
    wchar_t name[128];
    BYTE data[1024];
    int n = 0;
    for (i = 0;; i++) {
        nlen = 128;
        dlen = sizeof(data);
        if (RegEnumValueW(src, i, name, &nlen, NULL, &type, data, &dlen) != ERROR_SUCCESS) break;
        if (RegSetValueExW(dst, name, 0, type, data, dlen) == ERROR_SUCCESS) n++;
    }
    return n;
}

/* Запомнить записи PROXYDATABASE, которые указывают на наш порт. Возвращает число сетей. */
int wifiproxy_learn(int port)
{
    HKEY db, net, entry, saved;
    DWORD i, nlen, disp, p, sz, type;
    wchar_t name[128], path[300];
    int learned = 0;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, DB_KEY, 0, 0, &db) != ERROR_SUCCESS) return 0;
    for (i = 0;; i++) {
        nlen = 128;
        if (RegEnumKeyExW(db, i, name, &nlen, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
        wsprintfW(path, L"%s\\1", name);
        if (RegOpenKeyExW(db, path, 0, 0, &entry) != ERROR_SUCCESS) continue;
        sz = sizeof(p);
        if (RegQueryValueExW(entry, L"Port", NULL, &type, (LPBYTE)&p, &sz) == ERROR_SUCCESS && type == REG_DWORD &&
            (int)p == port) {
            wsprintfW(path, L"%s\\%s", SAVED_KEY, name);
            if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, path, 0, NULL, 0, 0, NULL, &saved, &disp) == ERROR_SUCCESS) {
                copy_values(entry, saved);
                RegCloseKey(saved);
                learned++;
            }
        }
        RegCloseKey(entry);
    }
    RegCloseKey(db);
    return learned;
}

/* Включить (с адресом ip) или убрать прокси во всех запомненных сетях. */
int wifiproxy_apply(int on, const char *ip, int port)
{
    HKEY saved, src, db, net, entry;
    DWORD i, nlen, disp;
    wchar_t name[128], path[300], wip[32];
    int n = 0;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, SAVED_KEY, 0, 0, &saved) != ERROR_SUCCESS) return 0;
    MultiByteToWideChar(CP_ACP, 0, ip ? ip : "", -1, wip, 32);
    for (i = 0;; i++) {
        nlen = 128;
        if (RegEnumKeyExW(saved, i, name, &nlen, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
        if (!on) {
            wsprintfW(path, L"%s\\%s", DB_KEY, name);
            if (RegDeleteKeyW(HKEY_LOCAL_MACHINE, path) == ERROR_SUCCESS) n++;
            continue;
        }
        if (!wip[0]) continue;
        if (RegOpenKeyExW(saved, name, 0, 0, &src) != ERROR_SUCCESS) continue;
        wsprintfW(path, L"%s\\%s\\1", DB_KEY, name);
        if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, path, 0, NULL, 0, 0, NULL, &entry, &disp) == ERROR_SUCCESS) {
            DWORD p = (DWORD)port;
            copy_values(src, entry);
            RegSetValueExW(entry, L"Server", 0, REG_SZ, (const BYTE *)wip, (lstrlenW(wip) + 1) * sizeof(wchar_t));
            RegSetValueExW(entry, L"Port", 0, REG_DWORD, (const BYTE *)&p, sizeof(p));
            RegCloseKey(entry);
            n++;
        }
        RegCloseKey(src);
    }
    RegCloseKey(saved);
    (void)db; (void)net;
    return n;
}
