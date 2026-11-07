/*
 * happd.exe — фоновый процесс VPN на HD7 (как simemud.exe у SIM-эмулятора).
 * Настройки берёт из HKLM\Software\HappWP, состояние пишет в HKLM\Software\HappWP\Live.
 * Приложение управляет им событиями: HappWP.Stop (остановиться), HappWP.Reload (перечитать сервер).
 */
#include <stdio.h>
#include <string.h>
#include <windows.h>

#include "happ_reg.h"
#include "ca.h"
#include "proxy.h"
#include "wifiproxy.h"

void plat_log_file(const char *path);

static volatile int g_stop;
static HANDLE g_evStop, g_evReload;

/* Сервер из реестра → Outbound. */
static void load_outbound(Outbound *o)
{
    memset(o, 0, sizeof(*o));
    if (!reg_dword(CFG_KEY, L"Enabled", 0)) return;
    o->type = (int)reg_dword(CFG_KEY, L"Type", OUT_TROJAN);
    o->port = (int)reg_dword(CFG_KEY, L"Port", 443);
    o->insecure = (int)reg_dword(CFG_KEY, L"Insecure", 0);
    reg_str_a(CFG_KEY, L"Server", o->host, sizeof(o->host));
    reg_str_a(CFG_KEY, L"Password", o->password, sizeof(o->password));
    reg_str_a(CFG_KEY, L"Sni", o->sni, sizeof(o->sni));
    if (!o->host[0] || !o->password[0]) o->type = 0;
}

static DWORD WINAPI ca_thread(LPVOID p)
{
    (void)p;
    reg_set_dword(LIVE_KEY, L"CaReady", 0);
    if (ca_init() == 0) reg_set_dword(LIVE_KEY, L"CaReady", 1);
    return 0;
}

static DWORD WINAPI proxy_thread(LPVOID p)
{
    int port = (int)(INT_PTR)p;
    if (proxy_run("0.0.0.0", port, &g_stop) != 0) {
        reg_set_str_a(LIVE_KEY, L"Error", "порт занят — прокси не запустился");
        g_stop = 1;
        SetEvent(g_evStop);
    }
    return 0;
}

/*
 * Движок: прокси + обновление состояния, пока не придёт HappWP.Stop или не выключат в настройках.
 * writer: 1 — отдельный процесс happd.exe, 2 — поток внутри приложения.
 */
int happ_engine(HINSTANCE hInst, int writer)
{
    HANDLE hMutex, waits[2], th;
    char ca[MAX_PATH];
    Outbound o;
    int port;

    g_stop = 0;
    hMutex = CreateMutexW(NULL, TRUE, MTX_ENGINE);
    if (!hMutex) return 1;
    if (GetLastError() == ERROR_ALREADY_EXISTS) { CloseHandle(hMutex); return 0; }
    g_evStop = CreateEventW(NULL, TRUE, FALSE, EVT_STOP);
    ResetEvent(g_evStop);
    g_evReload = CreateEventW(NULL, FALSE, FALSE, EVT_RELOAD);

    plat_log_file("\\Temp\\happd.log");
    module_dir_a(hInst, ca, sizeof(ca));
    strcat(ca, "cacert.pem");

    reg_set_dword(LIVE_KEY, L"EngineVersion", HAPP_NATIVE_VERSION);
    reg_set_dword(LIVE_KEY, L"Writer", (DWORD)writer);
    reg_set_str_a(LIVE_KEY, L"Error", "");
    if (plat_init() || tun_global_init(ca)) {
        reg_set_str_a(LIVE_KEY, L"Error", "не запустился TLS");
        ReleaseMutex(hMutex);
        CloseHandle(hMutex);
        return 1;
    }
    load_outbound(&o);
    proxy_set_outbound(&o);
    g_mitm = (int)reg_dword(CFG_KEY, L"Mitm", 1);
    {
        HANDLE ct = CreateThread(NULL, 0, ca_thread, NULL, 0, NULL);
        if (ct) CloseHandle(ct);
    }
    port = (int)reg_dword(CFG_KEY, L"ListenPort", 10809);
    th = CreateThread(NULL, 0, proxy_thread, (LPVOID)(INT_PTR)port, 0, NULL);
    reg_set_dword(LIVE_KEY, L"Running", 1);
    reg_set_dword(LIVE_KEY, L"ListenPort", (DWORD)port);

    waits[0] = g_evStop;
    waits[1] = g_evReload;
    {
    char applied_ip[32] = "";
    int auto_proxy = 0, tick = 0;
    while (!g_stop) {
        char err[200];
        DWORD w = WaitForMultipleObjects(2, waits, FALSE, 1000);
        if (w == WAIT_OBJECT_0) break;
        if (w == WAIT_OBJECT_0 + 1) {
            load_outbound(&o);
            proxy_set_outbound(&o);
            g_mitm = (int)reg_dword(CFG_KEY, L"Mitm", 1);
            plat_log("сервер: %s:%d", o.host, o.port);
        }
        if (!reg_dword(CFG_KEY, L"Enabled", 0)) break;
        /* состояние для приложения */
        reg_set_dword(LIVE_KEY, L"Tick", GetTickCount());
        reg_set_dword(LIVE_KEY, L"Conns", (DWORD)g_active_conns);
        reg_set_dword(LIVE_KEY, L"Total", (DWORD)g_total_conns);
        reg_set_dword(LIVE_KEY, L"UpKB", (DWORD)(g_bytes_up / 1024));
        reg_set_dword(LIVE_KEY, L"DownKB", (DWORD)(g_bytes_down / 1024));
        proxy_last_error(err, sizeof(err));
        reg_set_str_a(LIVE_KEY, L"Error", err);
        /* Адрес телефона в Wi-Fi: его указывают как прокси (127.0.0.1 система не принимает). */
        {
            char name[128], ip[32] = "";
            struct hostent *he;
            if (gethostname(name, sizeof(name)) == 0 && (he = gethostbyname(name)) != NULL && he->h_addr_list[0]) {
                unsigned char *a = (unsigned char *)he->h_addr_list[0];
                sprintf(ip, "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
            }
            reg_set_str_a(LIVE_KEY, L"LocalIp", ip);

            /* Прокси Wi-Fi автоматически: запомнить записи на наш порт, выставить актуальный адрес. */
            auto_proxy = (int)reg_dword(CFG_KEY, L"AutoProxy", 1);
            if (auto_proxy && (tick++ % 5) == 0)
                reg_set_dword(LIVE_KEY, L"ProxyNets", (DWORD)wifiproxy_learn(port));
            if (auto_proxy && ip[0] && strcmp(ip, applied_ip) != 0) {
                int n = wifiproxy_apply(1, ip, port);
                plat_log("прокси Wi-Fi: %s:%d в %d сетях", ip, port, n);
                strcpy(applied_ip, ip);
            }
        }
    }
    /* VPN выключили — убрать прокси, иначе без Happ интернета не будет. */
    if (auto_proxy) {
        wifiproxy_learn(port);
        plat_log("прокси Wi-Fi убран в %d сетях", wifiproxy_apply(0, NULL, port));
    }
    }
    g_stop = 1;
    if (th) { WaitForSingleObject(th, 3000); CloseHandle(th); }
    reg_set_dword(LIVE_KEY, L"Running", 0);
    reg_set_dword(LIVE_KEY, L"Writer", 0);
    CloseHandle(g_evReload);
    CloseHandle(g_evStop);
    ReleaseMutex(hMutex);
    CloseHandle(hMutex);
    return 0;
}

#ifndef HAPP_DLL
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPWSTR cmd, int show)
{
    (void)hPrev; (void)cmd; (void)show;
    return happ_engine(hInst, 1);
}
#endif
