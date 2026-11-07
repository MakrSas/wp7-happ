/*
 * HappNative.dll — COM-объект для приложения (через ComBridge, как у SIM-эмулятора).
 * Реестр, запуск и остановка движка, пинг серверов и загрузка подписки.
 * Порядок методов должен совпадать с IHappNative в app/Native.cs.
 */
#include <windows.h>
#include <ole2.h>
#include <oleauto.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include "happ_reg.h"
#include "https.h"
#include "tunnel.h"

int happ_engine(HINSTANCE hInst, int writer);

/* {61A80CDD-2C09-41BC-8900-899346D9F3C8} */
static const GUID CLSID_HappNative = {0x61A80CDD, 0x2C09, 0x41BC, {0x89, 0x00, 0x89, 0x93, 0x46, 0xD9, 0xF3, 0xC8}};
/* {50A42CCA-ADB9-45FC-BEA2-7519D0F97933} */
static const GUID IID_IHappNative = {0x50A42CCA, 0xADB9, 0x45FC, {0xBE, 0xA2, 0x75, 0x19, 0xD0, 0xF9, 0x79, 0x33}};
static const GUID IID_IUnknown_ = {0x00000000, 0x0000, 0x0000, {0xC0, 0, 0, 0, 0, 0, 0, 0x46}};
static const GUID IID_IClassFactory_ = {0x00000001, 0x0000, 0x0000, {0xC0, 0, 0, 0, 0, 0, 0, 0x46}};

#define WRITER_NONE 0
#define WRITER_DAEMON 1
#define WRITER_THREAD 2

static HINSTANCE g_hInst;
static LONG g_locks;
static HANDLE g_thread;

static int same_guid(REFIID a, const GUID *b) { return memcmp(a, b, sizeof(GUID)) == 0; }

/* TLS для пинга и подписки — один раз на процесс. */
static int tls_ready(void)
{
    static int r = -1;
    if (r < 0) {
        char ca[MAX_PATH];
        module_dir_a(g_hInst, ca, sizeof(ca));
        strcat(ca, "cacert.pem");
        r = (plat_init() == 0 && tun_global_init(ca) == 0) ? 1 : 0;
    }
    return r;
}

/* ---------------------------------------------------------------- строки */

static char *utf8(LPCWSTR w)
{
    int n;
    char *s;
    if (!w) w = L"";
    n = WideCharToMultiByte(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
    s = (char *)malloc(n > 0 ? (size_t)n : 1);
    if (!s) return NULL;
    if (n <= 0) s[0] = 0;
    else WideCharToMultiByte(CP_UTF8, 0, w, -1, s, n, NULL, NULL);
    return s;
}

static BSTR bstr_utf8(const char *s, size_t len)
{
    int n = MultiByteToWideChar(CP_UTF8, 0, s, (int)len, NULL, 0);
    BSTR b = SysAllocStringLen(NULL, (UINT)(n > 0 ? n : 0));
    if (b && n > 0) MultiByteToWideChar(CP_UTF8, 0, s, (int)len, b, n);
    return b;
}

/* ---------------------------------------------------------------- движок */

static int engine_running(void)
{
    HANDLE h = CreateMutexW(NULL, FALSE, MTX_ENGINE);
    int running = h && GetLastError() == ERROR_ALREADY_EXISTS;
    if (h) CloseHandle(h);
    return running;
}

static DWORD WINAPI engine_thread(LPVOID p)
{
    (void)p;
    happ_engine(g_hInst, WRITER_THREAD);
    return 0;
}

static void engine_stop(void)
{
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, EVT_STOP);
    int i;
    if (ev) SetEvent(ev);
    for (i = 0; i < 60 && engine_running(); i++) Sleep(50);
    if (ev) { ResetEvent(ev); CloseHandle(ev); }
}

static int engine_start(int allowDaemon)
{
    wchar_t path[MAX_PATH];
    PROCESS_INFORMATION pi;
    int i, n;

    if (engine_running() && reg_dword(LIVE_KEY, L"EngineVersion", 0) != HAPP_NATIVE_VERSION) engine_stop();
    if (engine_running()) {
        HANDLE ev = CreateEventW(NULL, FALSE, FALSE, EVT_RELOAD);
        if (ev) { SetEvent(ev); CloseHandle(ev); }
        return (int)reg_dword(LIVE_KEY, L"Writer", WRITER_DAEMON);
    }
    if (allowDaemon) {
        n = (int)GetModuleFileNameW(g_hInst, path, MAX_PATH);
        while (n > 0 && path[n - 1] != L'\\') n--;
        path[n] = 0;
        lstrcatW(path, L"happd.exe");
        ZeroMemory(&pi, sizeof(pi));
        if (CreateProcessW(path, NULL, NULL, NULL, FALSE, 0, NULL, NULL, NULL, &pi)) {
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            for (i = 0; i < 60 && !engine_running(); i++) Sleep(50);
            if (engine_running()) return WRITER_DAEMON;
        }
        reg_set_dword(LIVE_KEY, L"DaemonError", GetLastError());
    }
    if (g_thread) {
        if (WaitForSingleObject(g_thread, 0) == WAIT_TIMEOUT) return WRITER_THREAD;
        CloseHandle(g_thread);
    }
    g_thread = CreateThread(NULL, 0, engine_thread, NULL, 0, NULL);
    if (!g_thread) return -(int)GetLastError();
    for (i = 0; i < 60 && !engine_running(); i++) Sleep(20);
    return WRITER_THREAD;
}

/* ---------------------------------------------------------------- IHappNative */

typedef struct HappNative HappNative;

typedef struct {
    HRESULT (WINAPI *QueryInterface)(HappNative *, REFIID, void **);
    ULONG (WINAPI *AddRef)(HappNative *);
    ULONG (WINAPI *Release)(HappNative *);
    HRESULT (WINAPI *GetVersion)(HappNative *, int *);
    HRESULT (WINAPI *RegGetDword)(HappNative *, LPCWSTR, LPCWSTR, int *);
    HRESULT (WINAPI *RegSetDword)(HappNative *, LPCWSTR, LPCWSTR, int);
    HRESULT (WINAPI *RegGetString)(HappNative *, LPCWSTR, LPCWSTR, BSTR *);
    HRESULT (WINAPI *RegSetString)(HappNative *, LPCWSTR, LPCWSTR, LPCWSTR);
    HRESULT (WINAPI *EngineStart)(HappNative *, int, int *);
    HRESULT (WINAPI *EngineStop)(HappNative *);
    HRESULT (WINAPI *EngineStatus)(HappNative *, int *);
    HRESULT (WINAPI *Reload)(HappNative *);
    HRESULT (WINAPI *Ping)(HappNative *, LPCWSTR, int, LPCWSTR, int, int *, BSTR *);
    HRESULT (WINAPI *HttpGet)(HappNative *, LPCWSTR, LPCWSTR, int *, BSTR *);
    HRESULT (WINAPI *Diag)(HappNative *, BSTR *);
    HRESULT (WINAPI *Post)(HappNative *, LPCWSTR, LPCWSTR, int *);
} HappNativeVtbl;

struct HappNative {
    const HappNativeVtbl *vtbl;
    LONG refs;
};

static HRESULT WINAPI hn_QueryInterface(HappNative *self, REFIID riid, void **out)
{
    if (!out) return E_POINTER;
    if (same_guid(riid, &IID_IUnknown_) || same_guid(riid, &IID_IHappNative)) {
        *out = self;
        InterlockedIncrement(&self->refs);
        return S_OK;
    }
    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG WINAPI hn_AddRef(HappNative *self) { return (ULONG)InterlockedIncrement(&self->refs); }

static ULONG WINAPI hn_Release(HappNative *self)
{
    LONG r = InterlockedDecrement(&self->refs);
    if (r == 0) { LocalFree(self); InterlockedDecrement(&g_locks); }
    return (ULONG)r;
}

static HRESULT WINAPI hn_GetVersion(HappNative *self, int *v) { (void)self; *v = HAPP_NATIVE_VERSION; return S_OK; }

static HRESULT WINAPI hn_RegGetDword(HappNative *self, LPCWSTR key, LPCWSTR name, int *out)
{
    const DWORD missing = 0xDEADBEEF;
    DWORD v = reg_dword(key, name, missing);
    (void)self;
    *out = v == missing ? 0 : (int)v;
    return v == missing ? S_FALSE : S_OK;
}

static HRESULT WINAPI hn_RegSetDword(HappNative *self, LPCWSTR key, LPCWSTR name, int v)
{
    (void)self;
    return reg_set_dword(key, name, (DWORD)v) ? S_OK : E_ACCESSDENIED;
}

static HRESULT WINAPI hn_RegGetString(HappNative *self, LPCWSTR key, LPCWSTR name, BSTR *out)
{
    wchar_t buf[512];
    int ok = reg_str_w(key, name, buf, 512);
    (void)self;
    *out = SysAllocString(buf);
    return ok ? S_OK : S_FALSE;
}

static HRESULT WINAPI hn_RegSetString(HappNative *self, LPCWSTR key, LPCWSTR name, LPCWSTR v)
{
    (void)self;
    return reg_set_str_w(key, name, v ? v : L"") ? S_OK : E_ACCESSDENIED;
}

static HRESULT WINAPI hn_EngineStart(HappNative *self, int allowDaemon, int *how)
{
    (void)self;
    *how = engine_start(allowDaemon);
    return S_OK;
}

static HRESULT WINAPI hn_EngineStop(HappNative *self) { (void)self; engine_stop(); return S_OK; }

static HRESULT WINAPI hn_EngineStatus(HappNative *self, int *writer)
{
    (void)self;
    *writer = engine_running() ? (int)reg_dword(LIVE_KEY, L"Writer", WRITER_DAEMON) : WRITER_NONE;
    return S_OK;
}

static HRESULT WINAPI hn_Reload(HappNative *self)
{
    HANDLE ev = CreateEventW(NULL, FALSE, FALSE, EVT_RELOAD);
    (void)self;
    if (ev) { SetEvent(ev); CloseHandle(ev); }
    return S_OK;
}

/* TCP + TLS до сервера: время в мс или -1 и текст ошибки. */
static HRESULT WINAPI hn_Ping(HappNative *self, LPCWSTR host, int port, LPCWSTR sni, int insecure, int *ms, BSTR *err)
{
    Outbound o;
    char e[256] = "", *h = utf8(host), *s = utf8(sni);
    (void)self;
    *ms = -1;
    if (!tls_ready()) { *err = SysAllocString(L"TLS не запустился"); free(h); free(s); return S_OK; }
    memset(&o, 0, sizeof(o));
    o.type = OUT_TROJAN;
    snprintf(o.host, sizeof(o.host), "%s", h ? h : "");
    snprintf(o.sni, sizeof(o.sni), "%s", s ? s : "");
    o.port = port;
    o.insecure = insecure;
    *ms = tun_ping(&o, e, sizeof(e));
    *err = bstr_utf8(e, strlen(e));
    free(h);
    free(s);
    return S_OK;
}

/* GET по https://. status = HTTP-код или -1 (тогда body — текст ошибки). */
static HRESULT WINAPI hn_HttpGet(HappNative *self, LPCWSTR url, LPCWSTR headers, int *status, BSTR *body)
{
    char e[256] = "", *u = utf8(url), *hd = utf8(headers), *b = NULL;
    size_t len = 0;
    (void)self;
    *status = -1;
    if (!tls_ready()) {
        *body = SysAllocString(L"TLS не запустился");
    } else if (https_get(u ? u : "", hd, status, &b, &len, e, sizeof(e)) != 0) {
        *status = -1;
        *body = bstr_utf8(e, strlen(e));
    } else {
        *body = bstr_utf8(b, len);
    }
    free(b);
    free(u);
    free(hd);
    return S_OK;
}

/* ---------------------------------------------------------------- диагностика */

typedef struct { char *p; size_t len, cap; } Text;

static void tadd(Text *t, const char *fmt, ...)
{
    char line[1024];
    va_list ap;
    size_t n;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    n = strlen(line);
    if (t->len + n + 1 > t->cap) {
        size_t cap = (t->cap + n + 1) * 2;
        char *np = (char *)realloc(t->p, cap);
        if (!np) return;
        t->p = np;
        t->cap = cap;
    }
    memcpy(t->p + t->len, line, n + 1);
    t->len += n;
}

/* Длинный текст целиком (tadd режет строку до 1 КБ). */
static void tadd_long(Text *t, const char *s)
{
    size_t n = strlen(s);
    if (t->len + n + 1 > t->cap) {
        size_t cap = t->len + n + 1024;
        char *np = (char *)realloc(t->p, cap);
        if (!np) return;
        t->p = np;
        t->cap = cap;
    }
    memcpy(t->p + t->len, s, n + 1);
    t->len += n;
}

/* Первая строка ответа и тело (коротко). */
static void show_reply(Text *t, const char *buf, int n)
{
    const char *body = strstr(buf, "\r\n\r\n");
    const char *eol = strstr(buf, "\r\n");
    tadd(t, "  ответ: %.*s\n", eol ? (int)(eol - buf) : (n > 80 ? 80 : n), buf);
    if (body) tadd(t, "  тело: %.120s\n", body + 4);
}

static const char REQ[] = "GET http://api.ipify.org/ HTTP/1.1\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n";
static const char REQ_ORIGIN[] = "GET / HTTP/1.1\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n";

static HRESULT WINAPI hn_Diag(HappNative *self, BSTR *out)
{
    Text t = {0, 0, 0};
    char buf[4096], err[256] = "";
    wchar_t ws[256];
    int n, port = (int)reg_dword(CFG_KEY, L"ListenPort", 10809);
    unsigned long t0;
    sock_t s;
    (void)self;

    tadd(&t, "== состояние\n");
    tadd(&t, "  движок: %s, writer %d, версия %d\n", engine_running() ? "работает" : "НЕ работает",
         (int)reg_dword(LIVE_KEY, L"Writer", 0), (int)reg_dword(LIVE_KEY, L"EngineVersion", 0));
    tadd(&t, "  Running %d, порт %d, соединений %d, всего %d, вверх %d КБ, вниз %d КБ\n",
         (int)reg_dword(LIVE_KEY, L"Running", 0), port, (int)reg_dword(LIVE_KEY, L"Conns", 0),
         (int)reg_dword(LIVE_KEY, L"Total", 0), (int)reg_dword(LIVE_KEY, L"UpKB", 0), (int)reg_dword(LIVE_KEY, L"DownKB", 0));
    if (reg_str_w(LIVE_KEY, L"Error", ws, 256)) { WideCharToMultiByte(CP_UTF8, 0, ws, -1, buf, sizeof(buf), NULL, NULL); tadd(&t, "  ошибка: %s\n", buf); }
    tadd(&t, "  DaemonError %d\n", (int)reg_dword(LIVE_KEY, L"DaemonError", 0));
    if (reg_str_w(LIVE_KEY, L"LocalIp", ws, 256)) { WideCharToMultiByte(CP_UTF8, 0, ws, -1, buf, sizeof(buf), NULL, NULL); tadd(&t, "  адрес телефона: %s\n", buf); }

    tadd(&t, "== журнал happd (\\Temp\\happd.log)\n");
    {
        FILE *f = fopen("\\Temp\\happd.log", "rb");
        if (!f) tadd(&t, "  нет файла\n");
        else {
            long size;
            fseek(f, 0, SEEK_END);
            size = ftell(f);
            fseek(f, size > 3000 ? size - 3000 : 0, SEEK_SET);
            n = (int)fread(buf, 1, sizeof(buf) - 1, f);
            buf[n > 0 ? n : 0] = 0;
            fclose(f);
            tadd(&t, "%s\n", buf);
        }
    }

    tadd(&t, "== через прокси 127.0.0.1:%d (как IE)\n", port);
    plat_init();
    t0 = GetTickCount();
    s = net_connect("127.0.0.1", port, 3000);
    if (s == SOCK_INVALID) {
        tadd(&t, "  НЕ подключился к прокси (ошибка %d)\n", WSAGetLastError());
    } else {
        int got = 0;
        net_send_all(s, REQ, sizeof(REQ) - 1);
        while (got < (int)sizeof(buf) - 1 && net_wait2(s, SOCK_INVALID, 15000) > 0) {
            n = net_recv(s, buf + got, sizeof(buf) - 1 - (size_t)got);
            if (n <= 0) break;
            got += n;
        }
        buf[got] = 0;
        tadd(&t, "  %lu мс, %d байт\n", GetTickCount() - t0, got);
        if (got) show_reply(&t, buf, got);
        net_close(s);
    }

    tadd(&t, "== Trojan напрямую из приложения\n");
    if (!tls_ready()) tadd(&t, "  TLS не запустился\n");
    else {
        Outbound o;
        Tunnel *tn;
        memset(&o, 0, sizeof(o));
        o.type = OUT_TROJAN;
        o.port = (int)reg_dword(CFG_KEY, L"Port", 443);
        o.insecure = (int)reg_dword(CFG_KEY, L"Insecure", 0);
        reg_str_a(CFG_KEY, L"Server", o.host, sizeof(o.host));
        reg_str_a(CFG_KEY, L"Password", o.password, sizeof(o.password));
        reg_str_a(CFG_KEY, L"Sni", o.sni, sizeof(o.sni));
        tadd(&t, "  сервер %s:%d, sni %s%s\n", o.host, o.port, o.sni, o.insecure ? ", insecure" : "");
        t0 = GetTickCount();
        tn = tun_open(&o, "api.ipify.org", 80, err, sizeof(err));
        if (!tn) tadd(&t, "  ОШИБКА: %s\n", err);
        else {
            int got = 0;
            tun_write(tn, REQ_ORIGIN, sizeof(REQ_ORIGIN) - 1);
            while (got < (int)sizeof(buf) - 1) {
                if (tun_pending(tn) == 0 && net_wait2(tun_sock(tn), SOCK_INVALID, 15000) <= 0) break;
                n = tun_read(tn, buf + got, sizeof(buf) - 1 - (size_t)got);
                if (n == -2) continue;
                if (n <= 0) break;
                got += n;
            }
            buf[got] = 0;
            tadd(&t, "  %lu мс, %d байт\n", GetTickCount() - t0, got);
            if (got) show_reply(&t, buf, got);
            tun_close(tn);
        }
    }
    *out = bstr_utf8(t.p ? t.p : "", t.len);
    free(t.p);
    return S_OK;
}

/* POST текста по http:// своим сокетом — мимо прокси Wi-Fi (журнал на мак). status — HTTP-код или -1. */
static HRESULT WINAPI hn_Post(HappNative *self, LPCWSTR url, LPCWSTR text, int *status)
{
    char *u = utf8(url), *body = utf8(text), host[256], hdr[1024], resp[256];
    const char *h, *path;
    int port = 80, n, got = 0;
    sock_t s;
    (void)self;
    *status = -1;
    if (!u || !body || strncmp(u, "http://", 7) != 0) goto done;
    h = u + 7;
    path = strchr(h, '/');
    snprintf(host, sizeof(host), "%.*s", path ? (int)(path - h) : (int)strlen(h), h);
    if (strchr(host, ':')) { port = atoi(strchr(host, ':') + 1); *strchr(host, ':') = 0; }
    plat_init();
    s = net_connect(host, port, 3000);
    if (s == SOCK_INVALID) goto done;
    snprintf(hdr, sizeof(hdr), "POST %s HTTP/1.1\r\nHost: %s:%d\r\nContent-Type: text/plain; charset=utf-8\r\n"
             "Content-Length: %u\r\nConnection: close\r\n\r\n", path ? path : "/", host, port, (unsigned)strlen(body));
    if (net_send_all(s, hdr, strlen(hdr)) == 0 && net_send_all(s, body, strlen(body)) == 0) {
        while (got < (int)sizeof(resp) - 1 && net_wait2(s, SOCK_INVALID, 3000) > 0) {
            n = net_recv(s, resp + got, sizeof(resp) - 1 - (size_t)got);
            if (n <= 0) break;
            got += n;
        }
        resp[got] = 0;
        if (sscanf(resp, "HTTP/%*s %d", status) != 1) *status = -1;
    }
    net_close(s);
done:
    free(u);
    free(body);
    return S_OK;
}

static const HappNativeVtbl g_vtbl = {
    hn_QueryInterface, hn_AddRef, hn_Release, hn_GetVersion,
    hn_RegGetDword, hn_RegSetDword, hn_RegGetString, hn_RegSetString,
    hn_EngineStart, hn_EngineStop, hn_EngineStatus, hn_Reload, hn_Ping, hn_HttpGet, hn_Diag, hn_Post};

/* ---------------------------------------------------------------- IClassFactory */

typedef struct Factory Factory;
typedef struct {
    HRESULT (WINAPI *QueryInterface)(Factory *, REFIID, void **);
    ULONG (WINAPI *AddRef)(Factory *);
    ULONG (WINAPI *Release)(Factory *);
    HRESULT (WINAPI *CreateInstance)(Factory *, IUnknown *, REFIID, void **);
    HRESULT (WINAPI *LockServer)(Factory *, BOOL);
} FactoryVtbl;
struct Factory { const FactoryVtbl *vtbl; };

static HRESULT WINAPI cf_QueryInterface(Factory *self, REFIID riid, void **out)
{
    if (same_guid(riid, &IID_IUnknown_) || same_guid(riid, &IID_IClassFactory_)) { *out = self; return S_OK; }
    *out = NULL;
    return E_NOINTERFACE;
}
static ULONG WINAPI cf_AddRef(Factory *self) { (void)self; return 2; }
static ULONG WINAPI cf_Release(Factory *self) { (void)self; return 1; }

static HRESULT WINAPI cf_CreateInstance(Factory *self, IUnknown *outer, REFIID riid, void **out)
{
    HappNative *o;
    HRESULT hr;
    (void)self;
    *out = NULL;
    if (outer) return CLASS_E_NOAGGREGATION;
    o = (HappNative *)LocalAlloc(LMEM_FIXED, sizeof(HappNative));
    if (!o) return E_OUTOFMEMORY;
    o->vtbl = &g_vtbl;
    o->refs = 1;
    InterlockedIncrement(&g_locks);
    hr = hn_QueryInterface(o, riid, out);
    hn_Release(o);
    return hr;
}

static HRESULT WINAPI cf_LockServer(Factory *self, BOOL lock)
{
    (void)self;
    if (lock) InterlockedIncrement(&g_locks); else InterlockedDecrement(&g_locks);
    return S_OK;
}

static const FactoryVtbl g_cfVtbl = {cf_QueryInterface, cf_AddRef, cf_Release, cf_CreateInstance, cf_LockServer};
static Factory g_factory = {&g_cfVtbl};

__declspec(dllexport) HRESULT WINAPI DllGetClassObject(REFCLSID clsid, REFIID riid, void **out)
{
    if (!same_guid(clsid, &CLSID_HappNative)) { *out = NULL; return CLASS_E_CLASSNOTAVAILABLE; }
    return cf_QueryInterface(&g_factory, riid, out);
}

__declspec(dllexport) HRESULT WINAPI DllCanUnloadNow(void)
{
    return g_locks == 0 && !g_thread ? S_OK : S_FALSE;
}

BOOL WINAPI DllMain(HANDLE hInst, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) g_hInst = (HINSTANCE)hInst;
    return TRUE;
}
