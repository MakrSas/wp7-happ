/*
 * Локальный прокси: один порт понимает и HTTP (CONNECT и обычные запросы с полным URL — так ходит
 * IE через прокси Wi-Fi), и SOCKS5 (для наших приложений, например будущего Telegram).
 * Каждое соединение — свой поток и свой туннель до сервера.
 */
#include "proxy.h"
#include "ca.h"
#include "mitm.h"

#include <ctype.h>
#ifndef _WIN32_WCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32_WCE
static CRITICAL_SECTION g_olock;
#define OLOCK() EnterCriticalSection(&g_olock)
#define OUNLOCK() LeaveCriticalSection(&g_olock)
#define OLOCK_INIT() InitializeCriticalSection(&g_olock)
#else
#include <pthread.h>
static pthread_mutex_t g_olock = PTHREAD_MUTEX_INITIALIZER;
#define OLOCK() pthread_mutex_lock(&g_olock)
#define OUNLOCK() pthread_mutex_unlock(&g_olock)
#define OLOCK_INIT() ((void)0)
#endif

static Outbound g_out;
volatile int g_mitm = 1; /* перехват HTTPS для IE (TLS ниже 1.2) */
static char g_err[200];
static int g_lock_ready;

static void lock_ready(void)
{
    if (!g_lock_ready) { OLOCK_INIT(); g_lock_ready = 1; }
}

void proxy_set_outbound(const Outbound *o)
{
    lock_ready();
    OLOCK();
    g_out = *o;
    OUNLOCK();
}

void proxy_get_outbound(Outbound *o)
{
    lock_ready();
    OLOCK();
    *o = g_out;
    OUNLOCK();
}

void proxy_last_error(char *buf, size_t len)
{
    lock_ready();
    OLOCK();
    snprintf(buf, len, "%s", g_err);
    OUNLOCK();
}

static void set_error(const char *e)
{
    OLOCK();
    snprintf(g_err, sizeof(g_err), "%s", e);
    OUNLOCK();
}

/* ---------------------------------------------------------------- перекачка */

#define BUF 16384
#define IDLE_MS (5 * 60 * 1000)

static void relay(sock_t c, Tunnel *t, char *buf)
{
    unsigned long last = plat_ms();
    for (;;) {
        int m, n;
        if (tun_pending(t) > 0) {
            m = 2;
        } else {
            m = net_wait2(c, tun_sock(t), 1000);
            if (m < 0) break;
            if (m == 0) {
                if (plat_ms() - last > IDLE_MS) break;
                continue;
            }
        }
        last = plat_ms();
        if (m & 1) {
            n = net_recv(c, buf, BUF);
            if (n <= 0) break;
            if (tun_write(t, buf, (size_t)n) != 0) break;
            plat_add64(&g_bytes_up, n);
        }
        if (m & 2) {
            n = tun_read(t, buf, BUF);
            if (n == -2) continue;
            if (n <= 0) break;
            if (net_send_all(c, buf, (size_t)n) != 0) break;
            plat_add64(&g_bytes_down, n);
        }
    }
}

/* Локальная сеть и сам телефон идут напрямую: зарубежный сервер до них не достанет. */
static int is_local(const char *host)
{
    unsigned a, b, c, d;
    if (!strchr(host, '.')) return 1;                       /* «router», «localhost» */
    if (strlen(host) > 6 && !strcmp(host + strlen(host) - 6, ".local")) return 1;
    if (sscanf(host, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return 0;
    return a == 10 || a == 127 || (a == 192 && b == 168) || (a == 172 && b >= 16 && b <= 31) ||
           (a == 169 && b == 254);
}

static Tunnel *open_tunnel(const char *host, int port)
{
    Outbound o;
    char err[200];
    Tunnel *t;
    if (is_local(host)) {
        t = tun_direct(host, port, err, sizeof(err));
        if (!t) plat_log("%s:%d напрямую — %s", host, port, err);
        return t;
    }
    proxy_get_outbound(&o);
    if (!o.type) {
        set_error("сервер не выбран");
        return NULL;
    }
    err[0] = 0;
    t = tun_open(&o, host, port, err, sizeof(err));
    if (!t) {
        plat_log("%s:%d — %s", host, port, err);
        set_error(err);
    } else {
        set_error("");
    }
    return t;
}

/* Разбор ClientHello в журнал: версия записи, версия клиента, шифры, расширения. */
static void log_client_hello(const char *host, const unsigned char *p, int n)
{
    char line[600];
    int pos, len, i, o = 0;
    if (n < 44 || p[0] != 0x16 || p[5] != 1) {
        plat_log("TLS %s: не ClientHello (%02x %02x)", host, n > 0 ? p[0] : 0, n > 5 ? p[5] : 0);
        return;
    }
    pos = 43;
    pos += 1 + p[pos];                         /* session id */
    if (pos + 2 > n) return;
    len = (p[pos] << 8) | p[pos + 1];
    pos += 2;
    o += snprintf(line + o, sizeof(line) - (size_t)o, "TLS %s: запись %02x%02x, клиент %02x%02x, шифров %d:",
                  host, p[1], p[2], p[9], p[10], len / 2);
    for (i = 0; i < len && pos + i + 1 < n && o < (int)sizeof(line) - 8; i += 2)
        o += snprintf(line + o, sizeof(line) - (size_t)o, " %02x%02x", p[pos + i], p[pos + i + 1]);
    pos += len;
    if (pos < n) {
        pos += 1 + p[pos];                     /* compression */
        if (pos + 2 <= n) {
            int el = (p[pos] << 8) | p[pos + 1], e = pos + 2;
            o += snprintf(line + o, sizeof(line) - (size_t)o, " | расширения:");
            while (e + 4 <= n && e + 4 <= pos + 2 + el && o < (int)sizeof(line) - 8) {
                int type = (p[e] << 8) | p[e + 1], l = (p[e + 2] << 8) | p[e + 3];
                o += snprintf(line + o, sizeof(line) - (size_t)o, " %d", type);
                e += 4 + l;
            }
        }
    }
    plat_log("%s", line);
}

/* ---------------------------------------------------------------- SOCKS5 */

static int recv_exact(sock_t c, unsigned char *p, int n)
{
    while (n > 0) {
        int r = net_recv(c, p, (size_t)n);
        if (r <= 0) return -1;
        p += r;
        n -= r;
    }
    return 0;
}

static void socks5(sock_t c, unsigned char *buf, int have)
{
    unsigned char h[4], rep[10] = {5, 0, 0, 1, 0, 0, 0, 0, 0, 0};
    char host[256];
    int port, nm;
    Tunnel *t;

    /* приветствие: 05 n методы… */
    if (have < 2) { if (recv_exact(c, buf + have, 2 - have)) return; have = 2; }
    nm = buf[1];
    if (have < 2 + nm && recv_exact(c, buf + have, 2 + nm - have)) return;
    if (net_send_all(c, "\x05\x00", 2)) return; /* без пароля */

    if (recv_exact(c, h, 4) || h[0] != 5) return;
    if (h[1] != 1) { rep[1] = 7; net_send_all(c, rep, 10); return; } /* только CONNECT */
    if (h[3] == 1) {
        unsigned char a[4];
        if (recv_exact(c, a, 4)) return;
        sprintf(host, "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
    } else if (h[3] == 3) {
        unsigned char l;
        if (recv_exact(c, &l, 1) || recv_exact(c, (unsigned char *)host, l)) return;
        host[l] = 0;
    } else {
        rep[1] = 8; net_send_all(c, rep, 10); return; /* IPv6 не поддерживаем */
    }
    if (recv_exact(c, h, 2)) return;
    port = (h[0] << 8) | h[1];

    t = open_tunnel(host, port);
    if (!t) { rep[1] = 1; net_send_all(c, rep, 10); return; }
    if (net_send_all(c, rep, 10) == 0) relay(c, t, (char *)buf);
    tun_close(t);
}

/* ---------------------------------------------------------------- HTTP */

static void serve_happ(sock_t c, const char *path)
{
    char hdr[300];
    size_t len;
    const unsigned char *der = ca_root_der(&len);
    if (path && strstr(path, "happ-root.cer") && der) {
        snprintf(hdr, sizeof(hdr), "HTTP/1.1 200 OK\r\nContent-Type: application/x-x509-ca-cert\r\n"
                 "Content-Disposition: attachment; filename=happ-root.cer\r\nContent-Length: %u\r\nConnection: close\r\n\r\n",
                 (unsigned)len);
        if (net_send_all(c, hdr, strlen(hdr)) == 0) net_send_all(c, der, len);
        return;
    }
    {
        char body[1200];
        int bl = snprintf(body, sizeof(body),
            "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><title>Happ</title></head>"
            "<body style=\"background:#000;color:#fff;font-family:'Segoe WP',sans-serif;margin:24px\">"
            "<div style=\"font-size:14px\">HAPP</div><div style=\"font-size:56px;font-weight:200;margin:0 0 24px -3px\">сертификат</div>"
            "%s</body></html>",
            der ? "<p>Чтобы IE открывал современные HTTPS-сайты, установите корневой сертификат Happ. "
                  "Он создан на этом телефоне, и его ключ никуда не передаётся.</p>"
                  "<p><a href=\"happ-root.cer\" style=\"color:#fff;font-size:32px\">установить сертификат</a></p>"
                  "<p style=\"color:#999\">Удалить можно в любой момент. Без него HTTPS-сайты тоже откроются, но IE будет предупреждать о сертификате.</p>"
                : "<p>Сертификат ещё создаётся — это занимает до минуты при первом включении VPN. Обновите страницу чуть позже.</p>");
        snprintf(hdr, sizeof(hdr), "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", bl);
        if (net_send_all(c, hdr, strlen(hdr)) == 0) net_send_all(c, body, (size_t)bl);
    }
}

static int starts_ci(const char *s, const char *p)
{
    while (*p) {
        if (tolower((unsigned char)*s) != tolower((unsigned char)*p)) return 0;
        s++; p++;
    }
    return 1;
}

static void http(sock_t c, char *buf, int have)
{
    char *end, method[16], target[2048], ver[16];
    char host[256];
    int port, hdrlen;
    Tunnel *t;

    /* заголовок целиком */
    for (;;) {
        buf[have] = 0;
        end = strstr(buf, "\r\n\r\n");
        if (end) break;
        if (have >= BUF - 1) return;
        {
            int n = net_recv(c, buf + have, (size_t)(BUF - 1 - have));
            if (n <= 0) return;
            have += n;
        }
    }
    hdrlen = (int)(end - buf) + 4;
    if (sscanf(buf, "%15s %2047s %15s", method, target, ver) != 3) return;

    if (strcmp(method, "CONNECT") == 0) {
        char *colon = strrchr(target, ':');
        port = colon ? atoi(colon + 1) : 443;
        if (colon) *colon = 0;
        snprintf(host, sizeof(host), "%s", target);
        t = open_tunnel(host, port);
        if (!t) {
            const char *r = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            net_send_all(c, r, strlen(r));
            return;
        }
        if (net_send_all(c, "HTTP/1.1 200 Connection established\r\n\r\n", 39) == 0) {
            if (have > hdrlen && tun_write(t, buf + hdrlen, (size_t)(have - hdrlen)) != 0) { tun_close(t); return; }
            /* Что за TLS у клиента: версия и шифры из ClientHello. IE9 (TLS 1.0) — перехватываем. */
            if (have <= hdrlen && net_wait2(c, SOCK_INVALID, 5000) > 0) {
                int n = net_recv(c, buf, BUF);
                const unsigned char *u = (const unsigned char *)buf;
                if (n <= 0) { tun_close(t); return; }
                log_client_hello(host, u, n);
                if (g_mitm && port == 443 && ca_ready() && n > 10 && u[0] == 0x16 && u[5] == 1 &&
                    ((u[9] << 8) | u[10]) < 0x0303 && !is_local(host)) {
                    char err[200] = "";
                    mitm_run(c, t, host, u, (size_t)n, err, sizeof(err));
                    return; /* туннель закрыт внутри */
                }
                if (tun_write(t, buf, (size_t)n) != 0) { tun_close(t); return; }
            }
            relay(c, t, buf);
        }
        tun_close(t);
        return;
    }

    /*
     * Страница и корневой сертификат Happ для установки из IE:
     *  — прямой запрос на порт прокси («GET / HTTP/1.1»: IE ходит на адрес телефона мимо прокси);
     *  — http://happ.cert/ через прокси.
     */
    if (target[0] == '/') {
        serve_happ(c, target);
        return;
    }
    if (starts_ci(target, "http://happ.cert/") || strcmp(target, "http://happ.cert") == 0) {
        serve_happ(c, target + 16);
        return;
    }

    /* Обычный запрос через прокси: «GET http://host[:port]/path HTTP/1.1» → «GET /path HTTP/1.1». */
    {
        char *p = target, *path, *hp, *line, *next, *out;
        size_t olen = 0;
        if (!starts_ci(p, "http://")) {
            const char *r = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            net_send_all(c, r, strlen(r));
            return;
        }
        p += 7;
        path = strchr(p, '/');
        if (path) { *path = 0; }
        hp = strrchr(p, ':');
        port = hp ? atoi(hp + 1) : 80;
        if (hp) *hp = 0;
        snprintf(host, sizeof(host), "%s", p);
        if (path) *path = '/';

        t = open_tunnel(host, port);
        if (!t) {
            const char *r = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            net_send_all(c, r, strlen(r));
            return;
        }
        out = (char *)malloc((size_t)hdrlen + 64);
        if (!out) { tun_close(t); return; }
        olen = (size_t)sprintf(out, "%s %s %s\r\n", method, path ? path : "/", ver);
        line = strstr(buf, "\r\n") + 2;
        while (line < buf + hdrlen - 2) {
            next = strstr(line, "\r\n");
            if (!next) break;
            if (!starts_ci(line, "Proxy-Connection:") && !starts_ci(line, "Proxy-Authorization:")) {
                memcpy(out + olen, line, (size_t)(next - line + 2));
                olen += (size_t)(next - line + 2);
            }
            line = next + 2;
        }
        memcpy(out + olen, "\r\n", 2);
        olen += 2;
        if (tun_write(t, out, olen) == 0 &&
            (have <= hdrlen || tun_write(t, buf + hdrlen, (size_t)(have - hdrlen)) == 0)) {
            free(out);
            relay(c, t, buf);
        } else {
            free(out);
        }
        tun_close(t);
    }
}

/* ---------------------------------------------------------------- приём */

/* Слушаем на всех адресах (WP7 не ходит в прокси на 127.0.0.1), но пускаем только сам телефон. */
static int from_self(sock_t c)
{
    struct sockaddr_in peer, self;
    socklen_t pl = sizeof(peer), sl = sizeof(self);
    if (getpeername(c, (struct sockaddr *)&peer, &pl) != 0 || getsockname(c, (struct sockaddr *)&self, &sl) != 0) return 0;
    if ((ntohl(peer.sin_addr.s_addr) >> 24) == 127) return 1;
    return peer.sin_addr.s_addr == self.sin_addr.s_addr;
}

static void client_thread(void *arg)
{
    sock_t c = (sock_t)(intptr_t)arg;
    char *buf;
    int n;
    if (!from_self(c)) {
        plat_log("чужое соединение отклонено");
        net_close(c);
        return;
    }
    buf = (char *)malloc(BUF + 1);
    plat_add(&g_active_conns, 1);
    plat_add(&g_total_conns, 1);
    if (buf && (n = net_recv(c, buf, BUF)) > 0) {
        /* первая строка запроса — в журнал, чтобы видеть, что шлёт IE */
        int i, l = n < 160 ? n : 160;
        char head[161];
        for (i = 0; i < l; i++) head[i] = (buf[i] == '\r' || buf[i] == '\n') ? '|' : (buf[i] < 32 ? '.' : buf[i]);
        head[l] = 0;
        plat_log("соединение #%ld, %d байт: %s", g_total_conns, n, head);
        if ((unsigned char)buf[0] == 5) socks5(c, (unsigned char *)buf, n);
        else http(c, buf, n);
        plat_log("соединение #%ld закрыто", g_total_conns);
    } else {
        plat_log("соединение без данных (%d)", n);
    }
    free(buf);
    net_close(c);
    plat_add(&g_active_conns, -1);
}

int proxy_run(const char *addr, int port, volatile int *stop)
{
    sock_t ls = net_listen(addr, port);
    lock_ready();
    if (ls == SOCK_INVALID) return -1;
    plat_log("слушаю %s:%d", addr, port);
    while (!*stop) {
        sock_t c;
        int m = net_wait2(ls, SOCK_INVALID, 500);
        if (m <= 0) continue;
        c = net_accept(ls);
        if (c == SOCK_INVALID) continue;
        if (plat_thread(client_thread, (void *)(intptr_t)c) != 0) net_close(c);
    }
    net_close(ls);
    return 0;
}
