/*
 * HTTPS GET для загрузки подписки. На WP7 HttpWebRequest не даёт поставить свой User-Agent и
 * x-hwid, а без них панель отдаёт заглушку «App not supported» — поэтому качаем сами, через mbedTLS.
 */
#include "https.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tunnel.h"

static int ci_prefix(const char *s, const char *p)
{
    for (; *p; s++, p++)
        if (tolower((unsigned char)*s) != tolower((unsigned char)*p)) return 0;
    return 1;
}

/* Значение заголовка (без пробелов в начале) или NULL. hdr — весь блок заголовков. */
static const char *header(const char *hdr, const char *name, char *out, size_t outlen)
{
    const char *p = hdr;
    size_t nl = strlen(name);
    while ((p = strstr(p, "\r\n")) != NULL) {
        p += 2;
        if (ci_prefix(p, name) && p[nl] == ':') {
            const char *v = p + nl + 1, *e;
            while (*v == ' ') v++;
            e = strstr(v, "\r\n");
            if (!e) e = v + strlen(v);
            snprintf(out, outlen, "%.*s", (int)(e - v), v);
            return out;
        }
    }
    return NULL;
}

/* Сборка chunked-тела на месте. Возвращает новую длину. */
static size_t dechunk(char *b, size_t len)
{
    size_t in = 0, out = 0;
    while (in < len) {
        char *end;
        unsigned long n = strtoul(b + in, &end, 16);
        char *crlf = strstr(b + in, "\r\n");
        if (!crlf || n == 0) break;
        in = (size_t)(crlf - b) + 2;
        if (in + n > len) n = (unsigned long)(len - in);
        memmove(b + out, b + in, n);
        out += n;
        in += n + 2;
        (void)end;
    }
    return out;
}

int https_get(const char *url, const char *extra_headers, int *status, char **body, size_t *body_len,
              char *err, size_t errlen)
{
    char cur[1024];
    int hop;
    *body = NULL;
    *body_len = 0;
    *status = 0;
    snprintf(cur, sizeof(cur), "%s", url);

    for (hop = 0; hop < 4; hop++) {
        Outbound o;
        Tunnel *t;
        const char *h = cur, *path;
        char *buf = NULL, *hend, tmp[1024];
        size_t cap = 65536, len = 0, hl;
        int n;

        if (!ci_prefix(cur, "https://")) { snprintf(err, errlen, "нужна ссылка https://"); return -1; }
        h += 8;
        path = strchr(h, '/');
        memset(&o, 0, sizeof(o));
        hl = path ? (size_t)(path - h) : strlen(h);
        snprintf(o.host, sizeof(o.host), "%.*s", (int)hl, h);
        o.port = 443;
        {
            char *colon = strchr(o.host, ':');
            if (colon) { o.port = atoi(colon + 1); *colon = 0; }
        }
        snprintf(o.sni, sizeof(o.sni), "%s", o.host);
        if (!path) path = "/";

        t = tun_tls(&o, err, errlen);
        if (!t) return -1;
        snprintf(tmp, sizeof(tmp), "GET %s HTTP/1.1\r\nHost: %s\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n", path, o.host);
        /* Свои заголовки: обрезаем хвостовые CR/LF и ставим ровно один CRLF после последнего. */
        {
            size_t el = extra_headers ? strlen(extra_headers) : 0;
            while (el > 0 && (extra_headers[el - 1] == '\r' || extra_headers[el - 1] == '\n')) el--;
            if (tun_write(t, tmp, strlen(tmp)) || (el && (tun_write(t, extra_headers, el) || tun_write(t, "\r\n", 2))) ||
                tun_write(t, "\r\n", 2))
                n = -1;
            else
                n = 0;
        }
        if (n) {
            snprintf(err, errlen, "не отправился запрос");
            tun_close(t);
            return -1;
        }
        buf = (char *)malloc(cap + 1);
        if (!buf) { tun_close(t); return -1; }
        for (;;) {
            if (len == cap) {
                char *nb;
                if (cap > 8 * 1024 * 1024) break;
                nb = (char *)realloc(buf, cap * 2 + 1);
                if (!nb) break;
                buf = nb;
                cap *= 2;
            }
            if (tun_pending(t) == 0 && net_wait2(tun_sock(t), SOCK_INVALID, 20000) <= 0) break;
            n = tun_read(t, buf + len, cap - len);
            if (n == -2) continue;
            if (n <= 0) break;
            len += (size_t)n;
        }
        tun_close(t);
        buf[len] = 0;

        hend = strstr(buf, "\r\n\r\n");
        if (!hend || sscanf(buf, "HTTP/%*s %d", status) != 1) {
            snprintf(err, errlen, "сервер ответил не по HTTP");
            free(buf);
            return -1;
        }
        hend[2] = 0; /* обрезаем блок заголовков для поиска */
        if (*status >= 300 && *status < 400 && header(buf, "Location", tmp, sizeof(tmp))) {
            if (tmp[0] == '/') snprintf(cur, sizeof(cur), "https://%s%s", o.host, tmp);
            else snprintf(cur, sizeof(cur), "%s", tmp);
            free(buf);
            continue;
        }
        {
            size_t hdrlen = (size_t)(hend - buf) + 4, blen = len - hdrlen;
            int chunked = header(buf, "Transfer-Encoding", tmp, sizeof(tmp)) && strstr(tmp, "chunked");
            memmove(buf, buf + hdrlen, blen);
            if (chunked) blen = dechunk(buf, blen);
            buf[blen] = 0;
            *body = buf;
            *body_len = blen;
        }
        return 0;
    }
    snprintf(err, errlen, "слишком много перенаправлений");
    return -1;
}
