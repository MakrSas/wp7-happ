/*
 * Выход в интернет через Trojan: TLS (1.3 или 1.2) до сервера, затем заголовок
 *   hex(SHA224(пароль)) CRLF  01 ATYP АДРЕС ПОРТ  CRLF
 * и дальше сырые данные в обе стороны.
 */
#include "tunnel.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/sha256.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"
#include "psa/crypto.h"
#ifndef _WIN32_WCE
#include <sys/socket.h>
#endif
#ifdef MBEDTLS_THREADING_ALT
#include "mbedtls/threading.h"
#endif

struct Tunnel {
    sock_t s;
    int plain;     /* напрямую, без TLS (локальная сеть) */
    Tunnel *inner; /* TLS к сайту внутри туннеля до сервера (перехват HTTPS для IE) */
    mbedtls_ssl_context ssl;
};

static mbedtls_entropy_context g_entropy;
static mbedtls_ctr_drbg_context g_drbg;
static mbedtls_x509_crt g_ca;
static mbedtls_ssl_config g_conf_verify, g_conf_insecure;
static int g_have_ca;

/* ---------------------------------------------------------------- WinCE: мьютексы и энтропия */
#ifdef _WIN32_WCE
static void mx_init(mbedtls_threading_mutex_t *m) { InitializeCriticalSection(&m->cs); m->valid = 1; }
static void mx_free(mbedtls_threading_mutex_t *m) { if (m->valid) DeleteCriticalSection(&m->cs); m->valid = 0; }
static int mx_lock(mbedtls_threading_mutex_t *m) { if (!m->valid) return -1; EnterCriticalSection(&m->cs); return 0; }
static int mx_unlock(mbedtls_threading_mutex_t *m) { if (!m->valid) return -1; LeaveCriticalSection(&m->cs); return 0; }

/* MBEDTLS_ENTROPY_HARDWARE_ALT: сильный источник для всех контекстов энтропии, включая PSA. */
int mbedtls_hardware_poll(void *data, unsigned char *out, size_t len, size_t *olen)
{
    (void)data;
    if (plat_random(out, len) != 0) return -1;
    *olen = len;
    return 0;
}
#endif

/* ---------------------------------------------------------------- ввод-вывод для mbedTLS */

static int bio_send(void *ctx, const unsigned char *buf, size_t len)
{
    sock_t s = *(sock_t *)ctx;
    int n = send(s, (const char *)buf, (int)len, 0);
    return n < 0 ? MBEDTLS_ERR_SSL_INTERNAL_ERROR : n;
}

static int bio_recv_timeout(void *ctx, unsigned char *buf, size_t len, uint32_t timeout)
{
    sock_t s = *(sock_t *)ctx;
    int n;
    if (timeout) {
        int r = net_wait2(s, SOCK_INVALID, (int)timeout);
        if (r == 0) return MBEDTLS_ERR_SSL_TIMEOUT;
        if (r < 0) return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
    n = recv(s, (char *)buf, (int)len, 0);
    if (n < 0) return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    return n; /* 0 — сервер закрыл */
}

/* ---------------------------------------------------------------- инициализация */

static int conf_setup(mbedtls_ssl_config *c, int verify)
{
    int r = mbedtls_ssl_config_defaults(c, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (r) return r;
    mbedtls_ssl_conf_rng(c, mbedtls_ctr_drbg_random, &g_drbg);
    mbedtls_ssl_conf_min_tls_version(c, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_max_tls_version(c, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_read_timeout(c, 15000);
    if (verify) {
        mbedtls_ssl_conf_authmode(c, MBEDTLS_SSL_VERIFY_REQUIRED);
        mbedtls_ssl_conf_ca_chain(c, &g_ca, NULL);
    } else {
        mbedtls_ssl_conf_authmode(c, MBEDTLS_SSL_VERIFY_NONE);
    }
    return 0;
}

int tun_global_init(const char *ca_pem)
{
    static const char pers[] = "happd";
    static int done;
    int r;
    if (done) return 0;
    done = 1;
#ifdef _WIN32_WCE
    mbedtls_threading_set_alt(mx_init, mx_free, mx_lock, mx_unlock);
#endif
    if (psa_crypto_init() != PSA_SUCCESS) {
        plat_log("psa_crypto_init: ошибка");
        return -1;
    }
    mbedtls_entropy_init(&g_entropy);
    mbedtls_ctr_drbg_init(&g_drbg);
    r = mbedtls_ctr_drbg_seed(&g_drbg, mbedtls_entropy_func, &g_entropy, (const unsigned char *)pers, sizeof(pers) - 1);
    if (r) {
        plat_log("ctr_drbg_seed: -0x%04x", -r);
        return -1;
    }
    mbedtls_x509_crt_init(&g_ca);
    if (ca_pem) {
        r = mbedtls_x509_crt_parse_file(&g_ca, ca_pem);
        if (r < 0) plat_log("корневые сертификаты %s: -0x%04x", ca_pem, -r);
        else { g_have_ca = 1; if (r > 0) plat_log("корневых сертификатов не разобрано: %d", r); }
    }
    mbedtls_ssl_config_init(&g_conf_verify);
    mbedtls_ssl_config_init(&g_conf_insecure);
    if (conf_setup(&g_conf_verify, 1) || conf_setup(&g_conf_insecure, 0)) {
        plat_log("ssl_config: ошибка");
        return -1;
    }
    return 0;
}

static void err_text(char *err, size_t errlen, const char *what, int r)
{
    char buf[128];
    if (!err) return;
    mbedtls_strerror(r, buf, sizeof(buf));
    snprintf(err, errlen, "%s: -0x%04x %s", what, (unsigned)-r, buf);
}

/* TCP + TLS до сервера (без заголовка Trojan) — и для туннеля, и для загрузки подписки. */
Tunnel *tun_tls(const Outbound *o, char *err, size_t errlen)
{
    Tunnel *t;
    int r;
    sock_t s = net_connect(o->host, o->port, 8000);
    if (s == SOCK_INVALID) {
        if (err) snprintf(err, errlen, "нет TCP до %s:%d", o->host, o->port);
        return NULL;
    }
    t = (Tunnel *)calloc(1, sizeof(Tunnel));
    if (!t) { net_close(s); return NULL; }
    t->s = s;
    mbedtls_ssl_init(&t->ssl);
    r = mbedtls_ssl_setup(&t->ssl, (o->insecure || !g_have_ca) ? &g_conf_insecure : &g_conf_verify);
    if (!r) r = mbedtls_ssl_set_hostname(&t->ssl, o->sni[0] ? o->sni : o->host);
    if (r) { err_text(err, errlen, "ssl_setup", r); tun_close(t); return NULL; }
    mbedtls_ssl_set_bio(&t->ssl, &t->s, bio_send, NULL, bio_recv_timeout);
    while ((r = mbedtls_ssl_handshake(&t->ssl)) != 0) {
        if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
        if (r == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
            char vb[256];
            mbedtls_x509_crt_verify_info(vb, sizeof(vb), "", mbedtls_ssl_get_verify_result(&t->ssl));
            if (err) snprintf(err, errlen, "сертификат сервера не прошёл проверку: %s", vb);
        } else {
            err_text(err, errlen, "TLS", r);
        }
        tun_close(t);
        return NULL;
    }
    return t;
}

Tunnel *tun_direct(const char *host, int port, char *err, size_t errlen)
{
    Tunnel *t;
    sock_t s = net_connect(host, port, 5000);
    if (s == SOCK_INVALID) {
        if (err) snprintf(err, errlen, "нет связи с %s:%d", host, port);
        return NULL;
    }
    t = (Tunnel *)calloc(1, sizeof(Tunnel));
    if (!t) { net_close(s); return NULL; }
    t->s = s;
    t->plain = 1;
    return t;
}

int tun_write(Tunnel *t, const void *buf, size_t len)
{
    const unsigned char *p = (const unsigned char *)buf;
    if (t->plain) return net_send_all(t->s, buf, len);
    while (len > 0) {
        int n = mbedtls_ssl_write(&t->ssl, p, len);
        if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
        if (n <= 0) return -1;
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

int tun_read(Tunnel *t, void *buf, size_t len)
{
    int n;
    if (t->plain) {
        n = net_recv(t->s, buf, len);
        return n > 0 ? n : n == 0 ? 0 : -1;
    }
    n = mbedtls_ssl_read(&t->ssl, (unsigned char *)buf, len);
    if (n > 0) return n;
    if (n == 0 || n == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) return 0;
    if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE || n == MBEDTLS_ERR_SSL_TIMEOUT
#ifdef MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET
        || n == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET
#endif
        )
        return -2;
    return -1;
}

size_t tun_pending(Tunnel *t)
{
    if (t->plain) return 0;
    return mbedtls_ssl_get_bytes_avail(&t->ssl) + (t->inner ? tun_pending(t->inner) : 0);
}

sock_t tun_sock(Tunnel *t) { return t->inner ? tun_sock(t->inner) : t->s; }

void tun_close(Tunnel *t)
{
    if (!t) return;
    if (!t->plain) {
        mbedtls_ssl_close_notify(&t->ssl);
        mbedtls_ssl_free(&t->ssl);
    }
    if (t->inner) tun_close(t->inner);
    else net_close(t->s);
    free(t);
}

/* ---------------------------------------------------------------- TLS поверх туннеля */

static int layer_send(void *ctx, const unsigned char *buf, size_t len)
{
    return tun_write((Tunnel *)ctx, buf, len) == 0 ? (int)len : MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}

static int layer_recv_timeout(void *ctx, unsigned char *buf, size_t len, uint32_t timeout)
{
    Tunnel *in = (Tunnel *)ctx;
    int n;
    if (tun_pending(in) == 0) {
        int r = net_wait2(tun_sock(in), SOCK_INVALID, timeout ? (int)timeout : 30000);
        if (r == 0) return MBEDTLS_ERR_SSL_TIMEOUT;
        if (r < 0) return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
    n = tun_read(in, buf, len);
    if (n == -2) return MBEDTLS_ERR_SSL_WANT_READ;
    if (n < 0) return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    return n;
}

Tunnel *tun_tls_over(Tunnel *inner, const char *sni, char *err, size_t errlen)
{
    Tunnel *t = (Tunnel *)calloc(1, sizeof(Tunnel));
    int r;
    if (!t) return NULL;
    t->s = SOCK_INVALID;
    t->inner = inner;
    mbedtls_ssl_init(&t->ssl);
    r = mbedtls_ssl_setup(&t->ssl, g_have_ca ? &g_conf_verify : &g_conf_insecure);
    if (!r) r = mbedtls_ssl_set_hostname(&t->ssl, sni);
    if (r) { err_text(err, errlen, "ssl_setup", r); t->inner = NULL; tun_close(t); return NULL; }
    mbedtls_ssl_set_bio(&t->ssl, inner, layer_send, NULL, layer_recv_timeout);
    while ((r = mbedtls_ssl_handshake(&t->ssl)) != 0) {
        if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
        if (r == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
            char vb[256];
            mbedtls_x509_crt_verify_info(vb, sizeof(vb), "", mbedtls_ssl_get_verify_result(&t->ssl));
            if (err) snprintf(err, errlen, "сертификат %s не прошёл проверку: %s", sni, vb);
        } else {
            err_text(err, errlen, "TLS к сайту", r);
        }
        t->inner = NULL; /* внутренний туннель закрывает вызывающий */
        tun_close(t);
        return NULL;
    }
    return t;
}

void *tun_drbg(void) { return &g_drbg; }

/* ---------------------------------------------------------------- Trojan */

static void trojan_key(const char *password, char out[57])
{
    unsigned char h[32];
    static const char hex[] = "0123456789abcdef";
    int i;
    mbedtls_sha256((const unsigned char *)password, strlen(password), h, 1 /* SHA-224 */);
    for (i = 0; i < 28; i++) {
        out[i * 2] = hex[h[i] >> 4];
        out[i * 2 + 1] = hex[h[i] & 15];
    }
    out[56] = 0;
}

Tunnel *tun_open(const Outbound *o, const char *dhost, int dport, char *err, size_t errlen)
{
    unsigned char req[56 + 2 + 1 + 1 + 1 + 255 + 2 + 2];
    size_t n = 0, hl = strlen(dhost);
    unsigned a, b, c, d;
    char key[57];
    Tunnel *t;

    if (hl > 255) { if (err) snprintf(err, errlen, "длинное имя"); return NULL; }
    t = tun_tls(o, err, errlen);
    if (!t) return NULL;

    trojan_key(o->password, key);
    memcpy(req, key, 56); n = 56;
    req[n++] = '\r'; req[n++] = '\n';
    req[n++] = 0x01; /* CONNECT */
    if (sscanf(dhost, "%u.%u.%u.%u", &a, &b, &c, &d) == 4 && a < 256 && b < 256 && c < 256 && d < 256) {
        req[n++] = 0x01;
        req[n++] = (unsigned char)a; req[n++] = (unsigned char)b; req[n++] = (unsigned char)c; req[n++] = (unsigned char)d;
    } else {
        req[n++] = 0x03;
        req[n++] = (unsigned char)hl;
        memcpy(req + n, dhost, hl); n += hl;
    }
    req[n++] = (unsigned char)(dport >> 8);
    req[n++] = (unsigned char)dport;
    req[n++] = '\r'; req[n++] = '\n';
    if (tun_write(t, req, n) != 0) {
        if (err) snprintf(err, errlen, "не отправился заголовок Trojan");
        tun_close(t);
        return NULL;
    }
    return t;
}

int tun_ping(const Outbound *o, char *err, size_t errlen)
{
    unsigned long t0 = plat_ms();
    Tunnel *t = tun_tls(o, err, errlen);
    int ms = (int)(plat_ms() - t0);
    if (!t) return -1;
    tun_close(t);
    return ms;
}
