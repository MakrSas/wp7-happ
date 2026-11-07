/*
 * «Современный HTTPS» для IE9: IE умеет только TLS 1.0 и не знает новых корневых центров.
 *
 *   IE ──TLS 1.0 (BearSSL, сертификат от корня Happ)──▶ happd ──TLS 1.2/1.3 (mbedTLS, настоящая проверка)──▶ сайт
 *                                                          (всё это внутри туннеля Trojan)
 *
 * Расшифрованный трафик никуда не пишется и не сохраняется: только перекладывается между двумя TLS.
 */
#include "mitm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bearssl.h"
#include "ca.h"
#ifndef _WIN32_WCE
#include <sys/select.h>
#include <sys/socket.h>
#endif

#define IDLE_MS (5 * 60 * 1000)

/* Ждать данных от IE (если want_ie) и/или от сайта (если want_up). Маска 1 — IE, 2 — сайт. */
static int wait_any(sock_t ie, int want_ie, Tunnel *up, int want_up, int ms)
{
    fd_set rf;
    struct timeval tv;
    sock_t us = tun_sock(up);
    int maxfd = -1, r, m = 0;
    if (want_up && tun_pending(up) > 0) return 2;
    FD_ZERO(&rf);
    if (want_ie) { FD_SET(ie, &rf); maxfd = (int)ie; }
    if (want_up) { FD_SET(us, &rf); if ((int)us > maxfd) maxfd = (int)us; }
    if (maxfd < 0) return 0;
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    r = select(maxfd + 1, &rf, NULL, NULL, &tv);
    if (r < 0) return -1;
    if (want_ie && FD_ISSET(ie, &rf)) m |= 1;
    if (want_up && FD_ISSET(us, &rf)) m |= 2;
    return m;
}

/* Страница ошибки в IE: когда до сайта не достучаться, показываем причину, а не пустоту. */
static void error_page(char *out, size_t cap, const char *host, const char *err)
{
    char body[900];
    int bl = snprintf(body, sizeof(body),
        "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"></head>"
        "<body style=\"font-family:'Segoe WP',sans-serif;margin:24px\"><div style=\"font-size:14px\">HAPP</div>"
        "<div style=\"font-size:48px;font-weight:200\">не удалось</div><p>%s</p><p style=\"color:#888\">%s</p></body></html>",
        host, err);
    snprintf(out, cap, "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\n"
             "Connection: close\r\n\r\n%s", bl, body);
}

int mitm_run(sock_t c, Tunnel *t, const char *host, const unsigned char *hello, size_t hello_len, char *err, size_t errlen)
{
    br_ssl_server_context sc;
    br_x509_certificate chain[2];
    unsigned char *iobuf, seed[32];
    const unsigned char *leaf, *root;
    size_t leaf_len, root_len, fed = 0;
    unsigned char *leaf_copy;
    Tunnel *up;
    char uerr[256] = "";
    unsigned long last = plat_ms();
    int failed_page = 0, result = 0;

    leaf = ca_leaf_der(host, &leaf_len);
    root = ca_root_der(&root_len);
    if (!leaf || !root) { snprintf(err, errlen, "нет сертификата для %s", host); return -1; }
    leaf_copy = (unsigned char *)malloc(leaf_len);
    iobuf = (unsigned char *)malloc(BR_SSL_BUFSIZE_BIDI);
    if (!leaf_copy || !iobuf) { free(leaf_copy); free(iobuf); return -1; }
    memcpy(leaf_copy, leaf, leaf_len);
    chain[0].data = leaf_copy; chain[0].data_len = leaf_len;
    chain[1].data = (unsigned char *)root; chain[1].data_len = root_len;

    /* Сначала настоящий TLS к сайту: если он не получится, IE покажем страницу с причиной. */
    up = tun_tls_over(t, host, uerr, sizeof(uerr));
    if (!up) {
        plat_log("https %s: %s", host, uerr);
        failed_page = 1;
    }

    br_ssl_server_init_full_rsa(&sc, chain, 2, (const br_rsa_private_key *)ca_br_key());
    br_ssl_engine_set_versions(&sc.eng, BR_TLS10, BR_TLS12);
    br_ssl_engine_set_buffer(&sc.eng, iobuf, BR_SSL_BUFSIZE_BIDI, 1);
    plat_random(seed, sizeof(seed));
    br_ssl_engine_inject_entropy(&sc.eng, seed, sizeof(seed));
    br_ssl_server_reset(&sc);

    for (;;) {
        unsigned st = br_ssl_engine_current_state(&sc.eng);
        unsigned char *b;
        size_t len;
        int n, m;

        if (st & BR_SSL_CLOSED) break;
        if (st & BR_SSL_SENDREC) {
            b = br_ssl_engine_sendrec_buf(&sc.eng, &len);
            n = send(c, (const char *)b, (int)len, 0);
            if (n <= 0) break;
            br_ssl_engine_sendrec_ack(&sc.eng, (size_t)n);
            plat_add64(&g_bytes_down, n);
            continue;
        }
        /* ClientHello, который прокси уже прочитал из сокета, отдаём движку первым. */
        if (fed < hello_len && (st & BR_SSL_RECVREC)) {
            b = br_ssl_engine_recvrec_buf(&sc.eng, &len);
            if (len > hello_len - fed) len = hello_len - fed;
            memcpy(b, hello + fed, len);
            br_ssl_engine_recvrec_ack(&sc.eng, len);
            fed += len;
            continue;
        }
        if (st & BR_SSL_RECVAPP) {
            b = br_ssl_engine_recvapp_buf(&sc.eng, &len);
            if (failed_page) {
                /* Запрос IE получен — отвечаем страницей ошибки и закрываемся. */
                char page[1400];
                br_ssl_engine_recvapp_ack(&sc.eng, len);
                if (failed_page == 1 && (st & BR_SSL_SENDAPP)) {
                    size_t pl, cap;
                    error_page(page, sizeof(page), host, uerr);
                    pl = strlen(page);
                    b = br_ssl_engine_sendapp_buf(&sc.eng, &cap);
                    if (pl > cap) pl = cap;
                    memcpy(b, page, pl);
                    br_ssl_engine_sendapp_ack(&sc.eng, pl);
                    br_ssl_engine_flush(&sc.eng, 0);
                    br_ssl_engine_close(&sc.eng);
                    failed_page = 2;
                }
                continue;
            }
            if (tun_write(up, b, len) != 0) break;
            br_ssl_engine_recvapp_ack(&sc.eng, len);
            plat_add64(&g_bytes_up, (long long)len);
            last = plat_ms();
            continue;
        }

        m = wait_any(c, (st & BR_SSL_RECVREC) != 0, up, up && (st & BR_SSL_SENDAPP) != 0, 1000);
        if (m < 0) break;
        if (m == 0) {
            if (plat_ms() - last > IDLE_MS) break;
            continue;
        }
        last = plat_ms();
        if (m & 1) {
            b = br_ssl_engine_recvrec_buf(&sc.eng, &len);
            n = recv(c, (char *)b, (int)len, 0);
            if (n <= 0) break;
            br_ssl_engine_recvrec_ack(&sc.eng, (size_t)n);
        }
        if ((m & 2) && up) {
            st = br_ssl_engine_current_state(&sc.eng);
            if (!(st & BR_SSL_SENDAPP)) continue;
            b = br_ssl_engine_sendapp_buf(&sc.eng, &len);
            n = tun_read(up, b, len);
            if (n == -2) continue;
            if (n <= 0) { br_ssl_engine_close(&sc.eng); continue; }
            br_ssl_engine_sendapp_ack(&sc.eng, (size_t)n);
            br_ssl_engine_flush(&sc.eng, 0);
        }
    }

    {
        int e = br_ssl_engine_last_error(&sc.eng);
        if (e && e != BR_ERR_IO) {
            snprintf(err, errlen, "TLS с IE: ошибка BearSSL %d", e);
            plat_log("https %s: TLS с IE, ошибка BearSSL %d", host, e);
            result = -1;
        }
    }
    if (up) tun_close(up); /* закрывает и внутренний туннель */
    else tun_close(t);
    free(iobuf);
    free(leaf_copy);
    return result;
}
