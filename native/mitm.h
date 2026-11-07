#ifndef HAPP_MITM_H
#define HAPP_MITM_H

#include "tunnel.h"

/*
 * Обслужить HTTPS-соединение IE через перехват. c — сокет IE (CONNECT уже отвечен),
 * t — открытый туннель до host:443 (переходит во владение функции), hello — ClientHello, уже прочитанный из c.
 */
int mitm_run(sock_t c, Tunnel *t, const char *host, const unsigned char *hello, size_t hello_len, char *err, size_t errlen);

#endif
