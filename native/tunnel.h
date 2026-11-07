#ifndef HAPP_TUNNEL_H
#define HAPP_TUNNEL_H

#include "plat.h"

#define OUT_TROJAN 1

/* Куда и как выходить в интернет. */
typedef struct {
    int type;
    char host[256];
    int port;
    char password[128];
    char sni[256];
    int insecure;   /* не проверять сертификат сервера */
} Outbound;

typedef struct Tunnel Tunnel;

/* ca_pem — файл с корневыми сертификатами (может быть NULL: тогда только insecure). */
int     tun_global_init(const char *ca_pem);
/* Только TLS до o->host:o->port (SNI из o->sni). */
Tunnel *tun_tls(const Outbound *o, char *err, size_t errlen);
/* Обычное TCP-соединение без шифрования — для адресов локальной сети. */
Tunnel *tun_direct(const char *host, int port, char *err, size_t errlen);
Tunnel *tun_open(const Outbound *o, const char *dhost, int dport, char *err, size_t errlen);
int     tun_write(Tunnel *t, const void *buf, size_t len);   /* 0 — успех */
int     tun_read(Tunnel *t, void *buf, size_t len);          /* >0 байт, 0 закрыто, -2 «ещё нет», <0 ошибка */
size_t  tun_pending(Tunnel *t);                               /* уже расшифровано и ждёт чтения */
sock_t  tun_sock(Tunnel *t);
void    tun_close(Tunnel *t);

/*
 * TLS 1.2/1.3 к сайту sni поверх уже открытого туннеля inner (с проверкой сертификата).
 * При успехе inner принадлежит новому туннелю; при ошибке остаётся у вызывающего.
 */
Tunnel *tun_tls_over(Tunnel *inner, const char *sni, char *err, size_t errlen);
/* ГСЧ mbedTLS (mbedtls_ctr_drbg_context *) — для выпуска сертификатов. */
void *tun_drbg(void);

/* Задержка до сервера: TCP + TLS-рукопожатие, мс; <0 — ошибка. */
int tun_ping(const Outbound *o, char *err, size_t errlen);

#endif
