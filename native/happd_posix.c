/*
 * happd для Linux/macOS — чтобы проверить ядро с компьютера на настоящем сервере.
 *
 *   happd --server HOST --sport 443 --password P [--sni S] [--insecure] [--ca FILE] [--port 10809]
 *   happd ping --server … — только TLS-рукопожатие и время
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "https.h"
#include "ca.h"
#include "proxy.h"

int main(int argc, char **argv)
{
    Outbound o;
    const char *ca = NULL, *listen_addr = "127.0.0.1";
    int port = 10809, ping = 0, i;
    const char *get = NULL, *headers = "";
    volatile int stop = 0;

    memset(&o, 0, sizeof(o));
    o.type = OUT_TROJAN;
    o.port = 443;
    for (i = 1; i < argc; i++) {
        const char *a = argv[i], *v = i + 1 < argc ? argv[i + 1] : "";
        if (!strcmp(a, "ping")) ping = 1;
        else if (!strcmp(a, "get")) { get = v; i++; }
        else if (!strcmp(a, "--headers")) { headers = v; i++; }
        else if (!strcmp(a, "--server")) { snprintf(o.host, sizeof(o.host), "%s", v); i++; }
        else if (!strcmp(a, "--sport")) { o.port = atoi(v); i++; }
        else if (!strcmp(a, "--password")) { snprintf(o.password, sizeof(o.password), "%s", v); i++; }
        else if (!strcmp(a, "--sni")) { snprintf(o.sni, sizeof(o.sni), "%s", v); i++; }
        else if (!strcmp(a, "--insecure")) o.insecure = 1;
        else if (!strcmp(a, "--no-mitm")) g_mitm = 0;
        else if (!strcmp(a, "--ca")) { ca = v; i++; }
        else if (!strcmp(a, "--port")) { port = atoi(v); i++; }
        else if (!strcmp(a, "--listen")) { listen_addr = v; i++; }
        else { fprintf(stderr, "неизвестный аргумент %s\n", a); return 2; }
    }
    if (plat_init() || tun_global_init(ca)) return 1;
    if (get) {
        char err[256] = "", *body;
        size_t len;
        int st;
        if (https_get(get, headers, &st, &body, &len, err, sizeof(err))) { fprintf(stderr, "ошибка: %s\n", err); return 1; }
        fprintf(stderr, "HTTP %d, %zu байт\n", st, len);
        fwrite(body, 1, len, stdout);
        free(body);
        return 0;
    }
    if (ping) {
        char err[256] = "";
        int ms = tun_ping(&o, err, sizeof(err));
        if (ms < 0) { printf("ошибка: %s\n", err); return 1; }
        printf("TLS до %s:%d — %d мс\n", o.host, o.port, ms);
        return 0;
    }
    proxy_set_outbound(&o);
    if (g_mitm && ca_init() != 0) fprintf(stderr, "корневой сертификат не готов\n");
    return proxy_run(listen_addr, port, &stop) ? 1 : 0;
}
