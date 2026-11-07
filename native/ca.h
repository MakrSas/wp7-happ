#ifndef HAPP_CA_H
#define HAPP_CA_H

#include <stddef.h>

/*
 * Корневой сертификат Happ для перехвата HTTPS от IE9.
 * Ключ RSA-2048 создаётся на телефоне один раз (это долго — в фоне), хранится локально и никуда не уходит.
 * Тем же ключом подписаны и сертификаты сайтов.
 */

/* Загрузить или создать ключ и корневой сертификат. Медленно при первом запуске. 0 — готово. */
int  ca_init(void);
int  ca_ready(void);
/* Корневой сертификат (DER) — его ставят на телефон. */
const unsigned char *ca_root_der(size_t *len);
/* Сертификат для host (DER), из кеша или выпущенный сейчас. NULL при ошибке. */
const unsigned char *ca_leaf_der(const char *host, size_t *len);
/* Закрытый ключ в виде для BearSSL (br_rsa_private_key *). */
const void *ca_br_key(void);

/* Хранилище: реестр на WinCE, файлы в ~/.happtest на Linux. */
int ca_store_load(const char *name, unsigned char *buf, size_t cap, size_t *len);
int ca_store_save(const char *name, const unsigned char *buf, size_t len);

#endif
