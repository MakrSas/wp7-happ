#ifndef HAPP_WIFIPROXY_H
#define HAPP_WIFIPROXY_H

/* Запомнить записи прокси Wi-Fi, указывающие на наш порт. Возвращает число сетей. */
int wifiproxy_learn(int port);
/* on = 1: восстановить записи с адресом ip; on = 0: удалить. Возвращает число затронутых сетей. */
int wifiproxy_apply(int on, const char *ip, int port);

#endif
