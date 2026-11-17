#pragma once
struct hp_store;
int hp_send_pending(struct hp_store *store, const char *ip, unsigned short port);
