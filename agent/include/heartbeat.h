#pragma once
struct hp_store;

/* now and deadline use CLOCK_MONOTONIC seconds; zero initializes the timer. */
int hp_heartbeat_tick(struct hp_store *store, double now, double *deadline);
