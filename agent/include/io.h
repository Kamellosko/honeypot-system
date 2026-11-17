#pragma once
#include <stddef.h>
#include <sys/types.h>

int hp_open_beneath(int root, const char *path, int flags, mode_t mode);
int hp_open_absolute(const char *path, int flags);
int hp_private_file(int root, const char *path, int flags, mode_t mode);
int hp_private_directory(int root, const char *name);
int hp_write_all(int fd, const void *data, size_t size);
int hp_sync(int fd);
int hp_read_file(const char *path, size_t limit, char **data, size_t *size);
