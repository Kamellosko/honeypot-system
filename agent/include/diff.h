#pragma once
#include <stdio.h>

/* Appends JSON format/diff fields: 0 = diff, 1 = use blocks, -1 = I/O/allocation error. */
int hp_write_text_diff(FILE *out, int old_fd, int new_fd);
