#pragma once
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

void hp_json_string(FILE *out, const unsigned char *data, size_t size);
void hp_json_escaped(FILE *out, const unsigned char *data, size_t size);
void hp_json_base64(FILE *out, const unsigned char *data, size_t size);
int hp_valid_utf8(const unsigned char *data, size_t size);
int hp_report_id(char id[65]);
int hp_utc_time(char out[32]);
