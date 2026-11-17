#define _GNU_SOURCE
#include "protocol.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

int hp_valid_utf8(const unsigned char *p, size_t n) {
  for (size_t i = 0; i < n;) {
    unsigned char c = p[i++];
    if (c < 0x80) continue;
    int count = c >= 0xc2 && c <= 0xdf ? 1 : c >= 0xe0 && c <= 0xef ? 2 : c >= 0xf0 && c <= 0xf4 ? 3 : -1;
    if (count < 0 || i + (size_t)count > n) return 0;
    unsigned char first = p[i];
    if ((c == 0xe0 && first < 0xa0) || (c == 0xed && first >= 0xa0) ||
        (c == 0xf0 && first < 0x90) || (c == 0xf4 && first >= 0x90)) return 0;
    for (int j = 0; j < count; j++) if ((p[i++] & 0xc0) != 0x80) return 0;
  }
  return 1;
}

void hp_json_escaped(FILE *out, const unsigned char *s, size_t n) {
  size_t start = 0;
  for (size_t i = 0; i < n; i++) {
    unsigned char c = s[i];
    if (c >= 32 && c != '"' && c != '\\') continue;
    if (i > start) fwrite(s + start, 1, i - start, out);
    if (c < 32) fprintf(out, "\\u%04x", c);
    else { fputc('\\', out); fputc(c, out); }
    start = i + 1;
  }
  if (n > start) fwrite(s + start, 1, n - start, out);
}

void hp_json_string(FILE *out, const unsigned char *s, size_t n) {
  fputc('"', out);
  hp_json_escaped(out, s, n);
  fputc('"', out);
}

void hp_json_base64(FILE *out, const unsigned char *data, size_t n) {
  unsigned char encoded[4097];
  fputc('"', out);
  while (n) {
    size_t count = n > 3072 ? 3072 : n;
    int size = EVP_EncodeBlock(encoded, data, (int)count);
    fwrite(encoded, 1, (size_t)size, out);
    data += count; n -= count;
  }
  fputc('"', out);
  explicit_bzero(encoded, sizeof(encoded));
}

int hp_report_id(char out[65]) {
  static const char hex[] = "0123456789abcdef";
  unsigned char bytes[32];
  if (RAND_bytes(bytes, sizeof(bytes)) != 1) {
    explicit_bzero(bytes, sizeof(bytes)); explicit_bzero(out, 65); return -1;
  }
  for (size_t i = 0; i < sizeof(bytes); i++) {
    out[i * 2] = hex[bytes[i] >> 4];
    out[i * 2 + 1] = hex[bytes[i] & 15];
  }
  out[64] = 0;
  explicit_bzero(bytes, sizeof(bytes));
  return 0;
}

int hp_utc_time(char out[32]) {
  time_t now = time(NULL);
  struct tm tm;
  if (now == (time_t)-1 || !gmtime_r(&now, &tm) || !strftime(out, 32, "%Y-%m-%dT%H:%M:%SZ", &tm)) return -1;
  return 0;
}
