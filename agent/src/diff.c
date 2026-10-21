#define _GNU_SOURCE
#include "diff.h"
#include "protocol.h"
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define HP_TEXT_LIMIT 1048576
#define HP_LCS_CELLS 1048576

struct text {
  unsigned char *bytes;
  uint32_t *offsets;
  size_t size, lines;
};

static void release(struct text *text) {
  if (text->bytes) explicit_bzero(text->bytes, text->size);
  free(text->bytes); free(text->offsets);
}

static int load_text(int fd, struct text *text) {
  if (fd < 0) return 0;
  struct stat st;
  if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 0) return -1;
  if (st.st_size > HP_TEXT_LIMIT) return 1;
  text->size = (size_t)st.st_size;
  text->bytes = malloc(text->size ? text->size : 1);
  if (!text->bytes) return -1;
  size_t used = 0;
  while (used < text->size) {
    ssize_t n = pread(fd, text->bytes + used, text->size - used, (off_t)used);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) return -1;
    used += (size_t)n;
  }
  if (memchr(text->bytes, 0, text->size) || !hp_valid_utf8(text->bytes, text->size)) return 1;
  for (size_t i = 0; i < text->size; i++) if (text->bytes[i] == '\n') text->lines++;
  if (text->size && text->bytes[text->size - 1] != '\n') text->lines++;
  text->offsets = malloc((text->lines + 1) * sizeof(*text->offsets));
  if (!text->offsets) return -1;
  size_t line = 0;
  text->offsets[line++] = 0;
  for (size_t i = 0; i < text->size; i++)
    if (text->bytes[i] == '\n' && line <= text->lines) text->offsets[line++] = (uint32_t)i + 1;
  text->offsets[text->lines] = (uint32_t)text->size;
  return 0;
}

static int equal_line(const struct text *a, size_t i, const struct text *b, size_t j) {
  size_t an = a->offsets[i + 1] - a->offsets[i], bn = b->offsets[j + 1] - b->offsets[j];
  return an == bn && !memcmp(a->bytes + a->offsets[i], b->bytes + b->offsets[j], an);
}

static void escaped(FILE *out, const char *text) {
  hp_json_escaped(out, (const unsigned char *)text, strlen(text));
}

static void emit_line(FILE *out, const struct text *text, size_t line, char operation) {
  fputc(operation, out);
  size_t start = text->offsets[line], size = text->offsets[line + 1] - start;
  hp_json_escaped(out, text->bytes + start, size);
  if (text->bytes[start + size - 1] != '\n') escaped(out, "\n\\ No newline at end of file\n");
}

int hp_write_text_diff(FILE *out, int old_fd, int new_fd) {
  struct text a = {0}, b = {0};
  char *ops = NULL;
  uint32_t *matrix = NULL;
  int result = load_text(old_fd, &a);
  if (result) goto done;
  result = load_text(new_fd, &b);
  if (result) goto done;
  result = -1;
  ops = malloc(a.lines + b.lines + 1);
  if (!ops) goto done;
  size_t prefix = 0, suffix = 0, count = 0;
  while (prefix < a.lines && prefix < b.lines && equal_line(&a, prefix, &b, prefix)) prefix++;
  while (suffix < a.lines - prefix && suffix < b.lines - prefix &&
         equal_line(&a, a.lines - suffix - 1, &b, b.lines - suffix - 1)) suffix++;
  memset(ops, ' ', prefix); count = prefix;
  size_t n = a.lines - prefix - suffix, m = b.lines - prefix - suffix;
  size_t columns = m + 1;
  if (n && m && n + 1 <= HP_LCS_CELLS / columns) {
    matrix = calloc((n + 1) * columns, sizeof(*matrix));
    if (!matrix) goto done;
    for (size_t i = n; i-- > 0;) for (size_t j = m; j-- > 0;) {
      uint32_t down = matrix[(i + 1) * columns + j], right = matrix[i * columns + j + 1];
      matrix[i * columns + j] = equal_line(&a, prefix + i, &b, prefix + j)
        ? 1 + matrix[(i + 1) * columns + j + 1] : down > right ? down : right;
    }
    size_t i = 0, j = 0;
    while (i < n || j < m) {
      if (i < n && j < m && equal_line(&a, prefix + i, &b, prefix + j)) { ops[count++] = ' '; i++; j++; }
      else if (i < n && (j == m || matrix[(i + 1) * columns + j] >= matrix[i * columns + j + 1])) {
        ops[count++] = '-'; i++;
      } else { ops[count++] = '+'; j++; }
    }
  } else {
    /* shortcut: bound quadratic LCS work; large edits use a complete replacement hunk. */
    memset(ops + count, '-', n); count += n;
    memset(ops + count, '+', m); count += m;
  }
  memset(ops + count, ' ', suffix); count += suffix;
  fputs(",\"format\":\"unified\",\"diff\":\"", out);
  int header_written = 0;
  size_t p = 0, old_line = 0, new_line = 0;
  while (p < count) {
    size_t changed = p;
    while (changed < count && ops[changed] == ' ') changed++;
    if (changed == count) break;
    if (!header_written) { escaped(out, "--- old\n+++ new\n"); header_written = 1; }
    size_t start = changed > p + 3 ? changed - 3 : p;
    for (; p < start; p++) { if (ops[p] != '+') old_line++; if (ops[p] != '-') new_line++; }
    size_t end = changed + 1;
    for (;;) {
      size_t next = end;
      while (next < count && ops[next] == ' ') next++;
      if (next < count && next - end <= 6) { end = next + 1; continue; }
      end = count - end > 3 ? end + 3 : count;
      break;
    }
    size_t old_count = 0, new_count = 0;
    for (size_t i = start; i < end; i++) { old_count += ops[i] != '+'; new_count += ops[i] != '-'; }
    char header[128];
    snprintf(header, sizeof(header), "@@ -%zu,%zu +%zu,%zu @@\n", old_line + !!old_count, old_count, new_line + !!new_count, new_count);
    escaped(out, header);
    for (; p < end; p++) {
      if (ops[p] == '+') emit_line(out, &b, new_line, '+');
      else emit_line(out, &a, old_line, ops[p]);
      if (ops[p] != '+') old_line++;
      if (ops[p] != '-') new_line++;
    }
  }
  fputc('"', out);
  result = ferror(out) ? -1 : 0;
done:
  release(&a); release(&b); free(ops); free(matrix);
  return result;
}
