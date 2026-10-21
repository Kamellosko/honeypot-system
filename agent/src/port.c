#define _GNU_SOURCE
#include "port.h"
#include "snapshot.h"
#include "io.h"
#include <curl/curl.h>
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static size_t discard_response(char *data, size_t size, size_t count, void *context) {
  (void)data; (void)context;
  return size && count > SIZE_MAX / size ? 0 : size * count;
}

static size_t read_report(char *data, size_t size, size_t count, void *context) {
  if (size && count > SIZE_MAX / size) return CURL_READFUNC_ABORT;
  FILE *input = context;
  size_t n = fread(data, 1, size * count, input);
  return ferror(input) ? CURL_READFUNC_ABORT : n;
}

int hp_send_pending(struct hp_store *store, const char *ip, unsigned short port) {
  int fd = openat(store->pending_fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (fd < 0) return -1;
  DIR *dir = fdopendir(fd);
  if (!dir) { close(fd); return -1; }
  int delivered = 0;
  for (;;) {
    errno = 0;
    struct dirent *ent = readdir(dir);
    if (!ent) { if (errno) delivered = -1; break; }
    size_t name_len = strlen(ent->d_name);
    if (name_len != 69 || strcmp(ent->d_name + 64, ".json") || strspn(ent->d_name, "0123456789abcdef") != 64) continue;
    int report_fd = hp_private_file(store->pending_fd, ent->d_name, O_RDONLY, 0);
    if (report_fd < 0) { if (errno == ENOENT) continue; delivered = -1; break; }
    struct stat st;
    if (fstat(report_fd, &st) || st.st_size < 0) { close(report_fd); delivered = -1; break; }
    FILE *input = fdopen(report_fd, "r");
    if (!input) { close(report_fd); delivered = -1; break; }
    char input_buffer[BUFSIZ], url[128];
    CURL *curl = NULL;
    struct curl_slist *headers = NULL;
    int acknowledged = 0;
    int n = snprintf(url, sizeof(url), strchr(ip, ':') ? "https://[%s]:%hu/events" : "https://%s:%hu/events", ip, port);
    if (n < 0 || n >= (int)sizeof(url) || setvbuf(input, input_buffer, _IOFBF, sizeof(input_buffer))) {
      delivered = -1; goto cleanup;
    }
    curl = curl_easy_init();
    if (!curl) { delivered = -1; goto cleanup; }
    headers = curl_slist_append(NULL, "Content-Type: application/json");
    if (!headers ||
        curl_easy_setopt(curl, CURLOPT_URL, url) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POST, 1L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_report) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_READDATA, input) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)st.st_size) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_PROXY, "") != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discard_response) != CURLE_OK) {
      delivered = -1; goto cleanup;
    }
    long status = 0;
    CURLcode result = curl_easy_perform(curl);
    if (result == CURLE_OK && curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status) == CURLE_OK)
      acknowledged = status >= 200 && status < 300;
cleanup:
    curl_slist_free_all(headers);
    if (curl) curl_easy_cleanup(curl);
    if (fclose(input)) { acknowledged = 0; delivered = -1; }
    explicit_bzero(input_buffer, sizeof(input_buffer));
    explicit_bzero(url, sizeof(url));
    if (acknowledged) {
      if (unlinkat(store->pending_fd, ent->d_name, 0) || hp_sync(store->pending_fd)) delivered = -1;
      else delivered = 1;
    }
    break;
  }
  if (closedir(dir)) return -1;
  return delivered;
}
