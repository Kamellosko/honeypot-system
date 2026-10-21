#define _GNU_SOURCE
#include "port.h"
#include "snapshot.h"
#include <curl/curl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

CURL *__real_curl_easy_init(void);

CURL *__wrap_curl_easy_init(void) {
  CURL *curl = __real_curl_easy_init();
  const char *ca = getenv("HP_TEST_CA");
  if (curl && ca && curl_easy_setopt(curl, CURLOPT_CAINFO, ca) != CURLE_OK) {
    curl_easy_cleanup(curl);
    return NULL;
  }
  return curl;
}

int main(int argc, char **argv) {
  if ((argc != 3 && argc != 5) ||
      (argc == 5 && strcmp(argv[1], "send")) ||
      (argc == 3 && strcmp(argv[1], "queue") && strcmp(argv[1], "count"))) {
    fprintf(stderr, "usage: %s queue|count STATE or send STATE IP PORT\n", argv[0]);
    return 2;
  }
  struct hp_store store;
  if (hp_store_init(&store, argv[2], "https-fixture-agent")) {
    perror("hp_store_init");
    return 1;
  }
  int result = -1;
  if (!strcmp(argv[1], "queue")) {
    static const unsigned char content[] = "fixture payload\n";
    result = hp_report_simple(&store, "status", "fixture_event", "/fixture/path",
                              NULL, content, sizeof(content) - 1);
  } else if (!strcmp(argv[1], "count")) {
    result = hp_store_pending_count(&store);
    if (result >= 0) printf("%d\n", result);
  } else {
    char *end;
    errno = 0;
    unsigned long port = strtoul(argv[4], &end, 10);
    if (errno || !argv[4][0] || *end || port == 0 || port > 65535) {
      fprintf(stderr, "invalid port\n");
      hp_store_close(&store);
      return 2;
    }
    result = hp_send_pending(&store, argv[3], (unsigned short)port);
    if (result >= 0) printf("%d\n", result);
  }
  hp_store_close(&store);
  if (result < 0) {
    fprintf(stderr, "%s failed\n", argv[1]);
    return 1;
  }
  return 0;
}
