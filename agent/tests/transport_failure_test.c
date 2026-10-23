#define _GNU_SOURCE
#include "port.h"
#include "snapshot.h"
#include <assert.h>
#include <curl/curl.h>
#include <stdarg.h>
#include <stdlib.h>

static int setup_failure = 1, network_failure, acknowledged = 1;
static size_t (*reader)(char *, size_t, size_t, void *);
static void *input;

CURLcode __wrap_curl_easy_setopt(CURL *curl, CURLoption option, ...) {
  assert(curl);
  va_list args;
  va_start(args, option);
  if (option == CURLOPT_READFUNCTION) reader = va_arg(args, size_t (*)(char *, size_t, size_t, void *));
  else if (option == CURLOPT_READDATA) input = va_arg(args, void *);
  else if (option == CURLOPT_SSL_VERIFYPEER) assert(va_arg(args, long) == 1L);
  else if (option == CURLOPT_SSL_VERIFYHOST) assert(va_arg(args, long) == 2L);
  va_end(args);
  return setup_failure && option == CURLOPT_SSL_VERIFYPEER ? CURLE_UNKNOWN_OPTION : CURLE_OK;
}
CURLcode __wrap_curl_easy_perform(CURL *curl) {
  assert(curl && !setup_failure && reader && input);
  if (network_failure) return CURLE_COULDNT_CONNECT;
  char buffer[64];
  size_t size = 0, n;
  while ((n = reader(buffer, 1, sizeof(buffer), input))) { assert(n <= sizeof(buffer)); size += n; }
  assert(size > 100);
  return CURLE_OK;
}
CURLcode __wrap_curl_easy_getinfo(CURL *curl, CURLINFO option, ...) {
  assert(curl && option == CURLINFO_RESPONSE_CODE);
  va_list args;
  va_start(args, option);
  *va_arg(args, long *) = acknowledged ? 204 : 503;
  va_end(args);
  return CURLE_OK;
}

int main(void) {
  char directory[] = "/tmp/hp-transport-fault-XXXXXX";
  struct hp_store store;
  assert(mkdtemp(directory) && !hp_store_init(&store, directory, "test"));
  assert(!hp_report_simple(&store, "system", "test", "", NULL, NULL, 0));
  assert(hp_send_pending(&store, "127.0.0.1", 443) == -1 && hp_store_pending_count(&store) == 1);
  setup_failure = 0; network_failure = 1;
  assert(!hp_send_pending(&store, "127.0.0.1", 443) && hp_store_pending_count(&store) == 1);
  network_failure = 0; acknowledged = 0;
  assert(!hp_send_pending(&store, "127.0.0.1", 443) && hp_store_pending_count(&store) == 1);
  acknowledged = 1;
  assert(hp_send_pending(&store, "127.0.0.1", 443) == 1 && hp_store_pending_count(&store) == 0);
  hp_store_close(&store);
  return 0;
}
