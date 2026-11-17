#define _GNU_SOURCE
#include "config.h"
#include "connections.h"
#include "snapshot.h"
#include <assert.h>
#include <dirent.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static char state[128];
int hp_agent_main(int argc, char **argv);
int __real_hp_store_init(struct hp_store *store, const char *path, const char *id);
int __wrap_hp_store_init(struct hp_store *store, const char *path, const char *id) {
  assert(!strcmp(path, "/var/lib/sys-auditd"));
  return __real_hp_store_init(store, state, id);
}
int __wrap_hp_discover_sources(struct hp_sources *sources) { (void)sources; return 0; }
int __wrap_hp_connections_poll(struct hp_connections *observer, struct hp_store *store, double now) {
  (void)observer; (void)store; (void)now;
  return 0;
}
int __wrap_hp_send_pending(struct hp_store *store, const char *ip, unsigned short port) {
  (void)store; (void)ip; (void)port;
  return 0; /* Keep test reports local; never contact a collector. */
}

static int pending_count(void) {
  char path[256];
  snprintf(path, sizeof(path), "%s/pending", state);
  DIR *dir = opendir(path);
  if (!dir) return 0;
  int count = 0;
  struct dirent *ent;
  while ((ent = readdir(dir))) if (strstr(ent->d_name, ".json")) count++;
  closedir(dir);
  return count;
}

int main(int argc, char **argv) {
  if (argc == 3 && !strcmp(argv[1], "--child")) {
    snprintf(state, sizeof(state), "%s", argv[2]);
    return hp_agent_main(1, argv);
  }
  for (int test = 0; test < 2; test++) {
    snprintf(state, sizeof(state), "/tmp/hp-lifecycle-XXXXXX");
    assert(mkdtemp(state));
    int output[2];
    assert(!pipe(output));
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
      close(output[0]);
      assert(dup2(output[1], STDOUT_FILENO) >= 0);
      assert(dup2(output[1], STDERR_FILENO) >= 0);
      close(output[1]);
      execl("/proc/self/exe", "lifecycle-agent", "--child", state, (char *)NULL);
      _exit(127);
    }
    close(output[1]);
    int ready = 0;
    for (int i = 0; i < 100; i++) {
      if (pending_count()) { ready = 1; break; }
      usleep(100000);
    }
    if (!ready) { kill(child, SIGKILL); waitpid(child, NULL, 0); }
    assert(ready);
    char path[256], name[128];
    snprintf(path, sizeof(path), "/proc/%ld/comm", (long)child);
    FILE *in = fopen(path, "r");
    assert(in && fgets(name, sizeof(name), in));
    assert(!strcmp(name, "sys-auditd\n"));
    fclose(in);
    snprintf(path, sizeof(path), "/proc/%ld/cmdline", (long)child);
    in = fopen(path, "r");
    assert(in && fread(name, 1, sizeof(name), in) > 10);
    assert(!strcmp(name, "sys-auditd"));
    fclose(in);
    assert(!kill(child, test ? SIGINT : SIGTERM));
    int done = 0, status = 0;
    for (int i = 0; i < 50; i++) {
      if (waitpid(child, &status, WNOHANG) == child) { done = 1; break; }
      usleep(100000);
    }
    if (!done) { kill(child, SIGKILL); waitpid(child, &status, 0); }
    assert(done && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    assert(read(output[0], name, sizeof(name)) == 0);
    close(output[0]);
    assert(pending_count() > 0);
    struct stat st;
    assert(!stat(state, &st) && (st.st_mode & 0777) == 0700);
    snprintf(path, sizeof(path), "%s/pending", state);
    DIR *dir = opendir(path);
    assert(dir);
    struct dirent *ent;
    while ((ent = readdir(dir))) {
      if (ent->d_name[0] == '.') continue;
      char report[512];
      snprintf(report, sizeof(report), "%s/%s", path, ent->d_name);
      assert(!unlink(report));
    }
    closedir(dir);
    assert(!rmdir(path));
    snprintf(path, sizeof(path), "%s/snapshots", state);
    assert(!rmdir(path) && !rmdir(state));
  }
  return 0;
}
