#include "agent.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Global context pointer for signal handling
static AgentContext g_ctx;

// Signal handler setting the shutdown flag
static void handle_signal(int sig) {
  (void)sig;
  g_ctx.stop_requested = 1;
}

int main(int argc, char *argv[]) {
  // Initialize default configuration
  agent_init_context(&g_ctx);

  // Parse CLI arguments (--id <id> --port <port>)
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--id") == 0 && i + 1 < argc) {
      strncpy(g_ctx.config.sensor_id, argv[++i], SENSOR_ID_MAX_LEN - 1);
    } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
      g_ctx.config.port = (uint16_t)atoi(argv[++i]);
    }
  }

  // Register SIGINT (Ctrl+C) and SIGTERM handlers
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handle_signal;
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);

  // Create and bind TCP socket
  if (!agent_init_socket(&g_ctx)) {
    agent_cleanup(&g_ctx);
    return 1;
  }

  agent_set_state(&g_ctx, STATE_IDLE_LISTEN);

  // Main state machine loop
  while (g_ctx.state != STATE_SHUTDOWN && g_ctx.state != STATE_ERROR) {
    if (g_ctx.stop_requested) {
      agent_set_state(&g_ctx, STATE_SHUTDOWN);
      break;
    }

    switch (g_ctx.state) {
    case STATE_IDLE_LISTEN: {
      int client_fd = accept(g_ctx.server_fd, NULL, NULL);
      if (client_fd >= 0) {
        g_ctx.current_client_fd = client_fd;
        agent_set_state(&g_ctx, STATE_HANDLING_CONN);
      } else {
        // Ignore timeouts (SO_RCVTIMEO) and signal interruptions
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
          perror("Accept failed");
          agent_set_state(&g_ctx, STATE_ERROR);
        }
      }
      break;
    }

    case STATE_HANDLING_CONN:
      agent_handle_connection(&g_ctx);
      agent_set_state(&g_ctx, STATE_IDLE_LISTEN);
      break;

    case STATE_INIT:
    case STATE_SHUTDOWN:
    case STATE_ERROR:
      break;
    }
  }

  // Final cleanup
  int exit_code = (g_ctx.state == STATE_ERROR) ? 1 : 0;
  agent_cleanup(&g_ctx);
  fprintf(stderr, "Agent stopped.\n");

  return exit_code;
}
