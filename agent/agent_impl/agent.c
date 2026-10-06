#include "agent.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

// Zeroes context structure and sets default configuration
void agent_init_context(AgentContext * restrict ctx) {
  if (!ctx)
    return;

  memset(ctx, 0, sizeof(*ctx));
  ctx->server_fd = -1;
  ctx->current_client_fd = -1;
  ctx->state = STATE_INIT;

  strncpy(ctx->config.sensor_id, "sensor-01", SENSOR_ID_MAX_LEN - 1);
  ctx->config.port = 2222;
  ctx->config.timeout_sec = 1;
  ctx->stop_requested = 0;
}

// Transitions state and logs the change to stderr
int agent_set_state(AgentContext * restrict ctx, AgentState new_state) {
  if (!ctx)
    return 0;

  const char *state_names[] = {"STATE_INIT", "STATE_IDLE_LISTEN",
                               "STATE_HANDLING_CONN", "STATE_SHUTDOWN",
                               "STATE_ERROR"};

  fprintf(stderr, "State transition: %s -> %s\n", state_names[ctx->state],
          state_names[new_state]);

  ctx->state = new_state;
  return 1;
}

// Configures and binds the TCP socket
int agent_init_socket(AgentContext * restrict ctx) {
  if (!ctx)
    return 0;

  ctx->server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (ctx->server_fd < 0) {
    perror("Failed to create socket");
    agent_set_state(ctx, STATE_ERROR);
    return 0;
  }

  // Reuse address to prevent "Address already in use" errors on restart
  int opt = 1;
  if (setsockopt(ctx->server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
    perror("Failed to set SO_REUSEADDR");
    agent_cleanup(ctx);
    agent_set_state(ctx, STATE_ERROR);
    return 0;
  }

  // Set timeout on accept() to periodically check stop_requested flag
  struct timeval tv;
  tv.tv_sec = ctx->config.timeout_sec;
  tv.tv_usec = 0;
  if (setsockopt(ctx->server_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
    perror("Failed to set SO_RCVTIMEO");
    agent_cleanup(ctx);
    agent_set_state(ctx, STATE_ERROR);
    return 0;
  }

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(ctx->config.port);

  if (bind(ctx->server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("Failed to bind socket");
    agent_cleanup(ctx);
    agent_set_state(ctx, STATE_ERROR);
    return 0;
  }

  if (listen(ctx->server_fd, 5) < 0) {
    perror("Failed to listen on socket");
    agent_cleanup(ctx);
    agent_set_state(ctx, STATE_ERROR);
    return 0;
  }

  return 1;
}

// Clears event structure
void event_init(ConnectionEvent * restrict event) {
  if (!event)
    return;
  memset(event, 0, sizeof(*event));
}

// Fast conversion of uint16_t to ASCII string without snprintf format parsing
static inline size_t fast_u16toa(uint16_t val, char * restrict dst) {
  char temp[5];
  size_t len = 0;
  do {
    temp[len++] = (char)('0' + (val % 10));
    val /= 10;
  } while (val > 0);

  for (size_t i = 0; i < len; i++) {
    dst[i] = temp[len - 1 - i];
  }
  return len;
}

// Extracts metadata from connected client, formats JSON and closes connection
void agent_handle_connection(AgentContext * restrict ctx) {
  if (!ctx || ctx->current_client_fd < 0)
    return;

  ConnectionEvent event;
  event_init(&event);

  // Extract client IP and port
  struct sockaddr_in client_addr;
  socklen_t addr_len = sizeof(client_addr);
  if (getpeername(ctx->current_client_fd, (struct sockaddr *)&client_addr,
                  &addr_len) == 0) {
    inet_ntop(AF_INET, &client_addr.sin_addr, event.src_ip,
              sizeof(event.src_ip));
    event.src_port = ntohs(client_addr.sin_port);
  } else {
    strncpy(event.src_ip, "unknown", sizeof(event.src_ip) - 1);
    event.src_port = 0;
  }
  event.dst_port = ctx->config.port;

  // Generate ISO-8601 UTC timestamp
  time_t now = time(NULL);
  struct tm *utc_time = gmtime(&now);
  if (utc_time) {
    strftime(event.timestamp, sizeof(event.timestamp), "%Y-%m-%dT%H:%M:%SZ",
             utc_time);
  }

  // Read payload preview safely
  ssize_t bytes_received = recv(ctx->current_client_fd, event.payload_preview,
                                sizeof(event.payload_preview) - 1, 0);
  if (bytes_received > 0) {
    event.payload_len = (size_t)bytes_received;
    event.payload_preview[bytes_received] = '\0';

    // Branchless sanitization loop to allow SIMD vectorization under -O3
    for (size_t i = 0; i < event.payload_len; i++) {
      unsigned char c = (unsigned char)event.payload_preview[i];
      int is_invalid = (c < 32) | (c > 126);
      event.payload_preview[i] = is_invalid ? '.' : (char)c;
    }
  } else {
    event.payload_len = 0;
    event.payload_preview[0] = '\0';
  }

  // Print JSON output
  event_to_json_stdout(ctx, &event);

  // Close client descriptor
  close(ctx->current_client_fd);
  ctx->current_client_fd = -1;
}

// Formats and writes JSON string directly to stdout using write() without printf/fflush
void event_to_json_stdout(const AgentContext * restrict ctx,
                          const ConnectionEvent * restrict event) {
  if (!ctx || !event)
    return;

  // Fixed buffer sized for maximum possible JSON output
  char buf[512];
  char * restrict p = buf;

  // Helper macro to append string literals with length known at compile-time
#define APPEND_LITERAL(lit) do {                  \
    memcpy(p, lit, sizeof(lit) - 1);              \
    p += sizeof(lit) - 1;                         \
  } while(0)

  APPEND_LITERAL("{\"msg_type\":\"event\",\"sensor_id\":\"");

  size_t len = strlen(ctx->config.sensor_id);
  memcpy(p, ctx->config.sensor_id, len); p += len;

  APPEND_LITERAL("\",\"timestamp\":\"");
  len = strlen(event->timestamp);
  memcpy(p, event->timestamp, len); p += len;

  APPEND_LITERAL("\",\"event_type\":\"raw_connection\",\"src_ip\":\"");
  len = strlen(event->src_ip);
  memcpy(p, event->src_ip, len); p += len;

  APPEND_LITERAL("\",\"src_port\":");
  p += fast_u16toa(event->src_port, p);

  APPEND_LITERAL(",\"dst_port\":");
  p += fast_u16toa(event->dst_port, p);

  APPEND_LITERAL(",\"payload\":\"");
  len = strlen(event->payload_preview);
  memcpy(p, event->payload_preview, len); p += len;

  APPEND_LITERAL("\"}\n");

#undef APPEND_LITERAL

  // Single system call output to bypass stdio buffering overhead
  (void)write(STDOUT_FILENO, buf, (size_t)(p - buf));
}

// Closes open socket descriptors and resets state
void agent_cleanup(AgentContext * restrict ctx) {
  if (!ctx)
    return;

  if (ctx->current_client_fd >= 0) {
    close(ctx->current_client_fd);
    ctx->current_client_fd = -1;
  }

  if (ctx->server_fd >= 0) {
    close(ctx->server_fd);
    ctx->server_fd = -1;
  }
}
