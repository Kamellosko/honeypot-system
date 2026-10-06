#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>

// Buffer size limits
#define SENSOR_ID_MAX_LEN 32
#define TIMESTAMP_ISO_LEN 32
#define PAYLOAD_PREVIEW_LEN 64

// Agent state machine
typedef enum {
  STATE_INIT,          // Setup socket, signals, and config
  STATE_IDLE_LISTEN,   // Waiting for incoming connections (with timeout)
  STATE_HANDLING_CONN, // Connection accepted: extract metadata & output JSON
  STATE_SHUTDOWN,      // Clean up resources after SIGINT / SIGTERM
  STATE_ERROR          // Fatal error: clean up and exit with error code
} AgentState;

// Startup options
typedef struct {
  char sensor_id[SENSOR_ID_MAX_LEN];
  uint16_t port;
  int timeout_sec;
} AgentConfig;

// Metadata for a single intercepted connection
typedef struct {
  char src_ip[INET6_ADDRSTRLEN];
  uint16_t src_port;
  uint16_t dst_port;
  char timestamp[TIMESTAMP_ISO_LEN];
  char payload_preview[PAYLOAD_PREVIEW_LEN];
  size_t payload_len;
} ConnectionEvent;

// Main application context holding runtime state
typedef struct {
  int server_fd;
  int current_client_fd;
  AgentState state;
  AgentConfig config;
  volatile sig_atomic_t stop_requested;
} AgentContext;

// Lifecycle & state machine management (functions return 1 for success, 0 for failure)
void agent_init_context(AgentContext * restrict ctx);
int agent_set_state(AgentContext * restrict ctx, AgentState new_state);
int agent_init_socket(AgentContext * restrict ctx);
void agent_handle_connection(AgentContext * restrict ctx);
void agent_cleanup(AgentContext * restrict ctx);

// Event handling
void event_init(ConnectionEvent * restrict event);
void event_to_json_stdout(const AgentContext * restrict ctx,
                          const ConnectionEvent * restrict event);
