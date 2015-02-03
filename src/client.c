#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>

#include "util/util.h"

#include "client.h"

static long open_clients = 0;
static long total_clients = 0;

bool client_init(struct client_t * client, struct worker_t * worker)
{
  open_clients++;
  total_clients++;

  client->id = total_clients;
  log_append(worker->log, LOG_DEBUG, "Initializing client %zu", client->id);
  client->log = worker->log;
  client->data_log = worker->data_log;
  client->wire_log = worker->wire_log;
  client->selected_protocol = false;
  client->closing = false;
  client->closed = false;
  client->eof = false;
  client->pending_writes = 0;
  client->tls_ctx = NULL;

  client->plugin_invoker = malloc(sizeof(struct plugin_invoker_t));
  if (!client->plugin_invoker) {
    return false;
  }
  client->plugin_invoker->plugins = worker->plugins;
  client->plugin_invoker->client = client;

  client->worker = worker;

  log_append(client->log, LOG_DEBUG, "Initialized client %zu (%ld/%ld left)",
      client->id, open_clients, total_clients);

  return true;
}

bool client_free(struct client_t * client)
{
  if (client->tls_ctx) {
    log_append(client->log, LOG_DEBUG, "Freeing TLS client %zu", client->id);
    tls_client_free(client->tls_ctx);
  }

  http_connection_free(client->connection);

  open_clients--;
  log_append(client->log, LOG_DEBUG, "Freed client %zu (%ld/%ld left)", client->id, open_clients, total_clients);

  free(client->plugin_invoker);
  free(client);

  return true;

}

