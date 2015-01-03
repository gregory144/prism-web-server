#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>

#include "util/util.h"

#include "server.h"

static int open_clients = 0;
static int total_clients = 0;

struct client_t * client_init(worker_t * worker)
{
  open_clients++;
  total_clients++;

  client_t * client = malloc(sizeof(client_t));
  client->id = worker->client_ids++;
  log_append(worker->log, LOG_DEBUG, "Initializing client %zu (%d)", client->id, total_clients);
  client->log = worker->log;
  client->data_log = worker->data_log;
  client->wire_log = worker->wire_log;
  client->selected_protocol = false;
  client->closing = false;
  client->closed = false;
  client->uv_closed = false;
  client->http_closed = false;
  client->reads_finished = true;
  client->eof = false;
  client->tls_ctx = NULL;
  client->octets_written = 0;
  client->octets_read = 0;
  client->worker_index = SIZE_MAX;
  client->plugin_invoker->plugins = server->plugins;
  client->plugin_invoker->client = client;

  if (atomic_int_init(&client->read_counter) == NULL) {
    free(client);
    return NULL;
  }

  client->write_queue = blocking_queue_init();

  client->closed_async_handle_count = 0;

  client->server = server;

  return client;
}

bool client_free(client_t * client)
{

  if (!client->http_closed) {
    log_append(client->log, LOG_TRACE, "Freeing client but http not finished: %zu", client->id);
    return false;
  }

  if (!client->uv_closed) {
    log_append(client->log, LOG_TRACE, "Freeing client but uv not finished: %zu", client->id);
    return false;
  }

  if (!client->reads_finished) {
    log_append(client->log, LOG_TRACE, "Freeing client but reads not finished: %zu", client->id);
    return false;
  }

  if (client->tls_ctx) {
    tls_client_free(client->tls_ctx);
  }

  http_connection_free(client->connection);

  atomic_int_free(&client->read_counter);
  blocking_queue_free(client->write_queue);

  /*uv_close((uv_handle_t *) &client->write_handle, client_free_close_cb);*/
  /*uv_close((uv_handle_t *) &client->close_handle, client_free_close_cb);*/
  /*uv_close((uv_handle_t *) &client->read_finished_handle, client_free_close_cb);*/

  open_clients--;
  log_append(client->log, LOG_DEBUG, "Freed client %zu (%d/%d left)", client->id, open_clients, total_clients);

  free(client);

  return true;

}

