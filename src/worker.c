#include <stdlib.h>

#include "util/util.h"
#include "server.h"
#include "blocking_queue.h"

#define POP_TIMEOUT 100000000 // in nanoseconds, = 100 milliseconds

static void worker_handle(uv_async_t * async_handle);

static void worker_stop(uv_async_t * async_handle);

static worker_t * worker_init()
{
  worker_t * worker = malloc(sizeof(worker_t));

  worker->read_queue = blocking_queue_init();
  worker->assigned_reads = 0;

  uv_mutex_init(&worker->terminate_mutex);
  uv_mutex_lock(&worker->terminate_mutex);
  worker->terminate = false;
  uv_mutex_unlock(&worker->terminate_mutex);

  uv_loop_init(&worker->loop);

  uv_async_init(&worker->loop, &worker->async_handle, worker_handle);
  worker->async_handle.data = worker;

  uv_async_init(&worker->loop, &worker->stop_handle, worker_stop);
  worker->stop_handle.data = worker;

  return worker;
}

static void worker_queue(client_t * client, uint8_t * buffer, size_t length)
{
  server_t * server = client->server;

  worker_buffer_t * worker_buffer = malloc(sizeof(worker_buffer_t));
  worker_buffer->buffer = buffer;
  worker_buffer->length = length;
  worker_buffer->client = client;

  if (client->worker_index == SIZE_MAX) {
    size_t worker_index = SIZE_MAX;
    size_t min_assigned_reads = SIZE_MAX;

    size_t i;

    for (i = 0; i < server->config->num_workers; i++) {
      worker_t * worker = server->workers[i];

      if (worker->assigned_reads < min_assigned_reads) {
        min_assigned_reads = worker->assigned_reads;
        worker_index = i;
      }
    }

    client->worker_index = worker_index;
  }

  worker_t * worker = server->workers[client->worker_index];
  worker->assigned_reads++;

  blocking_queue_push(worker->read_queue, worker_buffer);

  uv_async_send(&worker->async_handle);
  log_trace("Assigning to worker: #%ld with %ld reads", client->worker_index, worker->assigned_reads);
}

static bool worker_write_to_network(void * data, uint8_t * buffer, size_t length)
{
  client_t * client = data;

  worker_buffer_t * worker_buffer = malloc(sizeof(worker_buffer_t));

  // copy bytes to write to new buffer
  worker_buffer->buffer = malloc(sizeof(uint8_t) * length);
  memcpy(worker_buffer->buffer, buffer, length);

  worker_buffer->length = length;
  worker_buffer->client = client;

  blocking_queue_push(client->write_queue, worker_buffer);
  uv_mutex_lock(&client->async_mutex);
  uv_async_send(&client->write_handle);
  uv_mutex_unlock(&client->async_mutex);

  return true;
}

static void worker_http_cb_close_connection(void * data)
{
  client_t * client = data;

  uv_mutex_lock(&client->async_mutex);
  uv_async_send(&client->close_handle);
  uv_mutex_unlock(&client->async_mutex);
}

static bool worker_http_cb_write(void * data, uint8_t * buf, size_t length)
{
  client_t * client = data;
  server_t * server = client->server;

  client->octets_written += length;

  log_debug("Write client #%ld (%ld octets, %ld total)", client->id, length, client->octets_written);

  if (server->config->use_tls) {
    log_trace("Passing %ld octets of data from application to TLS handler", length);
    bool ret = tls_encrypt_data_and_pass_to_network(client->tls_ctx, buf, length);
    log_trace("Passed %ld octets of data from application to TLS handler", length);
    return ret;
  } else {
    return worker_write_to_network(client, buf, length);
  }
}

static void worker_parse(client_t * client, uint8_t * buffer, size_t length)
{
  client->octets_read += length;

  log_debug("Read client #%ld (%ld octets, %ld total)", client->id, length, client->octets_read);

  http_connection_t * connection = client->connection;
  http_connection_read(connection, buffer, length);
}

static void worker_handle(uv_async_t * async_handle)
{

  worker_t * worker = async_handle->data;
  worker_buffer_t * buffer = NULL;

  while (true) {

    buffer = blocking_queue_try_pop(worker->read_queue);

    if (!buffer) {
      break;
    }

    client_t * client = buffer->client;
    server_t * server = client->server;

    if (server->config->use_tls) {

      tls_client_ctx_t * tls_client_ctx = client->tls_ctx;

      log_trace("Passing %ld octets of data from network to TLS handler", buffer->length);
      tls_decrypt_data_and_pass_to_app(tls_client_ctx, buffer->buffer, buffer->length);
      log_trace("Passed %ld octets of data from network to TLS handler", buffer->length);

    } else {
      worker_parse(client, buffer->buffer, buffer->length);
    }

    free(buffer);
    buffer = NULL;
  }

}

static void worker_stop(uv_async_t * async_handle)
{
  worker_t * worker = async_handle->data;

  uv_stop(&worker->loop);
}

static void uv_close_cb_worker_stop(uv_handle_t * handle)
{
  UNUSED(handle);
  // noop
}

static void worker_free(worker_t * worker)
{
  blocking_queue_free(worker->read_queue);

  uv_close((uv_handle_t *) &worker->stop_handle, uv_close_cb_worker_stop);
  uv_close((uv_handle_t *) &worker->async_handle, uv_close_cb_worker_stop);

  log_debug("Closing worker loop");
  uv_loop_close(&worker->loop);

  free(worker);
}

static void worker_work(void * arg)
{
  worker_t * worker = arg;

  uv_run(&worker->loop, UV_RUN_DEFAULT);
  log_debug("Worker loop finished");
}

