#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>

#include <uv.h>

#include "config.h"

#include "util/util.h"
#include "http2/http.h"
#include "http2/request.h"

#include "server.h"

#include "worker.c"

#define MAX_CLIENTS 0x4000
#define LISTEN_BACKLOG 1024

static int open_clients = 0;
static int total_clients = 0;

static void server_sigpipe_handler(uv_signal_t * sigpipe_handler, int signum)
{
  log_warning("Caught SIGPIPE: %d", signum);

  UNUSED(sigpipe_handler);
}

static void server_sigint_handler(uv_signal_t * sigint_handler, int signum)
{
  log_info("Caught SIGINT: %d", signum);

  server_t * server = sigint_handler->data;

  if (!server->terminate) {
    server_stop(server);
    server->terminate = true;
  }
}

static void uv_cb_alloc_buffer(uv_handle_t * handle, size_t suggested_size, uv_buf_t * buf)
{
  UNUSED(handle);
  buf->len = suggested_size;
  buf->base = malloc(suggested_size);
}

static void uv_cb_write(uv_write_t * req, int status)
{
  if (req == NULL) {
    abort();
  }

  http_write_req_data_t * write_req_data = req->data;
  client_t * client = write_req_data->stream->data;

  if (status < 0) {
    log_error("Write error: %s, client #%ld", uv_strerror(status), client->id);
  }

  uv_async_send(&client->written_handle);

  free(write_req_data->buf.base);
  free(write_req_data);
}

static void server_uv_async_cb_write(uv_async_t * async_handle)
{
  client_t * client = async_handle->data;

  while (true) {
    worker_buffer_t * worker_buffer = blocking_queue_try_pop(client->write_queue);

    if (!worker_buffer) {
      break;
    }

    uv_tcp_t * stream = &client->tcp;

    if (uv_is_active((uv_handle_t *) stream) && !client->eof) {

      log_debug("Writing for client: #%ld", client->id);

      http_write_req_data_t * write_req_data = malloc(sizeof(http_write_req_data_t));
      write_req_data->stream = (uv_stream_t *) stream;
      write_req_data->req.data = write_req_data;

      write_req_data->buf.base = (char *) worker_buffer->buffer;
      write_req_data->buf.len = worker_buffer->length;

      if (LOG_DATA) {
        log_trace("uv_write: %s, %ld", worker_buffer->buffer, worker_buffer->length);
        size_t i;

        for (i = 0; i < worker_buffer->length; i++) {
          log_trace("%02x", worker_buffer->buffer[i]);
        }
      }

      uv_write(&write_req_data->req, (uv_stream_t *) stream, &write_req_data->buf, 1, uv_cb_write);

    } else {

      free(worker_buffer->buffer);
      uv_async_send(&client->written_handle);

    }

    free(worker_buffer);
  }

}

static void client_free_close_cb(uv_handle_t * handle)
{
  client_t * client = handle->data;

  client->closed_async_handle_count++;

  // we need the count to be 2 to continue - to make sure both
  // the client's write_handle and close_handle have been closed
  if (client->closed_async_handle_count == 2) {

    open_clients--;
    log_debug("Freed client %ld (%d/%d left)", client->id, open_clients, total_clients);
    free(client);

  }
}

static void client_free(client_t * client)
{

  if (!client->http_closed) {
    log_trace("Freeing client but http not finished: %ld", client->id);
  }

  if (!client->uv_closed) {
    log_trace("Freeing client but uv not finished: %ld", client->id);
  }

  // wait until all threads have finished with it
  if (client->uv_closed && client->http_closed) {

    if (client->tls_ctx) {
      tls_client_free(client->tls_ctx);
    }

    http_connection_free(client->connection);

    blocking_queue_free(client->write_queue);

    uv_close((uv_handle_t *) &client->write_handle, client_free_close_cb);
    uv_close((uv_handle_t *) &client->close_handle, client_free_close_cb);

  }

}

static void uv_cb_close_connection(uv_handle_t * handle)
{

  client_t * client = handle->data;

  log_debug("Closing connection from uv callback: %ld, reads = %ld octets, writes = %ld octets",
            client->id, client->octets_read, client->octets_written);

  client->uv_closed = true;

  client_free(client);

}

static void uv_cb_shutdown(uv_shutdown_t * shutdown_req, int status)
{
  client_t * client = shutdown_req->data;

  if (status) {
    log_error("Shutdown error, client: %ld: %s", client->id, uv_strerror(status));
  }

  if (!client->closing) {
    client->closing = true;
    uv_close((uv_handle_t *) &client->tcp, uv_cb_close_connection);
  }

  free(shutdown_req);
}

static void uv_cb_read(uv_stream_t * stream, ssize_t nread, const uv_buf_t * buf)
{

  client_t * client = stream->data;

  if (nread == UV_EOF) {
    free(buf->base);

    log_debug("EOF, client: %ld", client->id);

    client->eof = true;
    worker_queue(client, true, NULL, 0);

    return;
  } else if (nread < 0) {
    free(buf->base);

    log_error("Read error, client: %ld: %s", client->id, uv_strerror(nread));

    client->eof = true;
    worker_queue(client, true, NULL, 0);

    client->closing = true;
    uv_close((uv_handle_t *) &client->tcp, uv_cb_close_connection);

    return;
  }

  log_debug("Queueing from client: #%ld", client->id);
  worker_queue(client, false, (uint8_t *) buf->base, nread);

}

static void server_uv_async_cb_close(uv_async_t * async_handle)
{
  client_t * client = async_handle->data;
  log_debug("Closing connection from async callback: %ld", client->id);

  client->http_closed = true;

  // if the connection has already been closed (due to a read error)
  // don't try to shutdown - just free it
  if (client->uv_closed) {
    client_free(client);
    return;
  }

  if (client->closing) {
    return;
  }

  uv_shutdown_t * shutdown_req = malloc(sizeof(uv_shutdown_t));
  shutdown_req->data = client;
  uv_shutdown(shutdown_req, (uv_stream_t *) &client->tcp, uv_cb_shutdown);
}

// pass the decrypted data on to the application
static bool tls_cb_write_to_app(void * data, uint8_t * buf, size_t length)
{
  client_t * client = data;

  log_trace("Passing %ld octets of data from TLS handler to application", length);
  worker_parse(client, (uint8_t *)buf, length);
  log_trace("Passed %ld octets of data from TLS handler to application", length);

  return true;
}

static void server_request_handler(void * data, http_request_t * request, http_response_t * response)
{
  client_t * client = data;
  backend_t * backend = &client->server->backend;
  worker_t * worker = client->server->workers[client->worker_index];

  backend_request_handler(backend, worker, request, response);
}

static void server_data_handler(void * data, http_request_t * request, http_response_t * response,
                                uint8_t * buf, size_t length, bool last, bool free_buf)
{
  client_t * client = data;
  backend_t * backend = &client->server->backend;
  worker_t * worker = client->server->workers[client->worker_index];

  backend_data_handler(backend, worker, request, response, buf, length, last, free_buf);
}

static void uv_cb_listen(uv_stream_t * tcp_server, int status)
{
  if (status == -1) {
    log_error("Listen failed: %d", status);
    // error!
    return;
  }

  server_t * server = tcp_server->data;

  open_clients++;
  total_clients++;
  client_t * client = malloc(sizeof(client_t));
  client->id = server->client_ids++;
  log_debug("Initializing client %ld (%d)", client->id, total_clients);
  client->closing = false;
  client->closed = false;
  client->uv_closed = false;
  client->http_closed = false;
  client->eof = false;
  client->tls_ctx = NULL;
  client->octets_written = 0;
  client->octets_read = 0;
  client->worker_index = SIZE_MAX;

  client->write_queue = blocking_queue_init();

  uv_async_init(&server->loop, &client->write_handle, server_uv_async_cb_write);
  client->write_handle.data = client;

  uv_async_init(&server->loop, &client->close_handle, server_uv_async_cb_close);
  client->close_handle.data = client;

  client->closed_async_handle_count = 0;

  client->server = server;
  client->connection = http_connection_init(client, server_request_handler,
                       server_data_handler, worker_http_cb_write, worker_http_cb_close_connection);

  uv_tcp_init(&server->loop, &client->tcp);
  client->tcp.data = client;

  if (uv_accept(tcp_server, (uv_stream_t *) &client->tcp) == 0) {

    if (server->config->use_tls) {
      client->tls_ctx = tls_client_init(server->tls_ctx, client, worker_can_continue, worker_write_to_network,
                                        tls_cb_write_to_app);
    }

    int err = uv_read_start((uv_stream_t *) &client->tcp, uv_cb_alloc_buffer, uv_cb_read);

    if (err < 0) {
      log_error("Read error: %s", uv_strerror(err));
    }
  } else {
    // according to libuv docs - this should never fail as long as we're only calling uv_accept
    // once per listen callback
    log_fatal("Accepting the connection failed");
    abort();
  }
}

server_t * server_init(server_config_t * config)
{

  if (config->use_tls) {
    tls_init();
  }

  server_t * server = malloc(sizeof(server_t));
  ASSERT_OR_RETURN_NULL(server);
  server->tls_ctx = NULL;
  server->config = config;
  server->client_ids = 0;

  server->terminate = false;

  backend_t * backend = backend_init(&server->backend, server->config->backend_file, (struct server_s *) server);

  if (!backend) {
    free(server);
    return NULL;
  }

  if (config->use_tls) {
    server->tls_ctx = tls_server_init(config->private_key_file, config->cert_file);

    if (!server->tls_ctx) {
      free(server);
      return NULL;
    }
  }

  uv_loop_init(&server->loop);

  uv_signal_init(&server->loop, &server->sigpipe_handler);
  uv_signal_init(&server->loop, &server->sigint_handler);
  server->sigint_handler.data = server;

  return server;

}

static void null_close_cb(uv_handle_t * handle)
{
  UNUSED(handle);

  // noop
}

static void server_free(server_t * server)
{
  size_t i;

  for (i = 0; i < server->config->num_workers; i++) {
    worker_t * worker = server->workers[i];
    worker_free(worker);
  }

  free(server->workers);

  if (server->tls_ctx) {
    tls_server_free(server->tls_ctx);
  }

  uv_signal_stop(&server->sigint_handler);
  uv_signal_stop(&server->sigpipe_handler);

  uv_close((uv_handle_t *) &server->sigint_handler, null_close_cb);
  uv_close((uv_handle_t *) &server->sigpipe_handler, null_close_cb);
  uv_close((uv_handle_t *) &server->tcp_handler, null_close_cb);

  uv_loop_close(&server->loop);

  free(server);
}

int server_start(server_t * server)
{

  backend_start(&server->backend);

  // set up workers
  size_t i;
  server->workers = malloc(sizeof(worker_t *) * server->config->num_workers);

  for (i = 0; i < server->config->num_workers; i++) {
    worker_t * worker = worker_init();
    worker->server = server;

    uv_thread_create(&worker->thread, worker_work, worker);

    *(server->workers + i) = worker;
  }

  // set up connection listener
  uv_tcp_init(&server->loop, &server->tcp_handler);
  server->tcp_handler.data = server;

  struct sockaddr_in bind_addr;
  uv_ip4_addr(server->config->hostname, server->config->port, &bind_addr);
  uv_tcp_bind(&server->tcp_handler, (struct sockaddr *)&bind_addr, 0);

  int err = uv_listen((uv_stream_t *) &server->tcp_handler, LISTEN_BACKLOG, uv_cb_listen);

  if (err < 0) {
    log_error("Listen error: %s", uv_strerror(err));
    return 1;
  }

  log_info("Server starting on %s:%d", server->config->hostname, server->config->port);

  uv_signal_start(&server->sigpipe_handler, server_sigpipe_handler, SIGPIPE);
  uv_signal_start(&server->sigint_handler, server_sigint_handler, SIGINT);

  int ret = uv_run(&server->loop, UV_RUN_DEFAULT);

  server_free(server);

  return ret;

}

void server_stop(server_t * server)
{
  log_info("Server shutting down...");

  log_debug("Closing %ld workers", server->config->num_workers);

  // tell the workers to stop
  size_t i;

  for (i = 0; i < server->config->num_workers; i++) {
    worker_t * worker = server->workers[i];

    log_debug("Closing worker #%ld with %ld assigned reads (pushes: %ld, pops: %ld, length: %ld)",
              i, worker->assigned_reads, worker->read_queue->num_pushes, worker->read_queue->num_pops,
              worker->read_queue->length);

    uv_async_send(&worker->stop_handle);
  }

  // wait until the workers stop
  for (i = 0; i < server->config->num_workers; i++) {
    worker_t * worker = server->workers[i];

    uv_thread_join(&worker->thread);
  }

  backend_stop(&server->backend);

  uv_stop(&server->loop);
}
