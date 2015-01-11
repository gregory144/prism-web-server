#include "config.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>
#include <unistd.h>

#include "util.h"
#include "server.h"
#include "logo.h"

#define LISTEN_BACKLOG 128
#define PATH_SIZE 1024

uv_buf_t dummy_buf;

struct server_client_t {
  struct server_t * server;
  uv_tcp_t client;
  uv_write_t req;
  uv_buf_t buf;
};

static void close_process_handle(uv_process_t * req, int64_t exit_status, int term_signal)
{
  struct server_t * server = req->data;
  log_append(server->log, LOG_INFO, "Process exited with status %" PRId64 ", signal %d\n", exit_status, term_signal);

  uv_close((uv_handle_t *) req, NULL);
}

static void after_close(uv_handle_t * handle)
{
  struct server_client_t * server_client = handle->data;

  free(server_client);
}

void on_write_complete(uv_write_t * req, int status)
{
  struct server_client_t * server_client = req->data;
  struct server_t * server = server_client->server;

  if (status) {
    log_append(server->log, LOG_ERROR, "Error passing file descriptor to worker: %s\n", uv_err_name(status));
  }

  uv_close((uv_handle_t *) &server_client->client, after_close);
}

static void server_on_new_connection(uv_stream_t * uv_server, int status)
{
  struct server_t * server = uv_server->data;

  if (status == -1) {
    log_append(server->log, LOG_ERROR, "Error getting new connection: %s\n", uv_err_name(status));
    return;
  }

  struct server_client_t * server_client = malloc(sizeof(struct server_client_t));
  server_client->server = server;
  uv_tcp_t * client = &server_client->client;
  uv_tcp_init(&server->loop, client);
  client->data = server_client;

  if (uv_accept(uv_server, (uv_stream_t *) client) == 0) {

    uv_write_t * write_req = &server_client->req;
    write_req->data = server_client;

    uv_buf_t * buf = &server_client->buf;
    buf->base = ".";
    buf->len = 1;

    struct child_worker_t * worker = server->workers[server->round_robin_counter];

    log_append(server->log, LOG_DEBUG, "Server %d: Accepted fd %d\n", getpid(), client->io_watcher.fd);

    uv_write2(write_req, (uv_stream_t *) &worker->pipe, buf, 1,
        (uv_stream_t *) client, on_write_complete);
    server->round_robin_counter = (server->round_robin_counter + 1) %
      server->config->num_workers;

  } else {
    free(server_client);
    uv_close((uv_handle_t *) client, NULL);
  }
}

static bool setup_workers(struct server_t * server)
{
  size_t path_size = PATH_SIZE;
  char worker_path[PATH_SIZE];
  uv_exepath(worker_path, &path_size);

  // copy the existing arguments, but add "-a" as the second to start the child
  // process as a worker
  char * args[server->config->argc + 2];
  args[0] = worker_path;
  args[1] = "-a"; // run as a worker
  for (int i = 1; i < server->config->argc; i++) {
    args[i+1] = server->config->argv[i];
  }
  args[server->config->argc+1] = NULL;

  int num_workers = server->config->num_workers;

  server->workers = malloc(sizeof(struct child_worker_t *) * num_workers);

  while (num_workers--) {
    struct child_worker_t * worker = calloc(sizeof(struct child_worker_t), 1);
    server->workers[num_workers] = worker;
    uv_pipe_init(&server->loop, &worker->pipe, 1);

    uv_stdio_container_t child_stdio[3];
    child_stdio[0].flags = UV_CREATE_PIPE | UV_READABLE_PIPE;
    child_stdio[0].data.stream = (uv_stream_t *) &worker->pipe;
    child_stdio[1].flags = UV_INHERIT_FD;
    child_stdio[1].data.fd = 1;
    child_stdio[2].flags = UV_INHERIT_FD;
    child_stdio[2].data.fd = 2;

    worker->options.stdio = child_stdio;
    worker->options.stdio_count = 3;

    worker->options.exit_cb = close_process_handle;
    worker->options.file = args[0];
    worker->options.args = args;

    worker->req.data = server;

    int uv_error = uv_spawn(&server->loop, &worker->req, &worker->options);
    if (uv_error < 0) {
      log_append(server->log, LOG_FATAL, "Failed to spawn process: %s", uv_err_name(uv_error));
      return false;
    }
  }
  return true;
}

bool server_run(struct server_t * server)
{
  for (size_t i = 0; i < LOGO_LINES_LENGTH; i++) {
    log_append(server->log, LOG_INFO, (char *) LOGO_LINES[i]);
  }
  log_append(server->log, LOG_INFO, "Server starting on %s:%ld", server->config->hostname, server->config->port);

  if (!setup_workers(server)) {
    return false;
  }

  uv_tcp_t uv_server;
  uv_tcp_init(&server->loop, &uv_server);
  uv_server.data = server;

  struct sockaddr_in bind_addr;
  uv_ip4_addr(server->config->hostname, server->config->port, &bind_addr);
  uv_tcp_bind(&uv_server, (const struct sockaddr *)&bind_addr, 0);
  int r;
  if ((r = uv_listen((uv_stream_t *) &uv_server, LISTEN_BACKLOG, server_on_new_connection))) {
    log_append(server->log, LOG_FATAL, "Listen failed: %s", uv_err_name(r));
    return false;
  }
  if (uv_run(&server->loop, UV_RUN_DEFAULT)) {
    return false;
  }
  return true;
}

void server_stop(struct server_t * server)
{
  log_append(server->log, LOG_INFO, "Server shutting down...");

  uv_stop(&server->loop);
}

void server_init(struct server_t * server, struct server_config_t * config)
{
  uv_loop_init(&server->loop);

  server->log = &config->server_log;
  server->wire_log = &config->wire_log;
  server->data_log = &config->data_log;
  server->config = config;

  server->round_robin_counter = 0;
}

