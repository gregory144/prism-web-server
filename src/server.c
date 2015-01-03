#include "config.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

#include "util.h"
#include "server.h"
#include "logo.h"

#define LISTEN_BACKLOG 128
#define PATH_SIZE 1024

uv_buf_t dummy_buf;

struct server_client_t {
  uv_tcp_t client;
  uv_write_t req;
  uv_buf_t buf;
};

static void close_process_handle(uv_process_t * req, int64_t exit_status, int term_signal)
{
  fprintf(stderr, "Process exited with status %" PRId64 ", signal %d\n", exit_status, term_signal);
  uv_close((uv_handle_t *) req, NULL);
}

void on_write_complete(uv_write_t * req, int status)
{
  if (status) {
    fprintf(stderr, "Write error %s\n", uv_err_name(status));
  }
  free(req->data);
}

static void on_new_connection(uv_stream_t * server, int status)
{
  if (status == -1) {
    // error!
    return;
  }

  struct server_t * prism_server = server->data;

  struct server_client_t * server_client = malloc(sizeof(struct server_client_t));
  uv_tcp_t * client = &server_client->client;
  uv_tcp_init(&prism_server->loop, client);

  if (uv_accept(server, (uv_stream_t *) client) == 0) {

    uv_write_t * write_req = &server_client->req;
    write_req->data = server_client;

    uv_buf_t * buf = &server_client->buf;
    buf->base = ".";
    buf->len = 1;

    struct child_worker_t * worker = prism_server->workers[prism_server->round_robin_counter];

    uv_write2(write_req, (uv_stream_t *) &worker->pipe, buf, 1,
        (uv_stream_t *) client, on_write_complete);
    prism_server->round_robin_counter = (prism_server->round_robin_counter + 1) %
      prism_server->config->num_workers;

    fprintf(stderr, "Accepting new connection\n");
  } else {
    free(server_client);
    uv_close((uv_handle_t *) client, NULL);
  }
}

static void setup_workers(struct server_t * server)
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

  for (int j = 0; j < server->config->argc + 2; j++) {
    printf("args: %d: %s\n", j, args[j]);
  }

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

    uv_spawn(&server->loop, &worker->req, &worker->options);
    fprintf(stderr, "Started worker %d\n", worker->req.pid);
  }
}

int server_run(struct server_t * prism_server)
{
  for (size_t i = 0; i < LOGO_LINES_LENGTH; i++) {
    log_append(prism_server->log, LOG_INFO, (char *) LOGO_LINES[i]);
  }
  log_append(prism_server->log, LOG_INFO, "Server starting on %s:%ld", prism_server->config->hostname, prism_server->config->port);

  setup_workers(prism_server);

  uv_tcp_t server;
  uv_tcp_init(&prism_server->loop, &server);
  server.data = prism_server;

  struct sockaddr_in bind_addr;
  uv_ip4_addr(prism_server->config->hostname, prism_server->config->port, &bind_addr);
  uv_tcp_bind(&server, (const struct sockaddr *)&bind_addr, 0);
  int r;
  if ((r = uv_listen((uv_stream_t *) &server, LISTEN_BACKLOG, on_new_connection))) {
    fprintf(stderr, "Listen error %s\n", uv_err_name(r));
    return 2;
  }
  return uv_run(&prism_server->loop, UV_RUN_DEFAULT);
}

/*static void null_close_cb(uv_handle_t * handle)*/
/*{*/
  /*UNUSED(handle);*/

  /*// noop*/
/*}*/

void server_init(struct server_t * server, struct server_config_t * config)
{
  uv_loop_init(&server->loop);

  server->log = &config->server_log;
  server->wire_log = &config->wire_log;
  server->data_log = &config->data_log;
  server->config = config;

  server->round_robin_counter = 0;
}

/*static void server_free(struct server_t * server)*/
/*{*/
  /*[>for (size_t i = 0; i < server->config->num_workers; i++) {<]*/
    /*[>struct child_worker_t * worker = server->workers[i];<]*/
    /*[>free(worker);<]*/
  /*[>}<]*/

  /*free(server->workers);*/

  /*uv_signal_stop(&server->sigint_handler);*/
  /*uv_signal_stop(&server->sigpipe_handler);*/

  /*uv_close((uv_handle_t *) &server->sigint_handler, null_close_cb);*/
  /*uv_close((uv_handle_t *) &server->sigpipe_handler, null_close_cb);*/
  /*uv_close((uv_handle_t *) &server->tcp_handler, null_close_cb);*/

  /*uv_loop_close(&server->loop);*/

  /*free(server);*/
/*}*/

/*int server_start(struct server_t * server)*/
/*{*/

  /*plugin_list_t * current = server->plugins;*/

  /*while (current != NULL) {*/
    /*plugin_start(current->plugin);*/
    /*current = current->next;*/
  /*}*/

  /*// set up workers*/
  /*size_t i;*/
  /*server->workers = malloc(sizeof(struct child_worker_t *) * server->config->num_workers);*/

  /*for (i = 0; i < server->config->num_workers; i++) {*/
    /*struct child_worker_t * worker = child_worker_init(server->log);*/
    /*worker->server = server;*/

    /*uv_thread_create(&worker->thread, worker_work, worker);*/

    /**(server->workers + i) = worker;*/
  /*}*/

  /*// set up connection listener*/
  /*uv_tcp_init(&server->loop, &server->tcp_handler);*/
  /*server->tcp_handler.data = server;*/

  /*struct sockaddr_in bind_addr;*/
  /*uv_ip4_addr(server->config->hostname, server->config->port, &bind_addr);*/
  /*uv_tcp_bind(&server->tcp_handler, (struct sockaddr *)&bind_addr, 0);*/

  /*int err = uv_listen((uv_stream_t *) &server->tcp_handler, LISTEN_BACKLOG, uv_cb_listen);*/

  /*if (err < 0) {*/
    /*log_append(server->log, LOG_ERROR, "Listen error: %s", uv_strerror(err));*/
    /*return 1;*/
  /*}*/

  /*for (i = 0; i < LOGO_LINES_LENGTH; i++) {*/
    /*log_append(server->log, LOG_INFO, (char *) LOGO_LINES[i]);*/
  /*}*/
  /*log_append(server->log, LOG_INFO, "Server starting on %s:%ld", server->config->hostname, server->config->port);*/

  /*uv_signal_start(&server->sigpipe_handler, server_sigpipe_handler, SIGPIPE);*/
  /*uv_signal_start(&server->sigint_handler, server_sigint_handler, SIGINT);*/

  /*int ret = uv_run(&server->loop, UV_RUN_DEFAULT);*/

  /*server_free(server);*/

  /*return ret;*/

/*}*/

/*void server_stop(struct server_t * server)*/
/*{*/
  /*log_append(server->log, LOG_INFO, "Server shutting down...");*/

  /*log_append(server->log, LOG_DEBUG, "Closing %zu workers", server->config->num_workers);*/

  /*// tell the workers to stop*/
  /*size_t i;*/

  /*for (i = 0; i < server->config->num_workers; i++) {*/
    /*struct child_worker_t * worker = server->workers[i];*/

    /*log_append(server->log, LOG_DEBUG,*/
        /*"Closing worker #%zu with %zu assigned reads (pushes: %zu, pops: %zu, length: %zu)",*/
        /*i, worker->assigned_reads, worker->read_queue->num_pushes, worker->read_queue->num_pops,*/
        /*worker->read_queue->length);*/

    /*uv_async_send(&worker->stop_handle);*/
  /*}*/

  /*// wait until the workers stop*/
  /*for (i = 0; i < server->config->num_workers; i++) {*/
    /*worker_t * worker = server->workers[i];*/

    /*uv_thread_join(&worker->thread);*/
  /*}*/

  /*plugin_list_t * current = server->plugins;*/

  /*while (current) {*/
    /*plugin_stop(current->plugin);*/
    /*current = current->next;*/
  /*}*/

  /*uv_stop(&server->loop);*/
/*}*/
