#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

#include "server_config.h"

#define PATH_SIZE 1024

bool daemonize(struct server_config_t * config)
{
  size_t path_size = PATH_SIZE;
  char worker_path[PATH_SIZE];
  uv_exepath(worker_path, &path_size);

  // copy the existing arguments, but remove the "-d" to start the server process
  char * args[config->argc + 1];
  int argi = 0;
  args[argi++] = worker_path;
  for (int i = 1; i < config->argc; i++) {
    if (strcmp(config->argv[i], "-d") != 0) {
      args[argi++] = config->argv[i];
    }
  }
  args[argi++] = NULL;

  uv_loop_t * loop = uv_default_loop();

  uv_process_t child_req;
  memset(&child_req, 0, sizeof(child_req));
  uv_process_options_t options;
  memset(&options, 0, sizeof(options));

  options.file = args[0];
  options.args = args;
  options.flags = UV_PROCESS_DETACHED;

  int r;
  if ((r = uv_spawn(loop, &child_req, &options))) {
      fprintf(stderr, "%s\n", uv_strerror(r));
      return 1;
  }
  fprintf(stderr, "Launched daemon with PID %d\n", child_req.pid);
  uv_unref((uv_handle_t*) &child_req);

  return uv_run(loop, UV_RUN_DEFAULT);
}

