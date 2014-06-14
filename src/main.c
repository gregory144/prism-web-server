#include <signal.h>
#include <stdio.h>

#include "util/util.h"

#include "server.h"

http_server_data_t * server_data = NULL;

void catcher(int sig)
{
  log_error("Caught signal: %d", sig);

  server_stop(server_data);

  exit(EXIT_SUCCESS);
}

void log_sigpipe(int sig)
{
  log_error("Caught signal: %d", sig);
}

int main()
{
  // ignore sigpipe
  struct sigaction sigact_pipe;
  sigemptyset(&sigact_pipe.sa_mask);
  sigact_pipe.sa_flags = 0;
  sigact_pipe.sa_handler = log_sigpipe;
  sigaction(SIGPIPE, &sigact_pipe, NULL);

  struct sigaction sigact_int;
  sigemptyset(&sigact_int.sa_mask);
  sigact_int.sa_flags = 0;
  sigact_int.sa_handler = catcher;
  sigaction(SIGINT, &sigact_int, NULL);

  server_data = server_init();

  if (!server_data) {
    exit(EXIT_FAILURE);
  }

  server_start(server_data);

  server_stop(server_data);

  exit(EXIT_SUCCESS);
}

