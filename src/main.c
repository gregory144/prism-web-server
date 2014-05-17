#include <signal.h>
#include <stdio.h>

#include "util/util.h"

#include "server.h"

void catcher(int sig) {
  if (LOG_ERROR) log_error("caught signal %d", sig);
  exit(EXIT_SUCCESS);
}

int main() {
  // ignore sigpipe
  struct sigaction sigact_pipe;
  sigemptyset(&sigact_pipe.sa_mask);
  sigact_pipe.sa_flags = 0;
  sigact_pipe.sa_handler = catcher;
  sigaction(SIGPIPE, &sigact_pipe, NULL );

  struct sigaction sigact_int;
  sigemptyset(&sigact_int.sa_mask);
  sigact_int.sa_flags = 0;
  sigact_int.sa_handler = catcher;
  sigaction(SIGINT, &sigact_int, NULL);

  server_start();

  exit(EXIT_SUCCESS);
}

