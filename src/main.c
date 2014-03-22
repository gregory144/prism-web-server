#include <signal.h>
#include <stdio.h>

#include "server.h"
#include "util.h"

void catcher(int sig) {
  if (LOG_ERROR) log_error("caught signal %d\n", sig);
}

int main() {
  // ignore sigpipe
  struct sigaction sigact;
  sigemptyset(&sigact.sa_mask);
  sigact.sa_flags = 0;
  sigact.sa_handler = catcher;
  sigaction(SIGPIPE, &sigact, NULL );

  return server_start();
}

