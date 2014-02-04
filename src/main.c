#include <signal.h>
#include <stdio.h>

#include "server.h"

void catcher(int sig) {
  fprintf(stderr, "caught signal %d\n", sig);
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

