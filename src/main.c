#include <signal.h>

#include "server.h"

int main() {
  // ignore sigpipe
  signal(SIGPIPE, SIG_IGN);

  return http_server_loop();
}

