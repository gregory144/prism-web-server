#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>

#include "util/util.h"

#include "server.h"

#define MIN_PORT 1
#define MAX_PORT 0xFFFF

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

int main(int argc, char ** argv)
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

  bool use_tls = 1;
  long port = SERVER_PORT;
  char * private_key_file = "key.pem";
  char * cert_key_file = "cert.pem";
  int c;

  opterr = 0;

  while ((c = getopt(argc, argv, "p:k:c:i")) != -1) {
    switch (c) {
      case 'p':
        port = strtol(optarg, NULL, 10);
        break;

      case 'k':
        private_key_file = optarg;
        break;

      case 'c':
        cert_key_file = optarg;
        break;

      case 'i': // insecure
        use_tls = 0;
        break;

      case '?':
        if (optopt == 'c' || optopt == 'k' || optopt == 'p') {
          fprintf(stderr, "Option -%c requires an argument.\n", optopt);
        } else if (isprint(optopt)) {
          fprintf(stderr, "Unknown option `-%c'.\n", optopt);
        } else {
          fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
        }

        exit(EXIT_FAILURE);

      default:
        abort();
    }
  }

  if (port < MIN_PORT || port > MAX_PORT) {
    fprintf(stderr, "Port is out of range (%d to %d): %ld", MIN_PORT, MAX_PORT, port);
    exit(EXIT_FAILURE);
  }

  server_data = server_init(port, use_tls, private_key_file, cert_key_file);

  if (!server_data) {
    exit(EXIT_FAILURE);
  }

  server_start(server_data);

  server_stop(server_data);

  exit(EXIT_SUCCESS);
}

