#include "config.h"

#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>

#include "server_config.h"
#include "server.h"
#include "worker.h"


void print_version()
{
  fprintf(stdout, "%s\n", PACKAGE_STRING);
}

void print_help(char * cmd)
{
  fprintf(stdout, "Usage: %s [OPTION]...\n", cmd);
  fprintf(stdout, "Example: %s -p %d -n localhost -i\n\n", cmd, SERVER_PORT);
  fprintf(stdout, "  -p NUM\t\tport\n");
  fprintf(stdout, "  -n HOSTNAME\t\thostname\n");
  fprintf(stdout, "  -w NUM_WORKERS\tspecify the number of worker threads to handle requests\n");
  fprintf(stdout, "  -i\t\t\tturn off TLS\n");
  fprintf(stdout, "  -k FILE\t\tlocation of private key file (PEM)\n");
  fprintf(stdout, "  -c FILE\t\tlocation of certificate file (PEM)\n");
  fprintf(stdout, "  -e FILE\t\tlocation of a plugin shared library\n");
  fprintf(stdout, "  -l LEVEL\t\tone of: (TRACE|DEBUG|INFO|WARN|ERROR|FATAL), default: WARN\n");

  print_version();
}

static int run_as_server(struct server_config_t * config)
{
  struct server_t server;
  server_init(&server, config);

  server_run(&server);

  return -1;
}

static int run_as_worker(struct server_config_t * config)
{
  struct worker_t worker;
  if (!worker_init(&worker, config)) {
    //TODO error handling
    abort();
  }

  worker_run(&worker);

  return -1;
}

int main(int argc, char ** argv)
{
  struct server_config_t config;
  server_config_args_parse(&config, argc, argv);

  if (config.print_help) {
    print_help(argv[0]);
    exit(EXIT_SUCCESS);
  } else if (config.print_version) {
    print_version();
    exit(EXIT_SUCCESS);
  }

  enum log_level_e min_level = config.default_log_level;

  log_context_init(&config.server_log, "SERVER", stdout, min_level, true);
  log_context_init(&config.wire_log, "WIRE", stdout, min_level, true); // wire log must be configured separately
  log_context_init(&config.data_log, "DATA", stdout, min_level, true);
  log_context_init(&config.http_log, "HTTP", stdout, min_level, true);
  log_context_init(&config.hpack_log, "HPACK", stdout, min_level, true);
  log_context_init(&config.tls_log, "TLS", stdout, min_level, true);
  log_context_init(&config.plugin_log, "PLUGIN", stdout, min_level, true);

  fprintf(stdout, "Process: %d, stdout\n", getpid());
  fprintf(stderr, "Process: %d, stderr\n", getpid());

  if (config.start_worker) {

    printf("Running as worker\n");

    run_as_worker(&config);

  } else {

    printf("Running as server\n");

    run_as_server(&config);

  }

  exit(EXIT_SUCCESS);
}

