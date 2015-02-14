#include "config.h"

#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>

#include <uv.h>

#include "server_config.h"
#include "server.h"
#include "worker.h"
#include "daemon.h"

void print_version()
{
  fprintf(stdout, "%s %s\n", PACKAGE_STRING, BUILD_TIMESTAMP);
  if (strcmp(GIT_BRANCH, "") != 0 && strcmp(GIT_COMMIT_HASH, "") != 0) {
    fprintf(stdout, "Git: %s %s\n", GIT_BRANCH, GIT_COMMIT_HASH);
  } else if (strcmp(GIT_BRANCH, "") == 0 && strcmp(GIT_COMMIT_HASH, "") != 0) {
    fprintf(stdout, "Git: %s\n", GIT_COMMIT_HASH);
  }
  fprintf(stdout, "\tLibUV %s\n", uv_version_string());
  fprintf(stdout, "\t%s (build: %s)\n", SSLeay_version(SSLEAY_VERSION), OPENSSL_BUILD_VERSION);
}

void print_help(char * cmd)
{
  fprintf(stdout, "Usage: %s [OPTION]...\n", cmd);
  fprintf(stdout, "Example: %s -l https://%s:%d\n\n", cmd, SERVER_HOSTNAME, SERVER_PORT);
  fprintf(stdout, "  -l ADDRESS\t\tscheme, IP address and port: http://0.0.0.0:8080\n");
  fprintf(stdout, "  -p FILE\t\tlocation of a plugin shared library\n");
  fprintf(stdout, "  -k FILE\t\tlocation of private key file (PEM)\n");
  fprintf(stdout, "  -c FILE\t\tlocation of certificate file (PEM)\n");
  fprintf(stdout, "  -w NUM_WORKERS\tspecify the number of worker threads to handle requests\n");
  fprintf(stdout, "  -L LEVEL\t\tone of: (TRACE|DEBUG|INFO|WARN|ERROR|FATAL), default: WARN\n");
  fprintf(stdout, "  -o FILE\t\tthe log file to append to\n");
  fprintf(stdout, "  -d\t\t\tstart as a daemon\n");
  fprintf(stdout, "  -h\t\t\this help message\n");
  fprintf(stdout, "  -v\t\t\tversion information\n");

  print_version();
}

static bool run_as_server(struct server_config_t * config)
{
  struct server_t server;
  server_init(&server, config);

  if (!server_run(&server)) {
    // kill child processes if they were started
    server_stop(&server);

    server_free(&server);

    return false;
  }

  server_free(&server);

  return true;
}

static bool run_as_worker(struct server_config_t * config)
{
  struct worker_t worker;
  if (!worker_init(&worker, config)) {
    worker_free(&worker);
    return false;
  }

  worker_run(&worker);

  worker_free(&worker);

  return true;
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
  } else if (config.start_daemon) {
    daemonize(&config);
    exit(EXIT_SUCCESS);
  }

  enum log_level_e min_level = config.default_log_level;
  FILE * log_file = config.log_file;

  log_context_init(&config.server_log, "SERVER", log_file, min_level, true);
  log_context_init(&config.worker_log, "WORKER", log_file, min_level, true);
  log_context_init(&config.wire_log, "WIRE", log_file, min_level, true);
  log_context_init(&config.data_log, "DATA", log_file, min_level, true);
  log_context_init(&config.http_log, "HTTP", log_file, min_level, true);
  log_context_init(&config.hpack_log, "HPACK", log_file, min_level, true);
  log_context_init(&config.tls_log, "TLS", log_file, min_level, true);
  log_context_init(&config.plugin_log, "PLUGIN", log_file, min_level, true);

  bool success = false;
  if (config.start_worker) {
    success = run_as_worker(&config);
  } else {
    success = run_as_server(&config);
  }

  if (log_file != stdout) {
    fclose(log_file);
  }

  exit(success ? EXIT_SUCCESS : EXIT_FAILURE);
}

