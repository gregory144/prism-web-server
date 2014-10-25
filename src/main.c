#include "config.h"

#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>

#include "server.h"

#define MIN_PORT 1
#define MAX_PORT 0xFFFF
#define NUM_WORKERS 4
#define SERVER_HOSTNAME "0.0.0.0"
#define SERVER_PORT 8443

static server_t * server = NULL;

void print_version()
{
  fprintf(stdout, "%s\n", PACKAGE_STRING);
}

void print_help(char * cmd)
{
  fprintf(stdout, "Usage: %s [OPTION]...\n", cmd);
  fprintf(stdout, "Example: %s -p 8443 -n localhost -i\n\n", cmd);
  fprintf(stdout, "  -p NUM\t\tport\n");
  fprintf(stdout, "  -n HOSTNAME\t\thostname\n");
  fprintf(stdout, "  -w NUM_WORKERS\tspecify the number of worker threads to handle requests\n");
  fprintf(stdout, "  -i\t\t\tturn off TLS\n");
  fprintf(stdout, "  -k FILE\t\tlocation of private key file (PEM)\n");
  fprintf(stdout, "  -c FILE\t\tlocation of certificate file (PEM)\n");
  fprintf(stdout, "  -e FILE\t\tlocation of a plugin shared library\n");

  print_version();
}

int main(int argc, char ** argv)
{
  server_config_t * config = malloc(sizeof(server_config_t));
  config->use_tls = true;
  config->port = SERVER_PORT;
  config->hostname = SERVER_HOSTNAME;
  config->num_workers = NUM_WORKERS;
  config->private_key_file = "key.pem";
  config->cert_file = "cert.pem";
  config->plugin_configs = NULL;

  plugin_config_t * current_plugin = NULL;

  int c;

  opterr = 0;

  while ((c = getopt(argc, argv, "e:p:n:k:c:w:ighv")) != -1) {
    switch (c) {
      case 'p': // port
        config->port = strtol(optarg, NULL, 10);
        break;

      case 'n': // nodename (hostname)
        config->hostname = optarg;
        break;

      case 'e': // plugin file
      {
        plugin_config_t * last = current_plugin;
        current_plugin = malloc(sizeof(plugin_config_t));
        if (last) {
          last->next = current_plugin;
        }
        if (!config->plugin_configs) {
          config->plugin_configs = current_plugin;
        }
        current_plugin->filename = optarg;
        current_plugin->next = NULL;
        break;
      }
      case 'k': // private Key
        config->private_key_file = optarg;
        break;

      case 'c': // cert file
        config->cert_file = optarg;
        break;

      case 'w': // num workers
        config->num_workers = strtol(optarg, NULL, 10);
        break;

      case 'i': // insecure
        config->use_tls = false;
        break;

      case 'h': // help
        print_help(argv[0]);
        exit(EXIT_SUCCESS);

      case 'v': // version
        print_version();
        exit(EXIT_SUCCESS);

      case '?':
        if (optopt == 'c' || optopt == 'k' || optopt == 'p' | optopt == 'n') {
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

  if (config->port < MIN_PORT || config->port > MAX_PORT) {
    fprintf(stderr, "Port is out of range (%d to %d): %ld", MIN_PORT, MAX_PORT, config->port);
    exit(EXIT_FAILURE);
  }

  enum log_level_e min_level = LOG_DEBUG;

  log_context_init(&config->server_log, "SERVER", stdout, min_level, true);
  log_context_init(&config->data_log, "DATA", stdout, min_level, true);
  log_context_init(&config->http_log, "HTTP", stdout, min_level, true);
  log_context_init(&config->hpack_log, "HPACK", stdout, min_level, true);
  log_context_init(&config->tls_log, "TLS", stdout, min_level, true);
  log_context_init(&config->plugin_log, "PLUGIN", stdout, min_level, true);

  server = server_init(config);

  if (!server) {
    exit(EXIT_FAILURE);
  }

  server_start(server);

  exit(EXIT_SUCCESS);
}

