#include "config.h"

#include <uv.h>
#include <unistd.h>
#include <ctype.h>

#include "util/log.h"

#include "server_config.h"
#include "plugin.h"
#include "worker.h"

void server_config_args_parse(struct server_config_t * config, int argc, char ** argv)
{
  config->argc = argc;
  config->argv = argv;

  config->use_tls = USE_TLS;
  config->port = SERVER_PORT;
  config->hostname = SERVER_HOSTNAME;
  config->num_workers = NUM_WORKERS;
  config->private_key_file = PRIVATE_KEY_FILE_NAME;
  config->cert_file = CERTIFICATE_FILE_NAME;
  config->plugin_configs = NULL;
  config->default_log_level = DEFAULT_LOG_LEVEL;
  config->start_worker = false;
  config->print_help = false;
  config->print_version = false;

  struct plugin_config_t * current_plugin = NULL;

  int c;

  opterr = 0;

  while ((c = getopt(argc, argv, "p:n:e:k:c:w:l:iahv")) != -1) {
    switch (c) {
      case 'p': // port
        config->port = strtol(optarg, NULL, 10);
        if (config->port < MIN_PORT || config->port > MAX_PORT) {
          fprintf(stderr, "Port is out of range (%d to %d): %ld", MIN_PORT, MAX_PORT, config->port);
          exit(EXIT_FAILURE);
        }

        break;

      case 'n': // nodename (hostname)
        config->hostname = optarg;
        break;

      case 'e': { // plugin file
        struct plugin_config_t * last = current_plugin;
        current_plugin = malloc(sizeof(struct plugin_config_t));

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

      case 'l': { // plugin file
        enum log_level_e level = log_level_from_string(optarg);
        if (level > 0) {
          config->default_log_level = level;
        }
        break;
      }

      case 'i': // insecure
        config->use_tls = false;
        break;

      case 'a': // accept (start a worker process)
        config->start_worker = true;
        break;

      case 'h': // help
        config->print_help = true;
        break;

      case 'v': // version
        config->print_version = true;
        break;

      case '?':
        if (optopt == 'c' || optopt == 'k' || optopt == 'p' | optopt == 'n') {
          fprintf(stderr, "Option -%c requires an argument.\n", optopt);
        } else if (isprint(optopt)) {
          fprintf(stderr, "Unknown option `-%c'.\n", optopt);
        } else {
          fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
        }
        break;

      default:
        abort();
    }
  }
}
