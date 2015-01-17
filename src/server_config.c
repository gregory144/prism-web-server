#include "config.h"

#include <uv.h>
#include <unistd.h>
#include <ctype.h>

#include "util/log.h"

#include "server_config.h"
#include "plugin.h"
#include "worker.h"

static void append_address(struct server_config_t * config, struct listen_address_t * addr) {
  addr->next = NULL;

  struct listen_address_t * curr = config->address_list;
  if (!curr) {
    config->address_list = addr;
  } else {
    while (curr->next) {
      curr = curr->next;
    }
    curr->next = addr;
  }
}

static bool starts_with(char * s, char * pre)
{
  size_t lenpre = strlen(pre);
  size_t lenstr = strlen(s);
  return lenstr < lenpre ? false : strncmp(pre, s, lenpre) == 0;
}


static struct listen_address_t * parse_address(char * address)
{
  bool use_tls = false;
  if (starts_with(address, "https://")) {
    use_tls = true;
  } else if (starts_with(address, "http://")) {
    use_tls = false;
  } else {
    return NULL;
  }
  char * host = SERVER_HOSTNAME;
  char * after_protocol = address + (use_tls ? strlen("https://") : strlen("http://"));
  char * colon = strchr(after_protocol, ':');
  long port = SERVER_PORT;
  if (colon != NULL) {
    size_t host_length = colon - after_protocol;
    if (host_length > 0) {
      host = malloc(host_length + 1);
      memcpy(host, after_protocol, host_length);
      host[host_length] = '\0';
    }

    port = strtol(colon + 1, NULL, 10);
  } else {
    host = strdup(after_protocol);
  }
  if (port < MIN_PORT || port > MAX_PORT) {
    fprintf(stderr, "Port is out of range (%d to %d): %ld", MIN_PORT, MAX_PORT, port);
    exit(EXIT_FAILURE);
  }

  struct listen_address_t * addr = malloc(sizeof(struct listen_address_t));
  addr->use_tls = use_tls;
  addr->hostname = host;
  addr->port = port;

  return addr;
}

void server_config_args_parse(struct server_config_t * config, int argc, char ** argv)
{
  config->argc = argc;
  config->argv = argv;

  config->address_list = NULL;
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

  while ((c = getopt(argc, argv, "l:p:k:c:w:L:ahv")) != -1) {

    switch (c) {
      case 'l': { // listen address
        struct listen_address_t * addr = parse_address(optarg);
        if (addr == NULL) {
          fprintf(stderr, "Failed to parse address: %s\n", optarg);
          exit(EXIT_FAILURE);
        }
        append_address(config, addr);
        break;

      }
      case 'p': { // plugin file
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

      case 'L': { // log level
        enum log_level_e level = log_level_from_string(optarg);
        if (level > 0) {
          config->default_log_level = level;
        }
        break;
      }

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
        if (optopt == 'l' || optopt == 'p' || optopt == 'k' || optopt == 'c' ||
            optopt == 'w' || optopt == 'o' || optopt == 'L') {
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

  if (config->address_list == NULL) {
    struct listen_address_t * addr = malloc(sizeof(struct listen_address_t));
    addr->use_tls = USE_TLS;
    addr->hostname = SERVER_HOSTNAME;
    addr->port = SERVER_PORT;
    append_address(config, addr);
  }

}
