#include "config.h"

#include <uv.h>
#include <unistd.h>
#include <ctype.h>

#include "util/log.h"

#include "util.h"
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
  long port = SECURE_SERVER_PORT;
  if (colon != NULL) {
    size_t host_length = colon - after_protocol;
    if (host_length > 0) {
      host = malloc(host_length + 1);
      memcpy(host, after_protocol, host_length);
      host[host_length] = '\0';
    }

    char * endptr = NULL;
    port = strtol(colon + 1, &endptr, 10);
    if (*endptr != '\0' || errno == ERANGE) {
      fprintf(stderr, "Invalid port in address \"%s\": %s\n", address, colon + 1);
      exit(EXIT_FAILURE);
    }
    if (port < MIN_PORT || port > MAX_PORT) {
      fprintf(stderr, "Port is out of range (%d to %d) in address \"%s\": %ld\n",
          MIN_PORT, MAX_PORT, address, port);
      exit(EXIT_FAILURE);
    }
  } else {
    host = strdup(after_protocol);
  }

  struct listen_address_t * addr = malloc(sizeof(struct listen_address_t));
  addr->use_tls = use_tls;
  addr->hostname = host;
  addr->port = port;

  return addr;
}

#if JANSSON_FOUND

static const char * get_string(json_t * root, char * key, const char * def)
{
  json_t * j = json_object_get(root, key);
  if (j) {
    return json_string_value(j);
  }

  return def;
}

static const int get_int(json_t * root, char * key, int def)
{
  json_t * int_j = json_object_get(root, key);
  if (int_j) {
    double int_d = json_number_value(int_j);
    int_d = int_d + 0.5; // round instead of truncate in the cast
    return (int) int_d;
  }

  return def;
}

static bool parse_config_file(struct server_config_t * config)
{
  json_t * root;
  json_error_t error;

  root = json_loadf(config->config_file, 0, &error);

  if (!root) {
    fprintf(stderr, "Error parsing config JSON on line %d: %s\n", error.line, error.text);
    return false;
  }

  config->json_root = root;

  if (!json_is_object(root)) {
    fprintf(stderr, "Error parsing config JSON: root is not an object\n");
    return false;
  }

  json_t * num_workers_j = json_object_get(root, "num_workers");
  if (num_workers_j) {
    double num_workers_d = json_number_value(num_workers_j);
    num_workers_d = num_workers_d + 0.5; // round instead of truncate in the cast
    int num_workers = num_workers_d;
    config->num_workers = num_workers;
    config->num_workers_set = true;
  }

  const char * value;

  value = get_string(root, "h2_protocol_version_string", NULL);
  if (value) config->h2_protocol_version_string = value;

  value = get_string(root, "h2c_protocol_version_string", NULL);
  if (value) config->h2c_protocol_version_string = value;

  value = get_string(root, "private_key_path", NULL);
  if (value) config->private_key_path = value;

  value = get_string(root, "certificate_path", NULL);
  if (value) config->certificate_path = value;

  value = get_string(root, "log_path", NULL);
  if (value) config->log_path = value;

  value = get_string(root, "log_level", NULL);
  if (value) config->log_level_string = value;

  json_t * plugins_j = json_object_get(root, "plugins");
  for (size_t i = 0; i < json_array_size(plugins_j); i++) {
    json_t * plugin_j = json_array_get(plugins_j, i);
    if (!json_is_object(plugin_j)) {
      fprintf(stderr, "plugin %lu must be a json object\n", i + 1);
      return false;
    }
    const char * path = get_string(plugin_j, "path", NULL);
    if (!path) {
      fprintf(stderr, "plugin %lu must have a path\n", i + 1);
      return false;
    }

    struct plugin_config_t * last = config->last_plugin;
    config->last_plugin = malloc(sizeof(struct plugin_config_t));

    if (last) {
      last->next = config->last_plugin;
    }

    if (!config->plugin_configs) {
      config->plugin_configs = config->last_plugin;
    }

    config->last_plugin->filename = path;
    config->last_plugin->config_context = plugin_j;
    config->last_plugin->next = NULL;
  }

  json_t * listen_addresses_j = json_object_get(root, "listen");
  for (size_t i = 0; i < json_array_size(listen_addresses_j); i++) {
    json_t * address_j = json_array_get(listen_addresses_j, i);
    if (!json_is_object(address_j)) {
      fprintf(stderr, "Plugin %lu must be a JSON object\n", i + 1);
      return false;
    }

    bool secure = true;
    json_t * secure_j = json_object_get(address_j, "secure");
    if (secure_j) {
      secure = json_is_true(secure_j);
    }

    int port = get_int(address_j, "port", secure ? SECURE_SERVER_PORT : CLEARTEXT_SERVER_PORT);
    if (port < 1) {
      fprintf(stderr, "Invalid port for listen address #%lu: %d\n", i + 1, port);
      return false;
    }

    const char * ip_address = get_string(address_j, "ip_address", SERVER_HOSTNAME);

    struct listen_address_t * addr = malloc(sizeof(struct listen_address_t));
    addr->use_tls = secure;
    addr->hostname = ip_address;
    addr->port = port;
    append_address(config, addr);
  }

  return true;
}

#endif

void server_config_args_parse(struct server_config_t * config, int argc, char ** argv)
{
  config->argc = argc;
  config->argv = argv;

  config->config_file = stdin;
  config->address_list = NULL;
  config->num_workers_set = false;
  config->num_workers = 0;
  config->private_key_path = PRIVATE_KEY_FILE_NAME;
  config->certificate_path = CERTIFICATE_FILE_NAME;
  config->last_plugin = NULL;
  config->plugin_configs = NULL;
  config->start_worker = false;
  config->start_daemon = false;
  config->print_help = false;
  config->print_version = false;
  config->h2_protocol_version_string = "h2-14";
  config->h2c_protocol_version_string = "h2c-14";
  config->log_level_string = NULL;
  config->log_path = NULL;

  int c;

  opterr = 0;

  while ((c = getopt(argc, argv, "f:l:p:k:c:w:L:o:adhv")) != -1) {

    switch (c) {
      case 'f': {
#ifdef JANSSON_FOUND
          FILE * fp = fopen(optarg, "r");
          if (fp == NULL) {
            fprintf(stderr, "Unable to open config file: %s\n", optarg);
            exit(EXIT_FAILURE);
          }
          config->config_file = fp;
#else
          fprintf(stderr, "%s was built without the ability to parse config files\n", PROJECT_NAME);
          exit(EXIT_FAILURE);
#endif // JANSSON_FOUND
        break;
      }
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
        struct plugin_config_t * last = config->last_plugin;
        config->last_plugin = malloc(sizeof(struct plugin_config_t));

        if (last) {
          last->next = config->last_plugin;
        }

        if (!config->plugin_configs) {
          config->plugin_configs = config->last_plugin;
        }

        config->last_plugin->filename = optarg;
        config->last_plugin->next = NULL;
        break;
      }

      case 'k': // private Key
        config->private_key_path = optarg;
        break;

      case 'c': // cert file
        config->certificate_path = optarg;
        break;

      case 'w': { // num workers
        char * endptr = NULL;
        config->num_workers = strtol(optarg, &endptr, 10);
        if (*endptr != '\0' || errno == ERANGE) {
          fprintf(stderr, "Invalid number of workers: %s\n", optarg);
          exit(EXIT_FAILURE);
        }
        config->num_workers_set = true;
        break;
      }

      case 'L': { // log level
        config->log_level_string = optarg;
        break;
      }

      case 'o': { // log file
        config->log_path = optarg;
        break;
      }

      case 'a': // accept (start a worker process)
        config->start_worker = true;
        break;

      case 'd': // daemon (start a daemon process)
        config->start_daemon = true;
        break;

      case 'h': // help
        config->print_help = true;
        break;

      case 'v': // version
        config->print_version = true;
        break;

      case '?':
        if (optopt == 'l' || optopt == 'p' || optopt == 'k' || optopt == 'c' ||
            optopt == 'w' || optopt == 'o' || optopt == 'L' || optopt == 'f') {
          fprintf(stderr, "Option -%c requires an argument.\n", optopt);
          exit(EXIT_FAILURE);
        } else if (isprint(optopt)) {
          fprintf(stderr, "Unknown option `-%c'.\n", optopt);
          exit(EXIT_FAILURE);
        } else {
          fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
          exit(EXIT_FAILURE);
        }
        break;

      default:
        abort();
    }
  }

#ifdef JANSSON_FOUND
  if (config->config_file != stdin) {
    if (!parse_config_file(config)) {
      fprintf(stderr, "Unable to parse config file\n");
      exit(EXIT_FAILURE);
    }
  } else {
    config->json_root = NULL;
  }
#endif // JANSSON_FOUND

  if (config->log_path && strcmp(config->log_path, "-") != 0) {
    FILE * fp = fopen(config->log_path, "a");
    if (fp == NULL) {
      fprintf(stderr, "Unable to open log file for appending: %s\n", config->log_path);
      exit(EXIT_FAILURE);
    }
    setvbuf(fp, LOG_BUFFER, _IOLBF, LOG_BUFFER_LENGTH);
    config->log_file = fp;
  } else {
    config->log_file = stdout;
  }

  if (config->log_level_string) {
    enum log_level_e level = log_level_from_string(config->log_level_string);
    if (level > 0) {
      config->default_log_level = level;
    } else {
      fprintf(stderr, "Invalid log level: %s\n", config->log_level_string);
      exit(EXIT_FAILURE);
    }
  } else {
    config->default_log_level = DEFAULT_LOG_LEVEL;
  }

  if (!config->num_workers_set) {
    // set default number of workers to the number of cpus
    uv_cpu_info_t * cpu_infos;
    int count;
    int r = uv_cpu_info(&cpu_infos, &count);
    if (r < 0) {
      fprintf(stderr, "Unable to determine number of processors: %s\n", uv_strerror(r));
      exit(EXIT_FAILURE);
    }
    config->num_workers = count;
    uv_free_cpu_info(cpu_infos, count);
  }

  if (config->address_list == NULL) {
    struct listen_address_t * addr = malloc(sizeof(struct listen_address_t));
    addr->use_tls = USE_TLS;
    addr->hostname = SERVER_HOSTNAME;
    addr->port = SECURE_SERVER_PORT;
    append_address(config, addr);
  }

}

const char * server_config_plugin_get_string(void * config_context, char * key)
{
#ifdef JANSSON_FOUND
  json_t * context = config_context;
  json_t * context_j = json_object_get(context, key);
  if (context_j) {
    return json_string_value(context_j);
  }
#endif
  return NULL;
}

struct string_list_t * server_config_plugin_get_strings(void * config_context)
{
#ifdef JANSSON_FOUND
  json_t * context = config_context;

  struct string_list_t * l = malloc(sizeof(struct string_list_t));
  l->num_strings = json_array_size(context);
  l->strings = malloc(sizeof(char *) * l->num_strings);

  size_t index;
  json_t * value;
  json_array_foreach(context, index, value) {
    l->strings[index] = (char *) json_string_value(value);
  }

  return l;
#else
  return NULL;
#endif
}

void * server_config_plugin_get(void * config_context, char * key)
{
#ifdef JANSSON_FOUND
  json_t * context = config_context;
  json_t * context_j = json_object_get(context, key);
  return context_j;
#else
  return NULL;
#endif
}

void server_config_plugin_each(void * context, void * config_context, plugin_config_iterator iter)
{
#ifdef JANSSON_FOUND
  json_t * context_j = config_context;

  const char * key;
  json_t * value;
  json_object_foreach(context_j, key, value) {
    iter(context, key, value);
  }
#endif
}

void server_config_free(struct server_config_t * config)
{
#ifdef JANSSON_FOUND
  if (config->json_root) {
    json_decref(config->json_root);
  }
#endif
}

