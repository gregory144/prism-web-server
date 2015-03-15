#ifndef HTTP_SERVER_CONFIG_H
#define HTTP_SERVER_CONFIG_H

#include <uv.h>

#include "util/log.h"

#ifdef JANSSON_FOUND
#include <jansson.h>
#endif

// TODO - namespace these defines
#define USE_TLS true
#define MIN_PORT 1
#define MAX_PORT 0xFFFF
#define SERVER_HOSTNAME "0.0.0.0"
#define SECURE_SERVER_PORT 8443
#define CLEARTEXT_SERVER_PORT 8080
#define DEFAULT_LOG_LEVEL LOG_WARN
#define PRIVATE_KEY_FILE_NAME "key.pem"
#define CERTIFICATE_FILE_NAME "cert.pem"

struct plugin_config_t {

  const char * filename;

  void * config_context;

  struct plugin_config_t * next;

};

struct listen_address_t {

  struct listen_address_t * next;
  void * data;
  size_t index;

  bool use_tls;
  const char * hostname;
  long port;

};

struct server_config_t {

  int argc;
  char ** argv;

  FILE * config_file;

#ifdef JANSSON_FOUND
  json_t * json_root;
#endif

  const char * h2_protocol_version_string;
  const char * h2c_protocol_version_string;

  struct listen_address_t * address_list;

  bool start_worker;
  bool start_daemon;
  bool print_help;
  bool print_version;

  bool num_workers_set;
  size_t num_workers;

  const char * certificate_path;
  const char * private_key_path;

  struct plugin_config_t * plugin_configs;
  struct plugin_config_t * last_plugin;

  const char * log_level_string;
  enum log_level_e default_log_level;

  const char * log_path;
  FILE * log_file;
  struct log_context_t server_log;
  struct log_context_t worker_log;
  struct log_context_t data_log;
  struct log_context_t http_log;
  struct log_context_t hpack_log;
  struct log_context_t tls_log;
  struct log_context_t plugin_log;

};

void server_config_args_parse(struct server_config_t * config, int argc, char ** argv);

void server_config_free(struct server_config_t * config);

#endif
