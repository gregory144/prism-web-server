#ifndef HTTP_SERVER_CONFIG_H
#define HTTP_SERVER_CONFIG_H

#include <uv.h>

#include "util/log.h"

// TODO - namespace these defines
#define USE_TLS true
#define MIN_PORT 1
#define MAX_PORT 0xFFFF
#define SERVER_HOSTNAME "0.0.0.0"
#define SERVER_PORT 8443
#define DEFAULT_LOG_LEVEL LOG_WARN
#define PRIVATE_KEY_FILE_NAME "key.pem"
#define CERTIFICATE_FILE_NAME "cert.pem"

struct plugin_config_t {

  char * filename;

  struct plugin_config_t * next;

};

struct listen_address_t {

  struct listen_address_t * next;
  void * data;
  size_t index;

  bool use_tls;
  char * hostname;
  long port;

};

struct server_config_t {

  int argc;
  char ** argv;

  const char * h2_protocol_version_string;
  const char * h2c_protocol_version_string;

  struct listen_address_t * address_list;

  bool start_worker;
  bool start_daemon;
  bool print_help;
  bool print_version;

  size_t num_workers;

  char * cert_file;
  char * private_key_file;

  struct plugin_config_t * plugin_configs;

  enum log_level_e default_log_level;

  FILE * log_file;
  struct log_context_t server_log;
  struct log_context_t worker_log;
  struct log_context_t wire_log;
  struct log_context_t data_log;
  struct log_context_t http_log;
  struct log_context_t hpack_log;
  struct log_context_t tls_log;
  struct log_context_t plugin_log;

};

void server_config_args_parse(struct server_config_t * config, int argc, char ** argv);

#endif
