#ifndef H1_1_H
#define H1_1_H

#include <stdbool.h>

#include "http/request.h"
#include "http/response.h"

#include "plugin_callbacks.h"

#include "http_parser.h"

typedef bool (*h1_1_write_cb)(void * data, uint8_t * buf, size_t len);

typedef bool (*h1_1_write_error_cb)(void * data, http_response_t * response, int http_status);

typedef void (*h1_1_close_cb)(void * data);

typedef http_request_t * (*h1_1_request_init_cb)(void * data, void * user_data, header_list_t * headers);

typedef bool (*h1_1_upgrade_cb)(void * data, char * settings_base64, header_list_t * headers, uint8_t * buffer,
                                size_t buffer_length);

typedef struct {

  void * data;

  log_context_t * log;

  bool use_tls;
  const char * hostname;
  int port;

  h1_1_write_cb writer;
  h1_1_write_error_cb error_writer;
  h1_1_close_cb closer;
  struct plugin_invoker_t * plugin_invoker;
  h1_1_request_init_cb request_init;
  h1_1_upgrade_cb upgrade_cb;

  /**
   * connection state
   */
  bool closed;
  bool is_1_1; // vs 1.0
  bool upgrade_to_h2;
  const char * h2c_protocol_version_string;

  binary_buffer_t * write_buffer;

  http_parser_settings http_settings;
  http_parser http_parser;

  bool keep_alive;

  /**
   * Current request data
   */
  http_request_t * request;
  http_response_t * response;
  header_list_t * headers;
  // true if the last header callback was the field callback
  bool read_field_last;
  char * curr_header_field;
  size_t curr_header_field_length;
  char * curr_header_value;
  size_t curr_header_value_length;

} h1_1_t;

enum h1_1_detect_result_e {
  H1_1_DETECT_FAILED,
  H1_1_DETECT_SUCCESS,
  H1_1_DETECT_NEED_MORE_DATA
};

/**
 * returns:
 * H1_1_DETECT_FAILED = the connection does not look like valid http/1.1 data
 * H1_1_DETECT_SUCCESS = the connection looks like valid http/1.1 data
 * H1_1_DETECT_NEED_MORE_DATA = we need more data to determine if this is valid http/1.1 data
 */
enum h1_1_detect_result_e h1_1_detect_connection(uint8_t * buffer, size_t len);

h1_1_t * h1_1_init(void * const data, log_context_t * log, bool use_tls, const char * hostname,
                   const int port, const char * h2c_protocol_version_string,
                   struct plugin_invoker_t * plugin_invoker, const h1_1_write_cb writer,
                   const h1_1_write_error_cb error_writer, const h1_1_close_cb closer,
                   const h1_1_request_init_cb request_init, const h1_1_upgrade_cb upgrade_cb);

void h1_1_free(h1_1_t * const h1_1);

void h1_1_read(h1_1_t * const h1_1, uint8_t * const buffer, const size_t len);

void h1_1_eof(h1_1_t * const h1_1);

void h1_1_shutdown(h1_1_t * const h1_1);

void h1_1_finished_writes(h1_1_t * const h1_1);

bool h1_1_response_write(h1_1_t * h1_1, http_response_t * const response, uint8_t * data, const size_t data_length,
                         bool last);

bool h1_1_response_write_data(h1_1_t * h1_1, http_response_t * const response, uint8_t * data, const size_t data_length,
                              bool last);

http_request_t * h1_1_push_init(h1_1_t * h1_1, http_request_t * const request);

bool h1_1_push_promise(h1_1_t * h1_1, http_request_t * const request);

http_response_t * h1_1_push_response_get(h1_1_t * h1_1, http_request_t * const request);

#endif
