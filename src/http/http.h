#ifndef HTTP_HTTP_H
#define HTTP_HTTP_H

#include <stdbool.h>

#include "hash_table.h"
#include "hpack/hpack.h"

#include "request.h"
#include "response.h"

enum http_protocol_e {
  NOT_SELECTED,
  H2,
  H1_1
};

typedef void (*request_cb)(void * data, http_request_t * request, http_response_t * response);

typedef void (*data_cb)(void * data, http_request_t * request, http_response_t * response, uint8_t * buf,
                        size_t len, bool last, bool free_buf);

typedef bool (*write_cb)(void * data, uint8_t * buf, size_t len);

typedef void (*close_cb)(void * data);

/**
 * Stores state for a client.
 */
typedef struct {

  void * data;

  const char * scheme;
  const char * hostname;
  int port;

  enum http_protocol_e protocol;
  const char * tls_version;
  const char * cipher;
  int cipher_key_size_in_bits;

  write_cb writer;
  close_cb closer;
  request_cb request_handler;
  data_cb data_handler;

  void * handler;

  bool closed;

  binary_buffer_t * buffer;

} http_connection_t;

typedef struct {

  void * data;

  http_connection_t * connection;

} http_request_data_t;

http_connection_t * http_connection_init(void * const data, const char * scheme, const char * hostname, const int port,
    const request_cb request_handler, const data_cb data_handler, const write_cb writer, const close_cb closer);

void http_connection_set_protocol(http_connection_t * const connection, const char * selected_protocol);

void http_connection_set_tls_details(http_connection_t * const connection, const char * tls_version,
                                     const char * cipher, const int key_size_in_bits);

void http_connection_free(http_connection_t * const connection);

void http_connection_read(http_connection_t * const connection, uint8_t * const buffer, const size_t len);

void http_connection_eof(http_connection_t * const connection);

void http_finished_writes(http_connection_t * const connection);

bool http_response_write(http_response_t * const response, uint8_t * data, const size_t data_length, bool last);

bool http_response_write_data(http_response_t * const response, uint8_t * data, const size_t data_length, bool last);

bool http_response_write_error(http_response_t * const response, int code);

http_request_t * http_push_init(http_request_t * const request);

bool http_push_promise(http_request_t * const request);

http_response_t * http_push_response_get(http_request_t * const request);

#endif
