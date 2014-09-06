#ifndef HTTP_HTTP_H
#define HTTP_HTTP_H

#include <stdbool.h>

#include "hash_table.h"
#include "hpack/hpack.h"

#include "request.h"
#include "response.h"

enum http_protocol_e {
  H2
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

  enum http_protocol_e protocol;

  write_cb writer;
  close_cb closer;
  request_cb request_handler;
  data_cb data_handler;

  // is the connection waiting to be gracefully closed?
  bool closing;
  bool closed;

  /**
   * what's currently being read
   */
  uint8_t * buffer;
  size_t buffer_length;
  size_t buffer_position;

  binary_buffer_t * write_buffer;

  size_t num_requests;

  void * handler;

} http_connection_t;

typedef struct {

  void * data;

  http_connection_t * connection;

} http_request_data_t;

http_connection_t * http_connection_init(void * const data, const request_cb request_handler,
    const data_cb data_handler, const write_cb writer, const close_cb closer);

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
