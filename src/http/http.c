#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "../config.h"

#include "util.h"
#include "binary_buffer.h"

#include "h2/h2.h"

#include "http.h"
#include "request.h"
#include "response.h"

#define MAX_CONNECTION_BUFFER_SIZE 0x1000000 // 2^24

void http_request_cb(void * data, http_request_t * request, http_response_t * response)
{
  http_connection_t * connection = data;

  connection->request_handler(connection->data, request, response);
}

void http_data_cb(void * data, http_request_t * request, http_response_t * response, uint8_t * buf,
    size_t len, bool last, bool free_buf)
{
  http_connection_t * connection = data;

  connection->data_handler(connection->data, request, response, buf, len, last, free_buf);
}

bool http_write_cb(void * data, uint8_t * buf, size_t len)
{
  http_connection_t * connection = data;

  return connection->writer(connection->data, buf, len);
}

void http_close_cb(void * data)
{
  http_connection_t * connection = data;

  connection->closer(connection->data);
}

http_request_t * http_request_init_cb(void * data, void * req_user_data, header_list_t * headers)
{
  http_request_data_t * req_data = malloc(sizeof(http_request_data_t));
  req_data->connection = data;
  req_data->data = req_user_data;
  return http_request_init(req_data, headers);
}

http_connection_t * http_connection_init(void * const data, const request_cb request_handler,
    const data_cb data_handler, const write_cb writer, const close_cb closer)
{
  http_connection_t * connection = malloc(sizeof(http_connection_t));
  ASSERT_OR_RETURN_NULL(connection);

  connection->data = data;

  connection->request_handler = request_handler;
  connection->data_handler = data_handler;
  connection->writer = writer;
  connection->closer = closer;

  connection->closing = false;
  connection->closed = false;

  connection->buffer = NULL;
  connection->buffer_length = 0;
  connection->buffer_position = 0;

  connection->write_buffer = binary_buffer_init(NULL, 0);
  if (!connection->write_buffer) {
    http_connection_free(connection);
    return NULL;
  }

  connection->num_requests = 0;

  connection->protocol = H2;
  connection->handler = h2_init(connection, http_request_cb, http_data_cb, http_write_cb, http_close_cb, http_request_init_cb);

  return connection;
}

void http_connection_free(http_connection_t * const connection)
{
  binary_buffer_free(connection->write_buffer);

  if (connection->protocol == H2) {
    h2_free((h2_t *) connection->handler);
  }

  free(connection);
}

void http_finished_writes(http_connection_t * const connection)
{
  if (connection->protocol == H2) {
    h2_finished_writes((h2_t *) connection->handler);
  } else {
    abort();
  }
}

/**
 * Reads the given buffer and acts on it. Caller must give up ownership of the
 * buffer.
 */
void http_connection_read(http_connection_t * const connection, uint8_t * const buffer, const size_t len)
{
  if (connection->protocol == H2) {
    h2_read((h2_t *) connection->handler, buffer, len);
  } else {
    abort();
  }
}

void http_connection_eof(http_connection_t * const connection)
{
  if (connection->protocol == H2) {
    h2_eof((h2_t *) connection->handler);
  } else {
    abort();
  }
}

bool http_response_write(http_response_t * const response, uint8_t * data, const size_t data_length, bool last)
{
  http_request_data_t * req_data = response->request->handler_data;
  void * anon_data = req_data->data;
  http_connection_t * connection = req_data->connection;

  if (connection->protocol == H2) {
    return h2_response_write((h2_stream_t *) anon_data, response, data, data_length, last);
  } else {
    abort();
  }
}

bool http_response_write_data(http_response_t * const response, uint8_t * data, const size_t data_length, bool last)
{
  http_request_data_t * req_data = response->request->handler_data;
  void * anon_data = req_data->data;
  http_connection_t * connection = req_data->connection;

  if (connection->protocol == H2) {
    return h2_response_write_data((h2_stream_t *) anon_data, response, data, data_length, last);
  } else {
    abort();
  }
}

bool http_response_write_error(http_response_t * const response, int code)
{
  http_response_status_set(response, code);

  char * resp_text = malloc(32);
  snprintf(resp_text, 32, "Error: %d\n", code);
  size_t content_length = strlen(resp_text);

  char content_length_s[256];
  snprintf(content_length_s, 255, "%ld", content_length);
  http_response_header_add(response, "content-length", content_length_s);

  http_response_header_add(response, "content-type", "text/html");
  http_response_header_add(response, "server", PACKAGE_STRING);

  size_t date_buf_length = RFC1123_TIME_LEN + 1;
  char date_buf[date_buf_length];
  char * date = current_date_rfc1123(date_buf, date_buf_length);

  if (date) {
    http_response_header_add(response, "date", date);
  }

  return http_response_write(response, (uint8_t *) resp_text, content_length, true);
}

http_request_t * http_push_init(http_request_t * const original_request)
{
  http_request_data_t * req_data = original_request->handler_data;
  void * data = req_data->data;
  http_connection_t * connection = req_data->connection;

  if (connection->protocol == H2) {
    return h2_push_init((h2_stream_t *) data, original_request);
  } else {
    abort();
  }
}

bool http_push_promise(http_request_t * const request)
{
  http_request_data_t * req_data = request->handler_data;
  void * data = req_data->data;
  http_connection_t * connection = req_data->connection;

  if (connection->protocol == H2) {
    return h2_push_promise((h2_stream_t *) data, request);
  } else {
    abort();
  }
}

http_response_t * http_push_response_get(http_request_t * const request)
{
  http_request_data_t * req_data = request->handler_data;
  void * data = req_data->data;
  http_connection_t * connection = req_data->connection;

  if (connection->protocol == H2) {
    return h2_push_response_get((h2_stream_t *) data, request);
  } else {
    abort();
  }
}

