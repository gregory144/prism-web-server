#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "../config.h"

#include "util.h"
#include "binary_buffer.h"

#include "h2/h2.h"
#include "h1_1/h1_1.h"

#include "http.h"
#include "request.h"
#include "response.h"

#define MAX_CONNECTION_BUFFER_SIZE 0x1000000 // 2^24

static void http_internal_request_cb(void * data, http_request_t * request, http_response_t * response)
{
  http_connection_t * connection = data;

  connection->request_handler(connection->data, request, response);
}

static void http_internal_data_cb(void * data, http_request_t * request, http_response_t * response, uint8_t * buf,
                                  size_t len, bool last, bool free_buf)
{
  http_connection_t * connection = data;

  connection->data_handler(connection->data, request, response, buf, len, last, free_buf);
}

static bool http_internal_write_cb(void * data, uint8_t * buf, size_t len)
{
  http_connection_t * connection = data;

  return connection->writer(connection->data, buf, len);
}

static void http_internal_close_cb(void * data)
{
  http_connection_t * connection = data;

  connection->closer(connection->data);
}

static http_request_t * http_internal_request_init_cb(void * data, void * req_user_data, header_list_t * headers)
{
  http_request_data_t * req_data = malloc(sizeof(http_request_data_t));
  req_data->connection = data;
  req_data->data = req_user_data;
  return http_request_init(req_data, headers);
}

static void set_protocol_h2(http_connection_t * connection)
{
  connection->protocol = H2;
  connection->handler = h2_init(connection, http_internal_request_cb, http_internal_data_cb,
                                http_internal_write_cb, http_internal_close_cb, http_internal_request_init_cb);
}

static bool send_upgrade_response(http_connection_t * connection)
{
  char * resp = "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c-14\r\n\r\n";
  size_t resp_length = strlen(resp);

  return connection->writer(connection->data, (uint8_t *) resp, resp_length);
}

static bool http_internal_upgrade_cb(void * data, char * settings_base64, header_list_t * headers, uint8_t * buffer, size_t buffer_length)
{
  http_connection_t * connection = data;

  h1_1_t * h1_1_handler = connection->handler;

  set_protocol_h2(connection);
  h2_t * h2_handler = connection->handler;

  if (!h2_settings_apply(h2_handler, settings_base64)) {
    return false;
  }

  if (!send_upgrade_response(connection)) {
    return false;
  }

  bool result = h2_request_begin(h2_handler, headers, buffer, buffer_length);

  h1_1_free(h1_1_handler);

  return result;
}

static void set_protocol_h1_1(http_connection_t * connection)
{
  connection->protocol = H1_1;
  connection->handler = h1_1_init(connection, connection->scheme, connection->hostname, connection->port,
      http_internal_request_cb, http_internal_data_cb, http_internal_write_cb, http_internal_close_cb,
      http_internal_request_init_cb, http_internal_upgrade_cb);
}

http_connection_t * http_connection_init(void * const data, const char * scheme, const char * hostname, const int port,
    const request_cb request_handler, const data_cb data_handler, const write_cb writer, const close_cb closer)
{
  http_connection_t * connection = malloc(sizeof(http_connection_t));
  ASSERT_OR_RETURN_NULL(connection);

  connection->data = data;

  connection->scheme = scheme;
  connection->hostname = hostname;
  connection->port = port;

  connection->request_handler = request_handler;
  connection->data_handler = data_handler;
  connection->writer = writer;
  connection->closer = closer;

  connection->protocol = NOT_SELECTED;
  connection->handler = NULL;

  return connection;
}

void http_connection_set_protocol(http_connection_t * const connection, const char * selected_protocol)
{
  log_debug("Selecting protocol: %s", selected_protocol);

  if (selected_protocol) {
    if (strcmp(selected_protocol, "h2-14") == 0) {
      log_debug("Selected 2.0");
      set_protocol_h2(connection);
    } else if (strcmp(selected_protocol, "http/1.1") == 0) {
      log_debug("Selected 1.1");
      set_protocol_h1_1(connection);
    } else if (strcmp(selected_protocol, "http/1.0") == 0) {
      log_debug("Selected 1.0");
      set_protocol_h1_1(connection);
    }
  }
}

void http_connection_free(http_connection_t * const connection)
{
  switch (connection->protocol) {
    case NOT_SELECTED:
      // ignore
      break;

    case H2:
      h2_free((h2_t *) connection->handler);
      break;

    case H1_1:
      h1_1_free((h1_1_t *) connection->handler);
      break;

    default:
      abort();
  }

  free(connection);
}

void http_finished_writes(http_connection_t * const connection)
{
  switch (connection->protocol) {
    case NOT_SELECTED:
      // ignore - it might be during handshake where a protocol hasn't been selected yet
      return;

    case H2:
      h2_finished_writes((h2_t *) connection->handler);
      break;

    case H1_1:
      h1_1_finished_writes((h1_1_t *) connection->handler);
      break;

    default:
      abort();
  }
}

static void detect_protocol(http_connection_t * connection, uint8_t * const buffer, const size_t len)
{
  if (h2_detect_connection(buffer, len)) {
    set_protocol_h2(connection);
  } else if (h1_1_detect_connection(buffer, len)) {
    set_protocol_h1_1(connection);
  }
}

/**
 * Reads the given buffer and acts on it. Caller must give up ownership of the
 * buffer.
 */
void http_connection_read(http_connection_t * const connection, uint8_t * const buffer, const size_t len)
{
  if (connection->protocol == NOT_SELECTED) {
    // auto select protocol
    detect_protocol(connection, buffer, len);
  }

  switch (connection->protocol) {
    case H2:
      h2_read((h2_t *) connection->handler, buffer, len);
      break;

    case H1_1:
      h1_1_read((h1_1_t *) connection->handler, buffer, len);
      break;

    default:
      abort();
  }
}

void http_connection_eof(http_connection_t * const connection)
{
  switch (connection->protocol) {
    case NOT_SELECTED:
      // ignore - a connection might have failed the handshake
      return;

    case H2:
      h2_eof((h2_t *) connection->handler);
      break;

    case H1_1:
      h1_1_eof((h1_1_t *) connection->handler);
      break;

    default:
      abort();
  }
}

bool http_response_write(http_response_t * const response, uint8_t * data, const size_t data_length, bool last)
{
  http_request_data_t * req_data = response->request->handler_data;
  void * anon_data = req_data->data;
  http_connection_t * connection = req_data->connection;

  switch (connection->protocol) {
    case H2:
      return h2_response_write((h2_stream_t *) anon_data, response, data, data_length, last);

    case H1_1:
      return h1_1_response_write((h1_1_t *) anon_data, response, data, data_length, last);

    default:
      abort();
  }
}

bool http_response_write_data(http_response_t * const response, uint8_t * data, const size_t data_length, bool last)
{
  http_request_data_t * req_data = response->request->handler_data;
  void * anon_data = req_data->data;
  http_connection_t * connection = req_data->connection;

  switch (connection->protocol) {
    case H2:
      return h2_response_write_data((h2_stream_t *) anon_data, response, data, data_length, last);

    case H1_1:
      return h1_1_response_write_data((h1_1_t *) anon_data, response, data, data_length, last);

    default:
      abort();
  }
}

bool http_response_write_error(http_response_t * const response, int code)
{
  http_response_status_set(response, code);

  char * resp_text = malloc(32);
  snprintf(resp_text, 32, "Error: %d\r\n", code);
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

  switch (connection->protocol) {
    case H2:
      return h2_push_init((h2_stream_t *) data, original_request);

    case H1_1:
      return h1_1_push_init((h1_1_t *) data, original_request);

    default:
      abort();
  }
}

bool http_push_promise(http_request_t * const request)
{
  http_request_data_t * req_data = request->handler_data;
  void * data = req_data->data;
  http_connection_t * connection = req_data->connection;

  switch (connection->protocol) {
    case H2:
      return h2_push_promise((h2_stream_t *) data, request);

    case H1_1:
      return h1_1_push_promise((h1_1_t *) data, request);

    default:
      abort();
  }
}

http_response_t * http_push_response_get(http_request_t * const request)
{
  http_request_data_t * req_data = request->handler_data;
  void * data = req_data->data;
  http_connection_t * connection = req_data->connection;

  switch (connection->protocol) {
    case H2:
      return h2_push_response_get((h2_stream_t *) data, request);

    case H1_1:
      return h1_1_push_response_get((h1_1_t *) data, request);

    default:
      abort();
  }
}
