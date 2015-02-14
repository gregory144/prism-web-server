#include "config.h"

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "util.h"
#include "binary_buffer.h"

#include "h2/h2.h"
#include "h1_1/h1_1.h"

#include "http.h"
#include "request.h"
#include "response.h"

#define MAX_DETECT_LENGTH 4096

static bool http_internal_write_cb(void * data, uint8_t * buf, size_t len)
{
  http_connection_t * connection = data;

  return connection->writer(connection->data, buf, len);
}

static bool http_internal_write_error_cb(void * data, http_response_t * response, int http_status)
{
  UNUSED(data);

  return http_response_write_error(response, http_status);
}

static void http_connection_close(http_connection_t * connection)
{
  if (!connection->closed) {
    connection->closer(connection->data);
    connection->closed = true;
  }
}

static void http_internal_close_cb(void * data)
{
  http_connection_t * connection = data;

  http_connection_close(connection);
}

static http_request_t * http_internal_request_init_cb(void * data, void * req_user_data, header_list_t * headers)
{
  http_connection_t * connection = data;
  http_request_data_t * req_data = malloc(sizeof(http_request_data_t));
  req_data->connection = connection;
  req_data->data = req_user_data;
  return http_request_init(req_data, connection->log, headers);
}

static void set_protocol_h2(http_connection_t * connection)
{
  connection->protocol = H2;
  connection->handler = h2_init(connection, connection->log, connection->hpack_log, connection->tls_version,
                                connection->cipher, connection->cipher_key_size_in_bits,
                                connection->plugin_invoker, http_internal_write_cb,
                                http_internal_close_cb, http_internal_request_init_cb);
}

static bool send_upgrade_response(http_connection_t * connection)
{
  size_t resp_capacity = 128;
  char resp[resp_capacity];
  int r = snprintf(resp, resp_capacity,
      "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: %s\r\n\r\n",
      connection->h2c_protocol_version_string);
  if (r < 0) {
    log_append(connection->log, LOG_DEBUG, "Error generating upgrade response: %d", r);
    return false;
  } else if (r > resp_capacity) {
    log_append(connection->log, LOG_DEBUG, "Not enough buffer to gernerate upgrade request: %d", r);
    return false;
  }
  size_t resp_length = r;

  return connection->writer(connection->data, (uint8_t *) resp, resp_length);
}

static bool http_internal_upgrade_cb(void * data, char * settings_base64, header_list_t * headers, uint8_t * buffer,
                                     size_t buffer_length)
{
  http_connection_t * connection = data;

  h1_1_t * h1_1_handler = connection->handler;

  set_protocol_h2(connection);
  h2_t * h2_handler = connection->handler;

  if (!send_upgrade_response(connection)) {
    return false;
  }

  if (!h2_settings_apply(h2_handler, settings_base64)) {
    return false;
  }

  bool result = h2_request_begin(h2_handler, headers, buffer, buffer_length);
  h1_1_handler->headers = NULL;

  h1_1_free(h1_1_handler);

  return result;
}

static void set_protocol_h1_1(http_connection_t * connection)
{
  connection->protocol = H1_1;
  connection->handler = h1_1_init(connection, connection->log, connection->use_tls, connection->hostname,
                                  connection->port, connection->h2c_protocol_version_string,
                                  connection->plugin_invoker, http_internal_write_cb,
                                  http_internal_write_error_cb, http_internal_close_cb,
                                  http_internal_request_init_cb, http_internal_upgrade_cb);
}

http_connection_t * http_connection_init(void * const data, struct log_context_t * log,
    struct log_context_t * hpack_log, const char * h2_protocol_version_string,
    const char * h2c_protocol_version_string, struct plugin_invoker_t * plugin_invoker,
    const write_cb writer, const close_cb closer)
{
  http_connection_t * connection = malloc(sizeof(http_connection_t));
  ASSERT_OR_RETURN_NULL(connection);

  connection->data = data;
  connection->log = log;
  connection->hpack_log = hpack_log;

  connection->h2_protocol_version_string = h2_protocol_version_string;
  connection->h2c_protocol_version_string = h2c_protocol_version_string;
  connection->use_tls = false;
  connection->hostname = NULL;
  connection->port = -1;

  connection->plugin_invoker = plugin_invoker;
  connection->writer = writer;
  connection->closer = closer;

  connection->protocol = NOT_SELECTED;
  connection->buffer = NULL;
  connection->handler = NULL;

  connection->tls_version = NULL;
  connection->cipher = NULL;
  connection->cipher_key_size_in_bits = -1;

  connection->closed = false;

  return connection;
}

void http_connection_set_details(http_connection_t * const connection, const bool use_tls,
    const char * hostname, const int port)
{
  connection->use_tls = use_tls;
  connection->hostname = hostname;
  connection->port = port;
}

void http_connection_set_protocol(http_connection_t * const connection, const char * selected_protocol)
{
  log_append(connection->log, LOG_DEBUG, "Selecting protocol: %s", selected_protocol);

  if (selected_protocol) {
    if (strcmp(selected_protocol, connection->h2_protocol_version_string) == 0) {
      log_append(connection->log, LOG_DEBUG, "Selected 2.0");
      set_protocol_h2(connection);
    } else if (strcmp(selected_protocol, "http/1.1") == 0) {
      log_append(connection->log, LOG_DEBUG, "Selected 1.1");
      set_protocol_h1_1(connection);
    } else if (strcmp(selected_protocol, "http/1.0") == 0) {
      log_append(connection->log, LOG_DEBUG, "Selected 1.0");
      set_protocol_h1_1(connection);
    }
  }
}

void http_connection_set_tls_details(http_connection_t * const connection, const char * tls_version,
                                     const char * cipher, const int cipher_key_size_in_bits)
{
  connection->tls_version = tls_version;
  connection->cipher = cipher;
  connection->cipher_key_size_in_bits = cipher_key_size_in_bits;;
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

  if (connection->buffer) {
    binary_buffer_free(connection->buffer);
    free(connection->buffer);
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

/**
 * Detects the protocol of the data in the given buffer and Sets connection->protocol.
 *
 * Returns false if the protocol could not be detected and getting more data will not help.
 */
static bool detect_protocol(http_connection_t * connection, uint8_t * const buffer, const size_t len)
{
  uint8_t * full_buffer = buffer;
  size_t full_buffer_length = len;
  bool fail_hard = false;

  if (connection->buffer) {
    // if we've already tried to detect the protocol, but it failed because it didn't
    // have enough data, append the input to the previous data and retry
    binary_buffer_write(connection->buffer, buffer, len);

    full_buffer = binary_buffer_start(connection->buffer);
    full_buffer_length = binary_buffer_size(connection->buffer);

    // if, the data length exceeds MAX_DETECT_LENGTH, give up
    // (to prevent DoS attacks)
    if (full_buffer_length > MAX_DETECT_LENGTH) {
      fail_hard = true;
    }
  }

  bool detected = false;
  bool h2_failed = false;
  bool h1_1_failed = false;

  enum h2_detect_result_e h2_result = h2_detect_connection(full_buffer, full_buffer_length);
  if (h2_result == H2_DETECT_SUCCESS) {
    set_protocol_h2(connection);
    detected = true;
  } else if (h2_result == H2_DETECT_FAILED) {
    h2_failed = true;
  }

  if (!detected) {
    enum h1_1_detect_result_e h1_1_result = h1_1_detect_connection(full_buffer, full_buffer_length);
    if (h1_1_result == H1_1_DETECT_SUCCESS) {
      set_protocol_h1_1(connection);
      detected = true;
    } else if (h1_1_result == H1_1_DETECT_FAILED) {
      h1_1_failed = true;
    }
  }

  if (h2_failed && h1_1_failed) {
    // we could not detect either an h2 or h1_1 connection
    return false;
  } else if (!detected) {
    if (fail_hard) {
      // fail if we've read a lot of data and still can't detect
      // the protocol
      return false;
    }

    // remember the existing data so we can use it to
    // recheck in the next read
    if (connection->buffer == NULL) {
      connection->buffer = malloc(sizeof(binary_buffer_t));
      binary_buffer_init(connection->buffer, len);

      binary_buffer_write(connection->buffer, buffer, len);
    }
  }

  return true;
}

/**
 * Reads the given buffer and acts on it. Caller must give up ownership of the
 * buffer.
 */
void http_connection_read(http_connection_t * const connection, uint8_t * const buffer, const size_t len)
{
  uint8_t * read_buffer = buffer;
  size_t read_buffer_length = len;

  if (connection->protocol == NOT_SELECTED) {
    // auto select protocol
    if (!detect_protocol(connection, buffer, len)) {
      log_append(connection->log, LOG_ERROR, "Unrecognized protocol");
      free(buffer);
      http_connection_close(connection);
      return;
    } else if (connection->buffer) {
      log_append(connection->log, LOG_TRACE, "Could not detect protocol, need more data");
      free(buffer);

      read_buffer_length = binary_buffer_size(connection->buffer);
      read_buffer = malloc(read_buffer_length);
      memcpy(read_buffer, binary_buffer_start(connection->buffer), read_buffer_length);
    }
  }

  switch (connection->protocol) {
    case NOT_SELECTED:
      log_append(connection->log, LOG_TRACE, "Protocol not selected");
      free(read_buffer);
      break;

    case H2:
      h2_read((h2_t *) connection->handler, read_buffer, read_buffer_length);
      break;

    case H1_1:
      h1_1_read((h1_1_t *) connection->handler, read_buffer, read_buffer_length);
      break;

    default:
      abort();
  }
}

void http_connection_eof(http_connection_t * const connection)
{
  switch (connection->protocol) {
    case NOT_SELECTED:
      log_append(connection->log, LOG_TRACE, "EOF but protocol not selected");
      http_connection_close(connection);
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

void http_connection_shutdown(http_connection_t * const connection)
{
  switch (connection->protocol) {
    case NOT_SELECTED:
      log_append(connection->log, LOG_TRACE, "Shutdown but protocol not selected");
      http_connection_close(connection);
      return;

    case H2:
      h2_shutdown((h2_t *) connection->handler);
      break;

    case H1_1:
      h1_1_shutdown((h1_1_t *) connection->handler);
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
  snprintf(content_length_s, 255, "%zu", content_length);
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

bool http_push_promise(http_request_t * const pushed_request)
{
  http_request_data_t * req_data = pushed_request->handler_data;
  void * data = req_data->data;
  http_connection_t * connection = req_data->connection;

  switch (connection->protocol) {
    case H2:
      return h2_push_promise((h2_stream_t *) data, pushed_request);

    case H1_1:
      return h1_1_push_promise((h1_1_t *) data, pushed_request);

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

