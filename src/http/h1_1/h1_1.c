#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "util.h"

#include "h1_1.h"

static int hp_message_begin_cb(http_parser * http_parser);
static int hp_url_cb(http_parser * http_parser, const char * at, size_t length);
static int hp_header_field_cb(http_parser * http_parser, const char * at, size_t length);
static int hp_header_value_cb(http_parser * http_parser, const char * at, size_t length);
static int hp_headers_complete_cb(http_parser * http_parser);
static int hp_body_cb(http_parser * http_parser, const char * at, size_t length);
static int hp_message_complete_cb(http_parser * http_parser);

static http_parser_settings http_settings = {
  .on_message_begin = hp_message_begin_cb,
  .on_url = hp_url_cb,
  .on_status = NULL, // only for responses
  .on_header_field = hp_header_field_cb,
  .on_header_value = hp_header_value_cb,
  .on_headers_complete = hp_headers_complete_cb,
  .on_body = hp_body_cb,
  .on_message_complete = hp_message_complete_cb,
};

bool h1_1_detect_connection(uint8_t * buffer, size_t buffer_length)
{
  // check for a line that vaguely looks like:
  // GET /path HTTP/1.1\r\n

  char * end_of_line = strpbrk((char *) buffer, "\r\n");

  if (end_of_line == NULL) {
    return false;
  }

  char * first_space = strchr((char *) buffer, ' ');
  char * after_first_space = first_space ? first_space + 1 : NULL;

  if (!after_first_space || after_first_space >= end_of_line) {
    return false;
  }

  char * second_space = strchr(after_first_space, ' ');
  char * after_second_space = second_space ? second_space + 1 : NULL;

  if (!after_second_space || after_second_space >= end_of_line) {
    return false;
  }

  if (((uint8_t *) after_second_space) + 8 >= buffer + buffer_length) {
    return false;
  }

  if (strncasecmp(second_space, "http/1.1", 8) == 0 || strncasecmp(second_space, "http/1.0", 8) == 0) {
    return second_space[8] == '\r' || second_space[8] == '\n';
  }

  return false;
}

h1_1_t * h1_1_init(void * const data, const char * scheme, const char * hostname, const int port, const h1_1_request_cb request_handler,
                   const h1_1_data_cb data_handler, const h1_1_write_cb writer, const h1_1_close_cb closer,
                   const h1_1_request_init_cb request_init, const h1_1_upgrade_cb upgrade_cb)
{
  h1_1_t * h1_1 = malloc(sizeof(h1_1_t));
  ASSERT_OR_RETURN_NULL(h1_1);

  h1_1->data = data;

  h1_1->scheme = scheme;
  h1_1->hostname = hostname;
  h1_1->port = port;

  h1_1->request_handler = request_handler;
  h1_1->data_handler = data_handler;
  h1_1->writer = writer;
  h1_1->closer = closer;
  h1_1->request_init = request_init;
  h1_1->upgrade_cb = upgrade_cb;

  h1_1->closed = false;

  h1_1->upgrade_to_h2 = false;
  h1_1->is_1_1 = true;
  h1_1->keep_alive = false;

  h1_1->write_buffer = binary_buffer_init(NULL, 0);

  if (!h1_1->write_buffer) {
    h1_1_free(h1_1);
    return NULL;
  }

  http_parser_init(&h1_1->http_parser, HTTP_REQUEST);
  h1_1->http_parser.data = h1_1;

  return h1_1;
}

void h1_1_free(h1_1_t * const h1_1)
{
  if (h1_1->write_buffer) {
    binary_buffer_free(h1_1->write_buffer);
  }

  free(h1_1);
}

static void h1_1_close(h1_1_t * const h1_1)
{
  if (h1_1->closed) {
    return;
  }

  h1_1->closer(h1_1->data);
  h1_1->closed = true;
}

void h1_1_finished_writes(h1_1_t * const h1_1)
{
  log_trace("Finished write");
  h1_1_close(h1_1);
}

static int hp_message_begin_cb(http_parser * http_parser)
{
  h1_1_t * h1_1 = http_parser->data;
  h1_1->upgrade_to_h2 = false;

  h1_1->headers = header_list_init(NULL);

  if (!h1_1->headers) {
    return 1; // error
  }

  h1_1->read_field_last = false;
  h1_1->curr_header_field = NULL;
  h1_1->curr_header_field_length = 0;
  h1_1->curr_header_value = NULL;
  h1_1->curr_header_value_length = 0;

  return 0;
}

static int hp_url_cb(http_parser * http_parser, const char * at, size_t length)
{
  h1_1_t * h1_1 = http_parser->data;

  char * value = malloc(length + 1);
  memcpy(value, at, length);
  value[length] = '\0';

  header_list_unshift(h1_1->headers,
                      ":path", 5, false,
                      value, length, true);

  return 0;
}

static void add_header(h1_1_t * h1_1)
{
  header_list_push(h1_1->headers,
                   h1_1->curr_header_field, h1_1->curr_header_field_length, true,
                   h1_1->curr_header_value, h1_1->curr_header_value_length, true
                  );
  h1_1->curr_header_field = NULL;
  h1_1->curr_header_field_length = 0;
  h1_1->curr_header_value = NULL;
  h1_1->curr_header_value_length = 0;
}

static int hp_header_field_cb(http_parser * http_parser, const char * at, size_t length)
{
  h1_1_t * h1_1 = http_parser->data;

  if (h1_1->read_field_last) {
    // reallocate field buffer and append
    size_t old_length = h1_1->curr_header_field_length;
    size_t new_length = old_length + length;
    h1_1->curr_header_field = realloc(h1_1->curr_header_field, new_length);
    memcpy(h1_1->curr_header_field + old_length, at, length);
    h1_1->curr_header_field[new_length] = '\0';
    h1_1->curr_header_field_length = new_length;
  } else {
    if (h1_1->curr_header_field) {
      // this is a new header field
      add_header(h1_1);
    }

    // allocate new field buffer
    h1_1->curr_header_field = malloc(length + 1);
    memcpy(h1_1->curr_header_field, at, length);
    h1_1->curr_header_field[length] = '\0';
    h1_1->curr_header_field_length = length;
  }

  h1_1->read_field_last = true;
  return 0;
}

static int hp_header_value_cb(http_parser * http_parser, const char * at, size_t length)
{
  h1_1_t * h1_1 = http_parser->data;

  if (!h1_1->read_field_last) {
    // reallocate value buffer and append
    size_t old_length = h1_1->curr_header_value_length;
    size_t new_length = old_length + length;
    h1_1->curr_header_value = realloc(h1_1->curr_header_value, new_length);
    memcpy(h1_1->curr_header_value + old_length, at, length);
    h1_1->curr_header_value[new_length] = '\0';
    h1_1->curr_header_value_length = new_length;
  } else {
    // allocate new value buffer
    h1_1->curr_header_value = malloc(length + 1);
    memcpy(h1_1->curr_header_value, at, length);
    h1_1->curr_header_value[length] = '\0';
    h1_1->curr_header_value_length = length;
  }

  h1_1->read_field_last = false;
  return 0;
}

static int hp_headers_complete_cb(http_parser * http_parser)
{
  h1_1_t * h1_1 = http_parser->data;

  h1_1->is_1_1 = http_parser->http_minor == 1;
  h1_1->keep_alive = http_should_keep_alive(http_parser);

  if (h1_1->curr_header_field) {
    add_header(h1_1);
  }

  // add in method, authority and scheme headers
  char * scheme = strdup(h1_1->scheme);
  header_list_unshift(h1_1->headers,
                      ":scheme", 7, false,
                      scheme, strlen(scheme), true);

  const size_t max_int_length = 128;
  size_t authority_length = strlen(h1_1->hostname) + max_int_length + 1;
  char * authority = malloc(authority_length + 1);
  snprintf(authority, authority_length + 1, "%s:%d", h1_1->hostname, h1_1->port);
  header_list_unshift(h1_1->headers,
                      ":authority", 10, false,
                      authority, authority_length, true);

  char * method_str = (char *) http_method_str(http_parser->method);
  header_list_unshift(h1_1->headers,
                      ":method", 7, false,
                      method_str, strlen(method_str), false);

  if (http_parser->upgrade) {
    header_list_linked_field_t * upgrade_header = header_list_get(h1_1->headers, "upgrade", NULL);
    if (!upgrade_header) {
      log_error("Parser indicated upgrade without upgrade header");
      // settings header is required
      h1_1_close(h1_1);
    } else {
      char * protocol = upgrade_header->field.value;
      log_info("Upgrading to %s", protocol);
      if (strncmp("h2c-14", protocol, 6) == 0) {
        h1_1->upgrade_to_h2 = true;
        // don't try to handle the response yet - it'll get passed on to the h2 handler
        return 0;
      }
    }
  }

  h1_1->request = h1_1->request_init(h1_1->data, h1_1, h1_1->headers);

  if (!h1_1->request) {
    return 1; // error
  }

  h1_1->response = http_response_init(h1_1->request);

  if (!h1_1->response) {
    return 1; // error
  }

  h1_1->request_handler(h1_1->data, h1_1->request, h1_1->response);

  return 0;
}

static int hp_body_cb(http_parser * http_parser, const char * at, size_t length)
{
  h1_1_t * h1_1 = http_parser->data;
  if (h1_1->upgrade_to_h2) {
    // don't try to handle the response yet - it'll get passed on to the h2 handler
    return 0;
  }

  h1_1->data_handler(h1_1->data, h1_1->request, h1_1->response, (uint8_t *) at, length, false, false);

  return 0;
}

static int hp_message_complete_cb(http_parser * http_parser)
{
  h1_1_t * h1_1 = http_parser->data;
  if (h1_1->upgrade_to_h2) {
    // don't try to handle the response yet - it'll get passed on to the h2 handler
    return 0;
  }

  // the request may have already been handled
  if (h1_1->request) {
    h1_1->data_handler(h1_1->data, h1_1->request, h1_1->response, NULL, 0, true, false);
  }

  return 0;
}

static void h1_1_parse(h1_1_t * const h1_1, uint8_t * const buffer, const size_t len)
{
  size_t ret = http_parser_execute(&h1_1->http_parser, &http_settings, (char *) buffer, len);

  if (h1_1->upgrade_to_h2) {
    // TODO spec requires 1 and only 1 settings header
    header_list_linked_field_t * settings_header = header_list_get(h1_1->headers, "http2-settings", NULL);
    if (!settings_header) {
      log_error("Tried to upgrade without settings header");
      // settings header is required
      h1_1_close(h1_1);
    } else {
      header_field_t * field = &settings_header->field;
      char * settings = field->value;
      log_info("Upgrading to h2: %s", settings);
      uint8_t * http2_buf_begin = buffer + ret;
      size_t buf_length = len - ret;
      h1_1->upgrade_cb(h1_1->data, settings, h1_1->headers, http2_buf_begin, buf_length);
    }
  } else if (ret != len) {

    enum http_errno err = h1_1->http_parser.http_errno;

    if (err != HPE_OK) {
      log_error("Error parsing HTTP1 request: %s", http_errno_description(err));
    } else {
      log_error("Could not process all of buffer: %ld / %ld", ret, len);
    }

    h1_1_close(h1_1);
  }
}

/**
 * Reads the given buffer and acts on it. Caller must give up ownership of the
 * buffer.
 */
void h1_1_read(h1_1_t * const h1_1, uint8_t * const buffer, const size_t len)
{
  h1_1_parse(h1_1, buffer, len);

  free(buffer);
}

void h1_1_eof(h1_1_t * const h1_1)
{
  h1_1_parse(h1_1, NULL, 0);
}

static void finish_response(h1_1_t * h1_1)
{
  if (!h1_1->keep_alive) {
    h1_1_close(h1_1);
  }

  http_response_free(h1_1->response);
  h1_1->response = NULL;
  h1_1->request = NULL;
}

bool h1_1_response_write(h1_1_t * h1_1, http_response_t * const response, uint8_t * data, const size_t data_length,
                         bool last)
{
  binary_buffer_reset(h1_1->write_buffer, 0);

  char status_line[256];
  snprintf(status_line, 256, "HTTP/1.%d %d \r\n", h1_1->is_1_1 ? 1 : 0, response->status);
  binary_buffer_write(h1_1->write_buffer, (uint8_t *) &status_line, strlen(status_line));

  header_list_iter_t iter;
  header_list_iterator_init(&iter, response->headers);

  while (header_list_iterate(&iter)) {
    char * name = iter.field->name;
    size_t name_length = iter.field->name_length;
    char * value = iter.field->value;
    size_t value_length = iter.field->value_length;

    size_t header_length = name_length + 2 + value_length + 2;
    char header_line[header_length + 1];
    snprintf(header_line, header_length + 1, "%s: %s\r\n", name, value);
    binary_buffer_write(h1_1->write_buffer, (uint8_t *) &header_line, header_length);
  }

  char * connection_header = "connection: close\r\n";
  if (h1_1->keep_alive) {
    connection_header = "connection: keep-alive\r\n";
  }

  binary_buffer_write(h1_1->write_buffer, (uint8_t *) connection_header, strlen(connection_header));

  // extra newline to separate headers from body
  binary_buffer_write(h1_1->write_buffer, (uint8_t *) "\r\n", 2);

  if (data) {
    binary_buffer_write(h1_1->write_buffer, data, data_length);
    free(data);
  }

  h1_1->writer(h1_1->data, binary_buffer_start(h1_1->write_buffer), binary_buffer_size(h1_1->write_buffer));

  if (last) {
    finish_response(h1_1);
  }

  return true;
}

bool h1_1_response_write_data(h1_1_t * h1_1, http_response_t * const response, uint8_t * data, const size_t data_length,
                              bool last)
{
  if (data) {
    h1_1->writer(h1_1->data, data, data_length);
    free(data);
  }

  UNUSED(response);
  UNUSED(last);

  if (last) {
    finish_response(h1_1);
  }

  return true;
}

http_request_t * h1_1_push_init(h1_1_t * h1_1, http_request_t * const original_request)
{
  UNUSED(h1_1);
  UNUSED(original_request);

  return NULL;
}

bool h1_1_push_promise(h1_1_t * h1_1, http_request_t * const request)
{
  UNUSED(h1_1);
  UNUSED(request);

  return false;
}

http_response_t * h1_1_push_response_get(h1_1_t * h1_1, http_request_t * const request)
{
  UNUSED(h1_1);
  UNUSED(request);

  return false;
}
