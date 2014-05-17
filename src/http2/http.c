#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "../util/util.h"

#include "http.h"
#include "request.h"
#include "response.h"

#define FRAME_HEADER_SIZE 8 // octets
#define DEFAULT_STREAM_PRIORITY 0x40000000 // 2^30

#define MAX_FRAME_SIZE 0x3FFF // 16,383
#define MAX_WINDOW_SIZE 0x7FFFFFFF // 2^31 - 1

const char * HTTP_CONNECTION_HEADER = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const size_t HTTP_CONNECTION_HEADER_LENGTH = 24;

static void emit_error_and_close(http_connection_t * const connection, uint32_t stream_id, enum h2_error_code_e error_code,
    char * format, ...);

http_connection_t * http_connection_init(void * const data, const request_cb request_handler,
    const write_cb writer, const close_cb closer) {
  http_connection_t * connection = malloc(sizeof(http_connection_t));

  connection->data = data;
  connection->writer = writer;
  connection->closer = closer;

  connection->received_connection_header = false;
  connection->received_settings = false;
  connection->last_stream_id = 0;
  connection->current_stream_id = 2;
  connection->window_size = DEFAULT_INITIAL_WINDOW_SIZE;
  connection->closing = false;

  connection->buffer = NULL;
  connection->buffer_length = 0;
  connection->buffer_position = 0;

  connection->header_table_size = DEFAULT_HEADER_TABLE_SIZE;
  connection->enable_push = DEFAULT_ENABLE_PUSH;
  connection->max_concurrent_streams = DEFAULT_MAX_CONNCURRENT_STREAMS;
  connection->initial_window_size = DEFAULT_INITIAL_WINDOW_SIZE;

  connection->streams = calloc(sizeof(http_stream_t *), 4096);

  connection->request_listener = request_handler;

  connection->encoding_context = hpack_context_init(DEFAULT_HEADER_TABLE_SIZE);
  connection->decoding_context = hpack_context_init(connection->header_table_size);

  return connection;
}

static http_stream_t * http_stream_get(http_connection_t * const connection, const uint32_t stream_id) {
  // TODO - use a better data structure than an array
  if (stream_id >= 4096) {
    emit_error_and_close(connection, stream_id, HTTP_ERROR_INTERNAL_ERROR,
        "Unable to find stream with ID higher than 4096");
    return NULL;
  }

  http_stream_t * stream = connection->streams[stream_id];

  return stream;
}

static void http_stream_close(const http_connection_t * const connection, http_stream_t * const stream) {
  if (stream->headers) {
    multimap_free(stream->headers, free, free);
  }
  connection->streams[stream->id] = NULL;
  free(stream);
}

void http_connection_free(http_connection_t * const connection) {
  int i;
  for (i = 0; i < 4096; i++) {
    http_stream_t * stream = connection->streams[i];
    if (stream) {
      http_stream_close(connection, stream);
    }
  }
  free(connection->streams);
  hpack_context_free(connection->encoding_context);
  hpack_context_free(connection->decoding_context);
  free(connection);
}

static void http_connection_close(http_connection_t * const connection) {
  // TODO loop through streams + close them
  connection->closer(connection->data);
  connection->closing = true;
}

static void http_frame_header_write(uint8_t * const buf, const uint16_t length, const uint8_t type,
    const uint8_t flags, uint32_t stream_id) {
  size_t pos = 0;

  buf[pos++] = (length >> 8) & 0x3F; // only the first 6 bits (first 2 bits are reserved)
  buf[pos++] = (length) & 0xFF;

  buf[pos++] = type;

  buf[pos++] = flags;

  buf[pos++] = (stream_id >> 24) & 0x7F; // only the first 7 bits (first bit is reserved)
  buf[pos++] = (stream_id >> 16) & 0xFF;
  buf[pos++] = (stream_id >> 8) & 0xFF;
  buf[pos++] = (stream_id) & 0xFF;
}

static void http_emit_goaway(const http_connection_t * const connection, enum h2_error_code_e error_code, char * debug) {

  size_t last_stream_id_length = 4; // 1 bit + 31 bits
  size_t error_code_length = 4; // 32 bits

  size_t debug_length = 0;
  if (debug) {
    debug_length = strlen(debug);
  }

  size_t payload_length = last_stream_id_length + error_code_length + debug_length;
  size_t buf_length = FRAME_HEADER_SIZE + payload_length;

  size_t pos = 0;
  uint8_t buf[buf_length];

  uint8_t flags = 0; // no flags

  http_frame_header_write(buf, payload_length, FRAME_TYPE_GOAWAY, flags, 0);
  pos += FRAME_HEADER_SIZE;

  size_t stream_id = connection->last_stream_id;

  buf[pos++] = (stream_id >> 24) & 0x7F; // only the first 7 bits (first bit is reserved)
  buf[pos++] = (stream_id >> 16) & 0xFF;
  buf[pos++] = (stream_id >> 8) & 0xFF;
  buf[pos++] = (stream_id) & 0xFF;

  buf[pos++] = (error_code >> 24) & 0xFF;
  buf[pos++] = (error_code >> 16) & 0xFF;
  buf[pos++] = (error_code >> 8) & 0xFF;
  buf[pos++] = (error_code) & 0xFF;

  if (debug) {
    memcpy(buf + pos, debug, debug_length);
  }

  if (LOG_DEBUG) log_debug("Writing goaway frame");
  connection->writer(connection->data, buf, buf_length);
}

static void http_emit_rst_stream(const http_connection_t * const connection, uint32_t stream_id,
    enum h2_error_code_e error_code) {

  size_t error_code_length = 4; // 32 bits

  size_t payload_length = error_code_length;
  size_t buf_length = FRAME_HEADER_SIZE + payload_length;

  size_t pos = 0;
  uint8_t buf[buf_length];

  uint8_t flags = 0; // no flags

  http_frame_header_write(buf, payload_length, FRAME_TYPE_RST_STREAM, flags, stream_id);
  pos += FRAME_HEADER_SIZE;

  buf[pos++] = (error_code >> 24) & 0xFF;
  buf[pos++] = (error_code >> 16) & 0xFF;
  buf[pos++] = (error_code >> 8) & 0xFF;
  buf[pos++] = (error_code) & 0xFF;

  if (LOG_DEBUG) log_debug("Writing reset stream frame");
  connection->writer(connection->data, buf, buf_length);
}

static void emit_error_and_close(http_connection_t * const connection, uint32_t stream_id, enum h2_error_code_e error_code,
    char * format, ...) {

  size_t buf_length = 1024;
  char buf[buf_length];
  if (format) {
    va_list ap;
    va_start(ap, format);
    vsnprintf(buf, buf_length, format, ap);
    va_end(ap);

    if (error_code != HTTP_ERROR_NO_ERROR) {
      log_error(buf);
    }
  }

  if (stream_id > 0) {
    http_emit_rst_stream(connection, stream_id, error_code);
  } else {
    http_emit_goaway(connection, error_code, format ? buf : NULL);
  }
  // TODO gracefully shutdown connection
  http_connection_close(connection);
}

static void http_emit_headers(http_connection_t * const connection, const http_stream_t * const stream,
    const multimap_t * const headers) {
  // TODO split large headers into multiple frames
  size_t headers_length = 0;
  uint8_t * hpack_buf = NULL;
  if (headers != NULL) {
    binary_buffer_t encoded;
    if (!hpack_encode(connection->encoding_context, headers, &encoded)) {
      // don't send stream ID because we want to generate a goaway - the
      // encoding context may have been corrupted
      emit_error_and_close(connection, 0, HTTP_ERROR_INTERNAL_ERROR, "Error encoding headers");
    }
    hpack_buf = encoded.buf;
    headers_length = binary_buffer_size(&encoded);
  }
  const size_t buf_length = FRAME_HEADER_SIZE + headers_length;
  uint8_t buf[buf_length];
  uint8_t flags = 0;
  // TODO - these should be dynamic
  const bool end_stream = false;
  const bool end_headers = true;
  const bool priority = false;
  if (end_stream) flags |= HEADERS_FLAG_END_STREAM;
  if (end_headers) flags |= HEADERS_FLAG_END_HEADERS;
  if (priority) flags |= HEADERS_FLAG_PRIORITY;
  http_frame_header_write(buf, headers_length, FRAME_TYPE_HEADERS, flags, stream->id);

  if (hpack_buf) {
    size_t pos = FRAME_HEADER_SIZE;
    memcpy(buf + pos, hpack_buf, headers_length);
    free(hpack_buf);
  }

  if (LOG_DEBUG) log_debug("Writing headers frame: stream %d, %ld octets", stream->id, buf_length);
  connection->writer(connection->data, buf, buf_length);
}

static void http_emit_data_frame(const http_connection_t * const connection, const http_stream_t * const stream,
    const http_queued_frame_t * const frame) {
  size_t header_length = FRAME_HEADER_SIZE;
  uint8_t header_buf[header_length];
  uint8_t flags = 0;
  if (frame->end_stream) flags |= DATA_FLAG_END_STREAM;
  http_frame_header_write(header_buf, frame->buf_length, FRAME_TYPE_DATA, flags, stream->id);
  connection->writer(connection->data, header_buf, header_length);

  if (LOG_DEBUG) log_debug("Writing data frame: stream %d, %ld octets", stream->id, frame->buf_length);
  connection->writer(connection->data, frame->buf, frame->buf_length);
}

static void http_trigger_send_data(http_connection_t * const connection, const http_stream_t * const stream) {
  uint32_t i;
  // TODO improve looping through open streams
  for (i = 0; i < 4096; i++) {
    http_stream_t * stream = http_stream_get(connection, i);
    if (stream) {
      while (stream->queued_data_frames) {
        http_queued_frame_t * frame = stream->queued_data_frames;
        size_t frame_payload_size = frame->buf_length;
        if ((long)frame_payload_size <= connection->window_size &&
            (long)frame_payload_size <= stream->window_size) {
          http_emit_data_frame(connection, stream, frame);

          connection->window_size -= frame_payload_size;
          stream->window_size -= frame_payload_size;

          stream->queued_data_frames = frame->next;

          if (frame->buf_begin) {
            free(frame->buf_begin);
          }
          free(frame);
        } else {
          if (LOG_DEBUG) {
            log_debug("Wanted to send %ld octets, but connection window is %ld and stream window is %ld",
                frame_payload_size, connection->window_size, stream->window_size);
          }

          // wait until the window size has been increased
          break;
        }
      }
    }
  }

  if (LOG_TRACE) log_trace("Connection window size: %ld, stream window: %ld", connection->window_size, stream->window_size);
}

static void http_queue_data_frame(http_stream_t * const stream, uint8_t * buf,
    const size_t buf_length, const bool end_stream, void * const buf_begin) {
  http_queued_frame_t * new_frame = malloc(sizeof(http_queued_frame_t));
  new_frame->buf = buf;
  new_frame->buf_length = buf_length;
  new_frame->end_stream = end_stream;
  new_frame->buf_begin = buf_begin;
  new_frame->buf_begin = buf_begin;
  new_frame->next = NULL;

  if (!stream->queued_data_frames) {
    stream->queued_data_frames = new_frame;
  } else {
    http_queued_frame_t * curr = stream->queued_data_frames;
    while (curr->next) {
      curr = curr->next;
    }
    curr->next = new_frame;
  }
}

static void http_emit_data(http_connection_t * const connection, http_stream_t * const stream,
    uint8_t * text, const size_t text_length) {
  // TODO support padding?

  size_t frame_payload_size = text_length;
  if (frame_payload_size > MAX_FRAME_SIZE) {
    size_t remaining_length = text_length;
    size_t per_frame_length;
    uint8_t * per_frame_text = text;
    bool last = false;
    while (remaining_length > 0) {
      if (remaining_length > MAX_FRAME_SIZE) {
        per_frame_length = MAX_FRAME_SIZE;
        last = false;
      } else {
        per_frame_length = remaining_length;
        last = true;
      }
      http_queue_data_frame(stream, per_frame_text, per_frame_length, last, last ? text : NULL);
      remaining_length -= per_frame_length;
      per_frame_text += per_frame_length;
    }
  } else {
    http_queue_data_frame(stream, text, text_length, true, text);
  }
  http_trigger_send_data(connection, stream);
}

static void http_emit_settings_ack(const http_connection_t * const connection) {
  size_t buf_length = FRAME_HEADER_SIZE;
  uint8_t buf[buf_length];
  uint8_t flags = 0;
  bool ack = true;
  if (ack) flags |= SETTINGS_FLAG_ACK;
  http_frame_header_write(buf, 0, FRAME_TYPE_SETTINGS, flags, 0);
  if (LOG_DEBUG) log_debug("Writing settings ack frame");
  connection->writer(connection->data, buf, buf_length);
}

/**
 * Returns true if the first part of data is the http connection
 * header string
 */
static bool http_connection_recognize_connection_header(http_connection_t * const connection) {
  if (connection->buffer_length >= HTTP_CONNECTION_HEADER_LENGTH) {
    connection->buffer_position = HTTP_CONNECTION_HEADER_LENGTH;
    return memcmp(connection->buffer, HTTP_CONNECTION_HEADER,
        HTTP_CONNECTION_HEADER_LENGTH) == 0;
  }
  return false;
}

static void http_adjust_initial_window_size(http_connection_t * const connection, const long difference) {
  http_stream_t * * streams = connection->streams;
  size_t i;
  for (i = 0; i < 4096; i++) {
    http_stream_t * stream = streams[i];
    if (stream) {
      stream->window_size += difference;
      if (stream->window_size > MAX_WINDOW_SIZE) {
        emit_error_and_close(connection, stream->id, HTTP_ERROR_FLOW_CONTROL_ERROR, NULL);
      }
    }
  }
}

static bool http_setting_set(http_connection_t * const connection, const enum settings_e id, const uint32_t value) {
  if (LOG_TRACE) log_trace("Settings: %d: %d", id, value);
  switch (id) {
    case SETTINGS_HEADER_TABLE_SIZE:
      if (LOG_TRACE) log_trace("Settings: Got table size: %d", value);
      connection->header_table_size = value;
      hpack_header_table_adjust_size(connection->decoding_context, value);
      break;
    case SETTINGS_ENABLE_PUSH:
      if (LOG_TRACE) log_trace("Settings: Enable push? %d", value);
      connection->enable_push = value;
      break;
    case SETTINGS_MAX_CONCURRENT_STREAMS:
      if (LOG_TRACE) log_trace("Settings: Max concurrent streams: %d", value);
      connection->max_concurrent_streams = value;
      break;
    case SETTINGS_INITIAL_WINDOW_SIZE:
      if (LOG_TRACE) log_trace("Settings: Initial window size: %d", value);
      http_adjust_initial_window_size(connection, value - connection->initial_window_size);
      connection->initial_window_size = value;
      break;
    default:
      emit_error_and_close(connection, 0, HTTP_ERROR_PROTOCOL_ERROR, "Invalid setting: %d", id);
      return false;
  }
  return true;
}

static http_stream_t * http_stream_init(http_connection_t * const connection, const uint32_t stream_id) {
  http_stream_t * stream = http_stream_get(connection, stream_id);
  if (stream != NULL) {
    emit_error_and_close(connection, stream_id, HTTP_ERROR_PROTOCOL_ERROR,
        "Got a headers frame for an existing stream");
    return NULL;
  }
  // TODO - we won't need this check once we support over 4096 streams
  if (stream == NULL && stream_id > 4096) {
    return NULL;
  }
  stream = malloc(sizeof(http_stream_t));
  if (!stream) {
    emit_error_and_close(connection, stream_id, HTTP_ERROR_INTERNAL_ERROR,
        "Unable to initialize stream: %ld", stream_id);
    return NULL;
  }
  connection->streams[stream_id] = stream;

  stream->queued_data_frames = NULL;

  stream->id = stream_id;
  stream->state = STREAM_STATE_IDLE;
  stream->header_fragments = NULL;
  stream->headers = NULL;
  stream->priority = DEFAULT_STREAM_PRIORITY;
  stream->window_size = connection->initial_window_size;

  return stream;
}

void http_trigger_request(http_connection_t * const connection, http_stream_t * const stream) {
  if (!connection->request_listener) {
    if (LOG_ERROR) log_error("No request listener set up");
    abort();
  }

  http_request_t * request = http_request_init(connection, stream, stream->headers);
  if (!request) {
    abort();
  }

  // transfer ownership of headers to the request
  stream->headers = NULL;

  http_response_t * response = http_response_init(request);

  if (stream->id > connection->last_stream_id) {
    connection->last_stream_id = stream->id;
  }
  connection->request_listener(request, response);
}

static void http_stream_add_header_fragment(http_stream_t * const stream, const uint8_t * const buffer, const size_t length) {
  http_header_fragment_t * fragment = malloc(sizeof(http_header_fragment_t));
  fragment->buffer = malloc(length);
  if (!fragment->buffer) {
    abort();
  }
  memcpy(fragment->buffer, buffer, length);
  fragment->length = length;
  fragment->next = NULL;

  http_header_fragment_t * current = stream->header_fragments;
  for (; current && current->next; current = current->next);
  if (current == NULL) {
    stream->header_fragments = fragment;
  } else {
    current->next = fragment;
  }
}

static bool http_parse_header_fragments(http_connection_t * const connection, http_stream_t * const stream) {
  size_t headers_length = 0;
  http_header_fragment_t * current = stream->header_fragments;
  for (; current; current = current->next) {
    if (LOG_TRACE) log_trace("Counting header fragment lengths: %ld", current->length);
    headers_length += current->length;
  }
  uint8_t * headers = malloc(headers_length + 1);
  if (!headers) {
    emit_error_and_close(connection, stream->id, HTTP_ERROR_INTERNAL_ERROR, "Unable to allocate memory for headers");
    return false;
  }
  uint8_t * header_appender = headers;
  current = stream->header_fragments;
  while (current) {
    if (LOG_TRACE) log_trace("Appending header fragment: %s (%ld)", current->buffer, current->length);
    memcpy(header_appender, current->buffer, current->length);
    header_appender += current->length;
    http_header_fragment_t * prev = current;
    current = current->next;
    free(prev->buffer);
    free(prev);
  }
  *header_appender = '\0';
  if (LOG_TRACE) log_trace("Got headers: %s (%ld), decoding", headers, headers_length);
  stream->headers = hpack_decode(connection->decoding_context, headers, headers_length);
  if (!stream->headers) {
    emit_error_and_close(connection, stream->id, HTTP_ERROR_COMPRESSION_ERROR, "Unable to decode headers");
    return false;
  }
  // TODO - check that the stream is in a valid state to be opened first
  stream->state = STREAM_STATE_OPEN;

  free(headers);

  // TODO - check that the stream is not closed?
  if (!connection->closing) {
    http_trigger_request(connection, stream);
  }

  return true;
}

static bool http_parse_frame_headers(http_connection_t * const connection,
    const http_frame_headers_t * const frame) {
  if (frame->stream_id < 1) {
    // TODO do we need to read the rest of the frame anyway so that the
    // decoding context is still synced?
    emit_error_and_close(connection, 0, HTTP_ERROR_PROTOCOL_ERROR,
        "Invalid stream ID for headers frame: %ld", frame->stream_id);
    return false;
  }
  uint8_t * pos = connection->buffer + connection->buffer_position;
  size_t header_block_fragment_size = frame->length;
  http_stream_t * stream = http_stream_init(connection, frame->stream_id);
  if (!stream) {
    return false;
  }
  if (frame->priority) {
    stream->priority = get_bits32(pos, 4, 0x7FFFFFFF);
    pos += 4;
    header_block_fragment_size -= 4;
  }
  http_stream_add_header_fragment(stream, pos, header_block_fragment_size);
  if (frame->end_headers) {
    // parse the headers
    if (LOG_TRACE) log_trace("Parsing headers");
    return http_parse_header_fragments(connection, stream);
  } else {
    // TODO mark stream as waiting for continuation frame
  }
  return true;
}

static bool http_parse_frame_continuation(http_connection_t * const connection,
    const http_frame_continuation_t * const frame) {
  uint8_t * pos = connection->buffer + connection->buffer_position;
  size_t header_block_fragment_size = frame->length;
  http_stream_t * stream = http_stream_get(connection, frame->stream_id);
  http_stream_add_header_fragment(stream, pos, header_block_fragment_size);
  if (frame->end_headers) {
    // TODO unmark stream as waiting for continuation frame
    // parse the headers
    if (LOG_TRACE) log_trace("Parsing headers + continuations");
    return http_parse_header_fragments(connection, stream);
  }
  return true;
}

static bool http_parse_frame_settings(http_connection_t * const connection, const http_frame_settings_t * const frame) {
  if (frame->stream_id != 0) {
    emit_error_and_close(connection, 0, HTTP_ERROR_PROTOCOL_ERROR,
        "Invalid stream ID for ACK settings frame: %ld", frame->stream_id);
  }
  if (frame->ack && frame->length != 0) {
    emit_error_and_close(connection, 0, HTTP_ERROR_FRAME_SIZE_ERROR,
        "Non-zero frame size for ACK settings frame: %ld", frame->length);
  }
  if (frame->ack) {
    // TODO mark the settings frame we sent as acknowledged
    if (LOG_TRACE) log_trace("Received settings ACK");
    abort();
  } else {
    uint8_t * pos = connection->buffer + connection->buffer_position;
    size_t setting_size = 5;
    size_t num_settings = frame->length / setting_size;
    if (LOG_TRACE) log_trace("Settings: Found #%ld settings", num_settings);
    size_t i;
    for (i = 0; i < num_settings; i++) {
      uint8_t * curr_setting = pos + (i * setting_size);
      uint8_t setting_id = curr_setting[0];
      uint32_t setting_value = get_bits32(curr_setting, 1, 0xFFFFFFFF);
      if (!http_setting_set(connection, setting_id, setting_value)) {
        return false;
      }
    }
    connection->received_settings = true;
    if (LOG_TRACE) log_trace("Settings: %ld, %d, %ld, %ld", connection->header_table_size, connection->enable_push,
        connection->max_concurrent_streams, connection->initial_window_size);

    http_emit_settings_ack(connection);
  }
  return true;
}

static bool http_increment_connection_window_size(http_connection_t * const connection, const uint32_t increment) {
  connection->window_size += increment;
  if (LOG_TRACE) log_trace("Connection window size incremented to: %ld", connection->window_size);

  http_trigger_send_data(connection, NULL);

  return true;
}

static bool http_increment_stream_window_size(http_connection_t * const connection, const uint32_t stream_id,
    const uint32_t increment) {
  http_stream_t * stream = http_stream_get(connection, stream_id);
  if (stream) {
    stream->window_size += increment;
    if (LOG_TRACE) log_trace("Stream window size incremented to: %ld", stream->window_size);

    http_trigger_send_data(connection, stream);
  } else {
    // TODO connection error if the stream was closed over x seconds ago
    abort();
  }
  return true;
}

static bool http_parse_frame_window_update(http_connection_t * const connection, http_frame_window_update_t * const frame) {
  uint8_t * buf = connection->buffer + connection->buffer_position;
  frame->increment = get_bits32(buf, 0, 0x7FFFFFFF);

  bool success = false;

  if (frame->stream_id > 0) {
    success = http_increment_stream_window_size(connection, frame->stream_id, frame->increment);
  } else {
    success = http_increment_connection_window_size(connection, frame->increment);
  }

  if (LOG_TRACE) log_trace("Received window update, stream: %d, increment: %ld",
      frame->stream_id, frame->increment);

  return success;
}

static bool http_parse_frame_goaway(http_connection_t * const connection, http_frame_goaway_t * const frame) {
  if (frame->stream_id != 0) {
    emit_error_and_close(connection, 0, HTTP_ERROR_PROTOCOL_ERROR, "Invalid stream ID for goaway frame: %ld", frame->stream_id);
    return false;
  }
  uint8_t * buf = connection->buffer + connection->buffer_position;
  frame->last_stream_id = get_bits32(buf, 0, 0x7FFFFFFF);
  frame->error_code = get_bits32(buf, 4, 0xFFFFFFFF);
  size_t debug_data_length = (frame->length - 8);

  uint8_t debug_data[debug_data_length + 1];
  memcpy(debug_data, buf + 8, debug_data_length);
  debug_data[debug_data_length] = '\0';
  frame->debug_data = debug_data;

  if (LOG_TRACE) log_trace("Received goaway, last stream: %d, error code: %d, debug_data: %s",
      frame->last_stream_id, frame->error_code, frame->debug_data);

  frame->debug_data = NULL;

  return true;
}

static http_frame_t * http_frame_init(http_connection_t * const connection, const uint16_t length, const uint8_t type,
    const uint8_t flags, const uint32_t stream_id) {
  http_frame_t * frame;
  switch(type) {
    case FRAME_TYPE_DATA:
    {
      http_frame_data_t *data_frame = malloc(sizeof(http_frame_data_t));
      data_frame->end_stream = flags & DATA_FLAG_END_STREAM;
      // TODO padding flags
      frame = (http_frame_t *) data_frame;
      break;
    }
    case FRAME_TYPE_HEADERS:
    {
      http_frame_headers_t *headers_frame = malloc(sizeof(http_frame_headers_t));
      headers_frame->end_stream = flags & HEADERS_FLAG_END_STREAM;
      headers_frame->end_headers = flags & HEADERS_FLAG_END_HEADERS;
      headers_frame->priority = flags & HEADERS_FLAG_PRIORITY;
      // TODO padding flags
      frame = (http_frame_t *) headers_frame;
      break;
    }
    /*
    case FRAME_TYPE_PRIORITY:
      parse_frame_priority(connection);
    case FRAME_TYPE_RST_STREAM:
      parse_frame_reset_stream(connection);
    */
    case FRAME_TYPE_SETTINGS:
    {
      http_frame_settings_t *settings_frame = malloc(sizeof(http_frame_settings_t));
      settings_frame->ack = flags & SETTINGS_FLAG_ACK;
      frame = (http_frame_t *) settings_frame;
      break;
    }
    /*
    case FRAME_TYPE_PUSH_PROMISE:
      parse_frame_push_promise(connection);
    case FRAME_TYPE_PING:
      parse_frame_ping(connection);
    */
    case FRAME_TYPE_GOAWAY:
    {
      http_frame_goaway_t *goaway_frame = malloc(sizeof(http_frame_goaway_t));
      frame = (http_frame_t *) goaway_frame;
      break;
    }
    case FRAME_TYPE_WINDOW_UPDATE:
    {
      http_frame_window_update_t *window_update_frame = malloc(sizeof(http_frame_window_update_t));
      frame = (http_frame_t *) window_update_frame;
      break;
    }
    case FRAME_TYPE_CONTINUATION:
    {
      http_frame_continuation_t *continuation_frame = malloc(sizeof(http_frame_continuation_t));
      continuation_frame->end_headers = flags & CONTINUATION_FLAG_END_HEADERS;
      // TODO padding flags
      frame = (http_frame_t *) continuation_frame;
      break;
    }
    default:
      emit_error_and_close(connection, stream_id, HTTP_ERROR_INTERNAL_ERROR, "Unhandled frame type");
      return NULL;
  }
  frame->type = type;
  frame->length = length;
  frame->stream_id = stream_id;
  return frame;
}

static bool is_valid_frame_type(enum frame_type_e frame_type) {

  // TODO is there a faster way to do this - will the compiler automatically optimize the loop out?
  enum frame_type_e valid[] = {
    FRAME_TYPE_DATA,
    FRAME_TYPE_HEADERS,
    FRAME_TYPE_PRIORITY,
    FRAME_TYPE_RST_STREAM,
    FRAME_TYPE_SETTINGS,
    FRAME_TYPE_PUSH_PROMISE,
    FRAME_TYPE_PING,
    FRAME_TYPE_GOAWAY,
    FRAME_TYPE_WINDOW_UPDATE,
    FRAME_TYPE_CONTINUATION
  };

  size_t index;
  size_t len = sizeof(valid) / sizeof(enum frame_type_e);
  for (index = 0; index < len; index++) {
    if (frame_type == valid[index]) {
      return true;
    }
  }

  return false;
}

/**
 * Processes the next frame in the buffer.
 *
 * Returns true a frame was processed.
 * Returns false if there was no frame to process.
 */
static bool http_connection_add_from_buffer(http_connection_t * const connection) {
  if (LOG_TRACE) log_trace("Reading %ld bytes", connection->buffer_length);
  if (connection->buffer_position == connection->buffer_length) {
    if (LOG_TRACE) log_trace("Finished with current buffer");
    return false;
  }
  // is there enough in the buffer to read a frame header?
  if (connection->buffer_position + FRAME_HEADER_SIZE > connection->buffer_length) {
    // TODO off-by-one?
    if (LOG_TRACE) log_trace("Not enough in buffer to read frame header");
    return false;
  }

  uint8_t * pos = connection->buffer + connection->buffer_position;

  // Read the frame header
  // get 14 bits of first 2 bytes
  uint16_t frame_length = get_bits16(pos, 0, 0x3FFF);

  // is there enough in the buffer to read the frame payload?
  if (connection->buffer_position + FRAME_HEADER_SIZE + frame_length <= connection->buffer_length) {

    uint8_t frame_type = pos[2];
    uint8_t frame_flags = pos[3];
    // get 31 bits
    uint32_t stream_id = get_bits32(pos, 4, 0x7FFFFFFF);

    // is this a valid frame type?
    if (!is_valid_frame_type(frame_type)) {
      // invalid frame type is always a connection error
      emit_error_and_close(connection, 0, HTTP_ERROR_PROTOCOL_ERROR, "Invalid Frame Type: %d", frame_type);
      return false;
    }

    // TODO - if the previous frame type was headers, and headers haven't been completed,
    // this frame must be a continuation frame, or else this is a protocol error

    http_frame_t * frame = http_frame_init(connection, frame_length, frame_type, frame_flags, stream_id);
    if (frame == NULL) {
      return false;
    }

    connection->buffer_position += FRAME_HEADER_SIZE;
    // TODO off-by-one?
    bool success = false;
    if (!connection->received_settings && frame->type != FRAME_TYPE_SETTINGS) {
      emit_error_and_close(connection, 0, HTTP_ERROR_PROTOCOL_ERROR, "Expected Settings frame as first frame");
    } else {
      switch(frame->type) {
        /*
        case FRAME_TYPE_DATA:
          parse_frame_data(connection);
        */
        case FRAME_TYPE_HEADERS:
          success = http_parse_frame_headers(connection, (http_frame_headers_t *) frame);
          break;
        /*
        case FRAME_TYPE_PRIORITY:
          parse_frame_priority(connection);
        case FRAME_TYPE_RST_STREAM:
          parse_frame_reset_stream(connection);
        */
        case FRAME_TYPE_SETTINGS:
          success = http_parse_frame_settings(connection, (http_frame_settings_t *) frame);
          break;
        /*
        case FRAME_TYPE_PUSH_PROMISE:
          parse_frame_push_promise(connection);
        case FRAME_TYPE_PING:
          parse_frame_ping(connection);
        */
        case FRAME_TYPE_GOAWAY:
          success = http_parse_frame_goaway(connection, (http_frame_goaway_t *) frame);
          break;
        case FRAME_TYPE_WINDOW_UPDATE:
          success = http_parse_frame_window_update(connection, (http_frame_window_update_t *) frame);
          break;
        case FRAME_TYPE_CONTINUATION:
          success = http_parse_frame_continuation(connection, (http_frame_continuation_t *) frame);
          break;
        default:
          emit_error_and_close(connection, 0, HTTP_ERROR_INTERNAL_ERROR, "Unhandled frame type: %d", frame->type);
          return false;
      }
    }

    connection->buffer_position += frame->length;
    free(frame);
    return success;
  } else {
    if (LOG_TRACE) log_trace("Not enough in buffer to read %ld byte frame payload", frame_length);
  }
  return false;
}

/**
 * Reads the given buffer and acts on it. Caller must give up ownership of the
 * buffer.
 */
void http_connection_read(http_connection_t * const connection, uint8_t * const buffer, const size_t len) {
  if (LOG_TRACE) log_trace("Reading from buffer: %ld", len);
  size_t unprocessed_bytes = connection->buffer_length;
  if (unprocessed_bytes > 0) {
    // there are still unprocessed bytes
    connection->buffer = realloc(connection->buffer, unprocessed_bytes + len);
    if (!connection->buffer) {
      emit_error_and_close(connection, 0, HTTP_ERROR_INTERNAL_ERROR, "Unable to allocate memory for reading full frame");
      return;
    }
    memcpy(connection->buffer + unprocessed_bytes, buffer, len);
    connection->buffer_length = unprocessed_bytes + len;
    free(buffer);
  } else {
    connection->buffer = buffer;
    connection->buffer_length = len;
  }
  connection->buffer_position = 0;

  if (!connection->received_connection_header) {
    if (http_connection_recognize_connection_header(connection)) {
      connection->received_connection_header = true;
      if (LOG_TRACE) log_trace("Found HTTP2 connection");
    } else {
      if (LOG_WARN) log_warning("Found non-HTTP2 connection, closing connection");
      http_connection_close(connection);
      return;
    }
  }

  while (http_connection_add_from_buffer(connection));

  if (connection->buffer_position > connection->buffer_length) {
    // buffer overflow
    abort();
  }

  // if there is still unprocessed data in the buffer, save it for when we
  // get the rest of the frame
  unprocessed_bytes = connection->buffer_length - connection->buffer_position;
  if (!connection->closing && unprocessed_bytes > 0) {
    // use memmove because it might overlap
    memmove(connection->buffer, connection->buffer + connection->buffer_position, unprocessed_bytes);
    connection->buffer = realloc(connection->buffer, unprocessed_bytes);
    connection->buffer_length = unprocessed_bytes;
  } else {
    free(connection->buffer);
    connection->buffer = NULL;
    connection->buffer_length = 0;
  }
}

void http_response_write(http_response_t * const response, char * text, const size_t text_length) {
  char status_buf[10];
  snprintf(status_buf, 10, "%d", response->status);
  // add the status header
  http_response_header_add(response, ":status", status_buf);

  http_connection_t * connection = (http_connection_t *)response->request->connection;
  http_stream_t * stream = (http_stream_t *)response->request->stream;

  // emit headers frame
  http_emit_headers(connection, stream, response->headers);

  // emit data frame
  http_emit_data(connection, stream, (uint8_t *)text, text_length);

  http_response_free(response);
}

