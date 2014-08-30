#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "config.h"

#include "../util/util.h"
#include "../util/binary_buffer.h"

#include "http.h"
#include "request.h"
#include "response.h"
#include "hash_table.h"

#define FRAME_HEADER_SIZE 9 // octets
#define DEFAULT_STREAM_EXCLUSIVE_FLAG 0
#define DEFAULT_STREAM_DEPENDENCY 0
#define DEFAULT_STREAM_WEIGHT 16
#define SETTING_ID_SIZE 2
#define SETTING_VALUE_SIZE 4
#define SETTING_SIZE (SETTING_ID_SIZE + SETTING_VALUE_SIZE)

#define MAX_WINDOW_SIZE 0x7FFFFFFF // 2^31 - 1
#define MAX_CONNECTION_BUFFER_SIZE 0x1000000 // 2^24

#define PING_OPAQUE_DATA_LENGTH 8

const char * HTTP_CONNECTION_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const size_t HTTP_CONNECTION_PREFACE_LENGTH = 24;

char * http_connection_errors[] = {
  "NO_ERROR",
  "PROTOCOL_ERROR",
  "INTERNAL_ERROR",
  "FLOW_CONTROL_ERROR",
  "SETTINGS_TIMEOUT",
  "STREAM_CLOSED",
  "FRAME_SIZE_ERROR",
  "REFUSED_STREAM",
  "CANCEL",
  "COMPRESSION_ERROR",
  "CONNECT_ERROR",
  "ENHANCE_YOUR_CALM",
  "INADEQUATE_SECURITY"
};

typedef struct {
  uint32_t length_min;
  uint32_t length_max;

  uint8_t frame_type;

  // which flags can be set to true?
  bool flags[8];

  bool must_have_stream_id;
  bool must_not_have_stream_id;
} frame_parser_definition_t;

frame_parser_definition_t frame_parser_definitions[] = {

  {
    // DATA frame
    0, // length min
    0x4000, // length max 2^14
    0x0, // type
    {
      true, // END_STREAM 0x1
      true, // END_SEGMENT 0x2
      false,
      true, // PADDED 0x8
      false,
      false,
      false,
      false
    },
    true,
    false
  },

  {
    // HEADERS frame
    0, // length min
    0x4000, // length max 2^14
    0x1, // type
    {
      true, // END_STREAM 0x1
      true, // END_SEGMENT 0x2
      true, // END_HEADERS 0x4
      true, // PADDED 0x8
      false,
      true, // PRIORITY 0x20
      false,
      false
    },
    true,
    false
  },

  {
    // PRIORITY frame
    0x5, // length min
    0x5, // length max
    0x2, // type
    {
      false,
      false,
      false,
      false,
      false,
      false,
      false,
      false
    },
    true,
    false
  },

  {
    // RST_STREAM frame
    0x4, // length min
    0x4, // length max
    0x3, // type
    {
      false,
      false,
      false,
      false,
      false,
      false,
      false,
      false
    },
    true,
    false
  },

  {
    // SETTINGS frame
    0, // length min
    0x4000, // length max 2^14
    0x4, // type
    {
      true, // ACK 0x1
      false,
      false,
      false,
      false,
      false,
      false,
      false
    },
    false,
    true
  },

  {
    // PUSH_PROMISE frame
    0, // length min
    0x4000, // length max 2^14
    0x5, // type
    {
      false,
      false,
      true, // END_HEADERS 0x4
      true, // PADDED 0x8
      false,
      false,
      false,
      false
    },
    false,
    true
  },

  {
    // PING frame
    0x8, // length min
    0x8, // length max
    0x6, // type
    {
      true, // ACK 0x1
      false,
      false,
      false,
      false,
      false,
      false,
      false
    },
    false,
    true
  },

  {
    // GOAWAY frame
    0x8, // length min
    0x4000, // length max // 2^14
    0x7, // type
    {
      false,
      false,
      false,
      false,
      false,
      false,
      false,
      false
    },
    false,
    true
  },

  {
    // WINDOW_UPDATE frame
    0x4, // length min
    0x4, // length max
    0x8, // type
    {
      false,
      false,
      false,
      false,
      false,
      false,
      false,
      false
    },
    false,
    false
  },

  {
    // CONTINUATION frame
    0, // length min
    0x4000, // length max 2^14
    0x9, // type
    {
      false,
      false,
      true, // END_HEADERS 0x4
      false,
      false,
      false,
      false,
      false
    },
    true,
    false
  },

};

static void http_stream_free(void * value)
{
  http_stream_t * stream = value;

  if (stream->headers) {
    header_list_free(stream->headers);
  }

  // Free any remaining data frames. This may need to happen
  // for streams that have been reset
  while (stream->queued_data_frames) {

    http_queued_frame_t * frame = stream->queued_data_frames;

    stream->queued_data_frames = frame->next;

    if (frame->buf_begin) {
      free(frame->buf_begin);
    }

    free(frame);

  }

  free(stream);
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

  connection->received_connection_preface = false;
  connection->received_settings = false;
  connection->last_stream_id = 0;
  connection->current_stream_id = 2;
  connection->outgoing_window_size = DEFAULT_INITIAL_WINDOW_SIZE;
  connection->incoming_window_size = DEFAULT_INITIAL_WINDOW_SIZE;
  connection->closing = false;
  connection->closed = false;

  connection->outgoing_concurrent_streams = 0;
  connection->incoming_concurrent_streams = 0;

  connection->buffer = NULL;
  connection->buffer_length = 0;
  connection->buffer_position = 0;
  connection->reading_from_client = false;

  connection->header_table_size = DEFAULT_HEADER_TABLE_SIZE;
  connection->enable_push = DEFAULT_ENABLE_PUSH;
  connection->max_concurrent_streams = DEFAULT_MAX_CONNCURRENT_STREAMS;
  connection->initial_window_size = DEFAULT_INITIAL_WINDOW_SIZE;
  connection->max_frame_size = DEFAULT_MAX_FRAME_SIZE;
  connection->max_header_list_size = DEFAULT_MAX_HEADER_LIST_SIZE;

  /**
   * Set these to NULL, http_connection_free requires the values to be set
   * to something other than garbage
   */
  connection->encoding_context = NULL;
  connection->decoding_context = NULL;
  connection->streams = NULL;
  connection->write_buffer = NULL;

  connection->encoding_context = hpack_context_init(DEFAULT_HEADER_TABLE_SIZE);

  if (!connection->encoding_context) {
    http_connection_free(connection);
    return NULL;
  }

  connection->decoding_context = hpack_context_init(connection->header_table_size);

  if (!connection->decoding_context) {
    http_connection_free(connection);
    return NULL;
  }

  connection->streams = hash_table_init_with_int_keys(http_stream_free);

  if (!connection->streams) {
    http_connection_free(connection);
    return NULL;
  }

  connection->write_buffer = binary_buffer_init(NULL, 0);

  if (!connection->write_buffer) {
    http_connection_free(connection);
    return NULL;
  }

  connection->num_requests = 0;

  return connection;
}

static http_stream_t * http_stream_get(http_connection_t * const connection, const uint32_t stream_id)
{

  return hash_table_get(connection->streams, &stream_id);

}

static void http_stream_close(http_connection_t * const connection, http_stream_t * const stream, bool force)
{
  UNUSED(connection);

  if (stream->state == STREAM_STATE_CLOSED) {
    return;
  }

  if (force || (stream->closing && !stream->queued_data_frames)) {

    log_trace("Closing stream #%d", stream->id);

    stream->state = STREAM_STATE_CLOSED;

  }

}

static bool http_stream_closed(http_connection_t * const connection, const uint32_t stream_id)
{

  http_stream_t * stream = http_stream_get(connection, stream_id);

  if (stream) {
    return stream->state == STREAM_STATE_CLOSED;
  }

  return false;

}

static void http_stream_mark_closing(http_connection_t * const connection, http_stream_t * const stream)
{
  UNUSED(connection);

  if (stream->state != STREAM_STATE_CLOSED && !stream->queued_data_frames) {
    stream->closing = true;

    if (stream->id % 2 == 0) {
      connection->outgoing_concurrent_streams--;
    } else {
      connection->incoming_concurrent_streams--;
    }

  }

}

void http_connection_free(http_connection_t * const connection)
{
  hash_table_free(connection->streams);
  hpack_context_free(connection->encoding_context);
  hpack_context_free(connection->decoding_context);
  binary_buffer_free(connection->write_buffer);

  free(connection);
}

static void http_connection_mark_closing(http_connection_t * const connection)
{
  connection->closing = true;
}

static void http_connection_close(http_connection_t * const connection)
{
  if (connection->closed) {
    return;
  }

  if (connection->closing) {
    // TODO loop through streams + close them
    connection->closer(connection->data);
    connection->closed = true;
  }
}

void http_finished_writes(http_connection_t * const connection)
{
  log_trace("Finished write");
  http_connection_close(connection);
}

static bool http_connection_flush(const http_connection_t * const connection, size_t new_length)
{

  size_t buf_length = binary_buffer_size(connection->write_buffer);

  if (buf_length > 0) {

    uint8_t * buf = binary_buffer_start(connection->write_buffer);
    connection->writer(connection->data, buf, buf_length);

    ASSERT_OR_RETURN_FALSE(binary_buffer_reset(connection->write_buffer, new_length));

  }

  return true;
}

static bool http_connection_write(const http_connection_t * const connection, uint8_t * const buf, size_t buf_length)
{

  size_t existing_length = binary_buffer_size(connection->write_buffer);

  if (existing_length + buf_length >= MAX_CONNECTION_BUFFER_SIZE) {
    // if the write buffer doesn't have enough space to accommodate the new buffer then
    // flush the buffer
    ASSERT_OR_RETURN_FALSE(
      http_connection_flush(connection, buf_length < MAX_CONNECTION_BUFFER_SIZE ? buf_length : 0)
    );
  }

  // if the given buffer's size is greater than MAX_CONNECTION_BUFFER_SIZE
  // then just write it directly - don't add it to the write buffer
  if (buf_length > MAX_CONNECTION_BUFFER_SIZE) {
    return connection->writer(connection->data, buf, buf_length);
  }

  ASSERT_OR_RETURN_FALSE(
    binary_buffer_write(connection->write_buffer, buf, buf_length)
  );

  size_t new_length = binary_buffer_size(connection->write_buffer);

  if (new_length + buf_length >= MAX_CONNECTION_BUFFER_SIZE) {
    ASSERT_OR_RETURN_FALSE(
      http_connection_flush(connection, 0)
    );
  }

  return true;
}

static void http_frame_header_write(uint8_t * const buf, const uint32_t length, const uint8_t type, const uint8_t flags,
                                    uint32_t stream_id)
{
  size_t pos = 0;

  buf[pos++] = (length >> 16) & 0xFF;
  buf[pos++] = (length >> 8) & 0xFF;
  buf[pos++] = (length) & 0xFF;

  buf[pos++] = type;

  buf[pos++] = flags;

  buf[pos++] = (stream_id >> 24) & 0x7F; // only the first 7 bits (first bit is reserved)
  buf[pos++] = (stream_id >> 16) & 0xFF;
  buf[pos++] = (stream_id >> 8) & 0xFF;
  buf[pos++] = (stream_id) & 0xFF;
}

static bool http_emit_goaway(const http_connection_t * const connection, enum h2_error_code_e error_code, char * debug)
{

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

  log_debug("Writing goaway frame");

  return http_connection_write(connection, buf, buf_length);
}

static bool http_emit_rst_stream(const http_connection_t * const connection, uint32_t stream_id,
                                 enum h2_error_code_e error_code)
{

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

  log_debug("Writing reset stream frame");

  return http_connection_write(connection, buf, buf_length);
}

static bool emit_error_and_close(http_connection_t * const connection, uint32_t stream_id,
                                 enum h2_error_code_e error_code, char * format, ...)
{

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

    bool success = http_emit_rst_stream(connection, stream_id, error_code);

    if (!success) {
      log_error("Unable to emit reset stream frame");
    }

    return success;

  } else {
    bool success = http_emit_goaway(connection, error_code, format ? buf : NULL);

    if (!success) {
      log_error("Unable to emit goaway frame");
    }

    http_connection_close(connection);

    return success;
  }

}

static bool http_emit_headers(http_connection_t * const connection, const http_stream_t * const stream,
                              const header_list_t * const headers)
{
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

  if (end_stream) {
    flags |= FLAG_END_STREAM;
  }

  if (end_headers) {
    flags |= FLAG_END_HEADERS;
  }

  if (priority) {
    flags |= FLAG_PRIORITY;
  }

  http_frame_header_write(buf, headers_length, FRAME_TYPE_HEADERS, flags, stream->id);

  if (hpack_buf) {
    size_t pos = FRAME_HEADER_SIZE;
    memcpy(buf + pos, hpack_buf, headers_length);
    free(hpack_buf);
  }

  log_debug("Writing headers frame: stream %d, %ld octets", stream->id, buf_length);

  http_connection_write(connection, buf, buf_length);

  return true;
}

static bool http_emit_push_promise(http_connection_t * const connection, const http_stream_t * const stream,
                                   const header_list_t * const headers, const uint32_t associated_stream_id)
{

  // TODO split large headers into multiple frames
  size_t headers_length = 0;
  uint8_t * hpack_buf = NULL;

  if (headers != NULL) {
    binary_buffer_t encoded;

    if (!hpack_encode(connection->encoding_context, headers, &encoded)) {
      // don't send stream ID because we want to generate a goaway - the
      // encoding context may have been corrupted
      emit_error_and_close(connection, 0, HTTP_ERROR_INTERNAL_ERROR, "Error encoding headers");
      return false;
    }

    hpack_buf = encoded.buf;
    headers_length = binary_buffer_size(&encoded);
  }

  const size_t stream_id_length = 4;
  const size_t payload_length = stream_id_length + headers_length;
  const size_t buf_length = FRAME_HEADER_SIZE + payload_length;
  uint8_t buf[buf_length];

  uint8_t flags = 0;
  // TODO - these should be dynamic
  const bool end_stream = false;
  const bool end_headers = true;
  const bool priority = false;

  if (end_stream) {
    flags |= FLAG_END_STREAM;
  }

  if (end_headers) {
    flags |= FLAG_END_HEADERS;
  }

  if (priority) {
    flags |= FLAG_PRIORITY;
  }

  http_frame_header_write(buf, payload_length, FRAME_TYPE_PUSH_PROMISE, flags, stream->id);

  size_t pos = FRAME_HEADER_SIZE;

  buf[pos++] = (associated_stream_id >> 24) & 0x7F; // only the first 7 bits (first bit is reserved)
  buf[pos++] = (associated_stream_id >> 16) & 0xFF;
  buf[pos++] = (associated_stream_id >> 8) & 0xFF;
  buf[pos++] = (associated_stream_id) & 0xFF;

  if (hpack_buf) {
    memcpy(buf + pos, hpack_buf, headers_length);
    free(hpack_buf);
  }

  log_debug("Writing push promise frame: associated stream %d, new stream %d, %ld octets", stream->id,
            associated_stream_id, buf_length);

  return http_connection_write(connection, buf, buf_length);
}

static bool http_emit_data_frame(const http_connection_t * const connection, const http_stream_t * const stream,
                                 const http_queued_frame_t * const frame)
{
  // buffer data frames per connection? - only trigger connection->writer after all emit_data_frames have been written
  // or size threshold has been reached

  size_t header_length = FRAME_HEADER_SIZE;
  uint8_t header_buf[header_length];
  uint8_t flags = 0;

  if (frame->end_stream) {
    flags |= FLAG_END_STREAM;
  }

  http_frame_header_write(header_buf, frame->buf_length, FRAME_TYPE_DATA, flags, stream->id);

  if (!http_connection_write(connection, header_buf, header_length)) {
    return false;
  }

  log_debug("Writing data frame: stream %d, %ld octets", stream->id, frame->buf_length);

  return http_connection_write(connection, frame->buf, frame->buf_length);
}

static bool http_stream_trigger_send_data(http_connection_t * const connection, http_stream_t * const stream)
{

  while (stream->queued_data_frames) {
    log_trace("Sending queued data for stream: %d", stream->id);

    http_queued_frame_t * frame = stream->queued_data_frames;
    size_t frame_payload_size = frame->buf_length;

    bool connection_window_open = (long)frame_payload_size <= connection->outgoing_window_size;
    bool stream_window_open = (long)frame_payload_size <= stream->outgoing_window_size;

    if (connection_window_open && stream_window_open) {
      bool success = http_emit_data_frame(connection, stream, frame);

      if (success) {
        connection->outgoing_window_size -= frame_payload_size;
        stream->outgoing_window_size -= frame_payload_size;
      }

      stream->queued_data_frames = frame->next;

      if (frame->buf_begin) {
        free(frame->buf_begin);
      }

      free(frame);

      if (!success) {
        return false;
      }

    } else {

      return true;

    }

  }

  log_trace("Connection window size: %ld, stream window: %ld", connection->outgoing_window_size,
            stream->outgoing_window_size);

  return true;
}

static bool http_trigger_send_data(http_connection_t * const connection, http_stream_t * stream)
{

  if (stream) {

    return http_stream_trigger_send_data(connection, stream);

  } else {

    log_trace("Sending queued data for open frames");

    // loop through open streams
    hash_table_iter_t iter;
    http_stream_t * prev = NULL;
    hash_table_iterator_init(&iter, connection->streams);

    while (hash_table_iterate(&iter)) {

      if (prev) {
        http_stream_close(connection, prev, false);
        prev = NULL;
      }

      stream = iter.value;

      if (stream->state != STREAM_STATE_CLOSED) {

        if (!http_stream_trigger_send_data(connection, stream)) {
          return false;
        }

        prev = stream;

      }
    }

    if (prev) {
      http_stream_close(connection, prev, false);
      prev = NULL;
    }

    log_trace("Connection window size: %ld", connection->outgoing_window_size);

    return true;
  }

}

static http_queued_frame_t * http_queue_data_frame(http_stream_t * const stream, uint8_t * buf, const size_t buf_length,
    const bool end_stream, void * const buf_begin)
{
  http_queued_frame_t * new_frame = malloc(sizeof(http_queued_frame_t));

  if (!new_frame) {
    log_error("Unable to allocate space for new data frame");
    return NULL;
  }

  new_frame->buf = buf;
  new_frame->buf_length = buf_length;
  new_frame->end_stream = end_stream;
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

  return new_frame;
}

static bool http_emit_data(http_connection_t * const connection, http_stream_t * const stream, uint8_t * in,
                           const size_t in_length, bool last_in)
{
  // TODO support padding?

  if (in_length == 0) {
    if (!http_queue_data_frame(stream, in, in_length, last_in, in)) {
      free(in);
      return false;
    }

    return http_trigger_send_data(connection, stream);
  }

  size_t remaining_length = in_length;
  size_t per_frame_length;
  uint8_t * per_frame_data = in;
  bool last_frame = false;

  bool in_freed = false;

  while (remaining_length > 0) {
    if (remaining_length > connection->max_frame_size) {
      per_frame_length = connection->max_frame_size;
      last_frame = false;
    } else {
      per_frame_length = remaining_length;
      last_frame = true;
    }

    uint8_t * curr_frame_data = per_frame_data;
    size_t curr_frame_length = per_frame_length;

    uint8_t * buf_begin = last_frame ? in : NULL;

    if (buf_begin == in) {
      in_freed = true;
    }

    if (!http_queue_data_frame(stream, curr_frame_data, curr_frame_length, last_in && last_frame, buf_begin)) {

      free(in);
      return false;
    }

    remaining_length -= per_frame_length;
    per_frame_data += per_frame_length;
  }

  bool success = http_trigger_send_data(connection, stream);

  // use after free possible - if a frame in the middle doesn't get compressed (possibly due to the output being bigger than the
  // input, which is unlikely), we will free the input here, but it may be needed afterwards
  if (!in_freed) {
    free(in);
  }

  return success;

}

static bool http_emit_settings_ack(const http_connection_t * const connection)
{
  size_t buf_length = FRAME_HEADER_SIZE;
  uint8_t buf[buf_length];
  uint8_t flags = 0;
  bool ack = true;

  if (ack) {
    flags |= FLAG_ACK;
  }

  http_frame_header_write(buf, 0, FRAME_TYPE_SETTINGS, flags, 0);

  log_debug("Writing settings ack frame");

  return http_connection_write(connection, buf, buf_length);
}

static bool http_emit_ping_ack(const http_connection_t * const connection, uint8_t * opaque_data)
{
  size_t payload_length = PING_OPAQUE_DATA_LENGTH;
  size_t buf_length = FRAME_HEADER_SIZE + payload_length;
  uint8_t buf[buf_length];

  uint8_t flags = 0;
  bool ack = true;

  if (ack) {
    flags |= FLAG_ACK;
  }

  http_frame_header_write(buf, payload_length, FRAME_TYPE_PING, flags, 0);

  log_debug("Writing ping ack frame");

  memcpy(buf + FRAME_HEADER_SIZE, opaque_data, payload_length);

  return http_connection_write(connection, buf, buf_length);
}

static bool http_emit_window_update(const http_connection_t * const connection, const uint32_t stream_id,
                                    const size_t increment)
{

  size_t payload_length = 4;
  size_t buf_length = FRAME_HEADER_SIZE + payload_length;

  size_t pos = 0;
  uint8_t buf[buf_length];

  uint8_t flags = 0; // no flags

  http_frame_header_write(buf, payload_length, FRAME_TYPE_WINDOW_UPDATE, flags, stream_id);
  pos += FRAME_HEADER_SIZE;

  buf[pos++] = (increment >> 24) & 0xFF;
  buf[pos++] = (increment >> 16) & 0xFF;
  buf[pos++] = (increment >> 8) & 0xFF;
  buf[pos++] = (increment) & 0xFF;

  log_debug("Writing window update frame");

  if (!http_connection_write(connection, buf, buf_length)) {
    return false;
  }

  // flush the connection so that we write the window update as soon as possible
  if (!http_connection_flush(connection, 0)) {
    log_warning("Could not flush write buffer after window update");
  }

  return true;
}

#define FRAME_FLAG(frame, mask) \
  http_frame_flag_get((http_frame_t *) frame, mask)

static bool http_frame_flag_get(const http_frame_t * const frame, int mask)
{
  return frame->flags & mask;
}

/**
 * Returns true if the first part of data is the http connection
 * header string
 */
static bool http_connection_recognize_connection_preface(http_connection_t * const connection)
{
  if (connection->buffer_length >= HTTP_CONNECTION_PREFACE_LENGTH) {
    if (memcmp(connection->buffer, HTTP_CONNECTION_PREFACE, HTTP_CONNECTION_PREFACE_LENGTH) == 0) {
      connection->buffer_position = HTTP_CONNECTION_PREFACE_LENGTH;
      return true;
    }
  }

  return false;
}

static void http_adjust_initial_window_size(http_connection_t * const connection, const long difference)
{
  hash_table_iter_t iter;
  hash_table_iterator_init(&iter, connection->streams);

  while (hash_table_iterate(&iter)) {
    http_stream_t * stream = iter.value;

    stream->outgoing_window_size += difference;

    if (stream->outgoing_window_size > MAX_WINDOW_SIZE) {
      emit_error_and_close(connection, stream->id, HTTP_ERROR_FLOW_CONTROL_ERROR, NULL);
    }
  }
}

static bool http_setting_set(http_connection_t * const connection, const enum settings_e id, const uint32_t value)
{
  log_trace("Settings: %d: %d", id, value);

  switch (id) {
    case SETTINGS_HEADER_TABLE_SIZE:
      log_trace("Settings: Got table size: %d", value);

      connection->header_table_size = value;
      hpack_header_table_adjust_size(connection->decoding_context, value);
      break;

    case SETTINGS_ENABLE_PUSH:
      log_trace("Settings: Enable push? %s", value ? "yes" : "no");

      connection->enable_push = value;
      break;

    case SETTINGS_MAX_CONCURRENT_STREAMS:
      log_trace("Settings: Max concurrent streams: %d", value);

      connection->max_concurrent_streams = value;
      break;

    case SETTINGS_INITIAL_WINDOW_SIZE:
      log_trace("Settings: Initial window size: %d", value);

      http_adjust_initial_window_size(connection, value - connection->initial_window_size);
      connection->initial_window_size = value;
      break;

    case SETTINGS_MAX_FRAME_SIZE:
      log_trace("Settings: Initial max frame size: %d", value);

      connection->max_frame_size = value;
      break;

    case SETTINGS_MAX_HEADER_LIST_SIZE:
      log_trace("Settings: Initial max header list size: %d", value);

      // TODO - send to hpack encoding context
      connection->max_header_list_size = value;
      break;

    default:
      emit_error_and_close(connection, 0, HTTP_ERROR_PROTOCOL_ERROR, "Invalid setting: %d", id);
      return false;
  }

  return true;
}

static http_stream_t * http_stream_init(http_connection_t * const connection, const uint32_t stream_id)
{

  log_trace("Opening stream #%d", stream_id);

  http_stream_t * stream = http_stream_get(connection, stream_id);

  if (stream != NULL) {
    emit_error_and_close(connection, stream_id, HTTP_ERROR_PROTOCOL_ERROR,
                         "Got a headers frame for an existing stream");
    return NULL;
  }

  stream = malloc(sizeof(http_stream_t));

  if (!stream) {
    emit_error_and_close(connection, stream_id, HTTP_ERROR_INTERNAL_ERROR,
                         "Unable to initialize stream: %ld", stream_id);
    return NULL;
  }

  long * stream_id_key = malloc(sizeof(long));

  if (!stream_id_key) {
    emit_error_and_close(connection, stream_id, HTTP_ERROR_INTERNAL_ERROR,
                         "Unable to initialize stream (stream identifier): %ld", stream_id);
    free(stream);
    return NULL;
  }

  * stream_id_key = stream_id;
  hash_table_put(connection->streams, stream_id_key, stream);

  stream->queued_data_frames = NULL;

  stream->id = stream_id;
  stream->state = STREAM_STATE_IDLE;
  stream->closing = false;
  stream->header_fragments = NULL;
  stream->headers = NULL;

  stream->priority_exclusive = DEFAULT_STREAM_EXCLUSIVE_FLAG;
  stream->priority_dependency = DEFAULT_STREAM_DEPENDENCY;
  stream->priority_weight = DEFAULT_STREAM_WEIGHT;

  stream->outgoing_window_size = connection->initial_window_size;
  stream->incoming_window_size = DEFAULT_INITIAL_WINDOW_SIZE;

  stream->associated_stream_id = 0;

  return stream;
}

static bool http_trigger_request(http_connection_t * const connection, http_stream_t * const stream)
{
  if (!connection->request_handler) {
    log_fatal("No request handler set up");

    abort();
  }

  http_request_t * request = http_request_init(connection, stream, stream->headers);

  if (!request) {
    return false;
  }

  stream->request = request;

  // transfer ownership of headers to the request
  stream->headers = NULL;

  http_response_t * response = http_response_init(request);
  stream->response = response;

  if (stream->id > connection->last_stream_id) {
    connection->last_stream_id = stream->id;
  }

  connection->request_handler(connection->data, request, response);

  connection->num_requests++;

  return true;
}

static bool strip_padding(uint8_t ** payload, size_t * payload_length, bool padded_on)
{
  if (padded_on) {
    size_t padding_length = get_bits8(*payload, 0xFF);

    (*payload_length)--;
    (*payload)++;
    *payload_length -= padding_length;
    log_trace("Stripped %ld octets of padding from frame", padding_length);
  }

  return true;
}

static bool http_parse_frame_data(http_connection_t * const connection, const http_frame_data_t * const frame)
{
  if (!connection->data_handler) {
    log_fatal("No data handler set up");

    abort();
  }

  http_stream_t * stream = http_stream_get(connection, frame->stream_id);

  if (!stream) {
    emit_error_and_close(connection, frame->stream_id, HTTP_ERROR_PROTOCOL_ERROR,
                         "Unable to find stream #%d", frame->stream_id);
    return true;
  }

  // adjust window sizes
  connection->incoming_window_size -= frame->length;
  stream->incoming_window_size -= frame->length;

  // pass on to application
  uint8_t * buf = connection->buffer + connection->buffer_position;
  size_t buf_length = frame->length;
  bool last_data_frame = FRAME_FLAG(frame, FLAG_END_STREAM);

  bool padded = FRAME_FLAG(frame, FLAG_PADDED);

  if (!strip_padding(&buf, &buf_length, padded)) {
    emit_error_and_close(connection, 0, HTTP_ERROR_PROTOCOL_ERROR,
                         "Problem with padding on data frame");
    return false;
  }

  connection->data_handler(connection->data, stream->request, stream->response, buf, buf_length, last_data_frame, false);

  // do we need to send WINDOW_UPDATE?
  if (connection->incoming_window_size < 0) {

    emit_error_and_close(connection, 0, HTTP_ERROR_FLOW_CONTROL_ERROR, "Connection window size is less than 0: %ld",
                         connection->incoming_window_size);

  } else if (connection->incoming_window_size < 0.75 * DEFAULT_INITIAL_WINDOW_SIZE) {

    size_t increment = DEFAULT_INITIAL_WINDOW_SIZE - connection->incoming_window_size;

    if (!http_emit_window_update(connection, 0, increment)) {
      emit_error_and_close(connection, 0, HTTP_ERROR_INTERNAL_ERROR, "Unable to emit window update frame");
      return false;
    }

    connection->incoming_window_size += increment;

  }

  if (stream->incoming_window_size < 0) {

    emit_error_and_close(connection, stream->id, HTTP_ERROR_FLOW_CONTROL_ERROR,
                         "Stream #%d: window size is less than 0: %ld", stream->incoming_window_size);

  } else if (!last_data_frame && (stream->incoming_window_size < 0.75 * DEFAULT_INITIAL_WINDOW_SIZE)) {

    size_t increment = DEFAULT_INITIAL_WINDOW_SIZE - stream->incoming_window_size;

    if (!http_emit_window_update(connection, stream->id, increment)) {
      emit_error_and_close(connection, stream->id, HTTP_ERROR_INTERNAL_ERROR, "Unable to emit window update frame");
      // don't return false - the connection is still OK
    } else {
      stream->incoming_window_size += increment;
    }

  }

  return true;
}

static bool http_stream_add_header_fragment(http_stream_t * const stream, const uint8_t * const buffer,
    const size_t length)
{
  http_header_fragment_t * fragment = malloc(sizeof(http_header_fragment_t));

  if (!fragment) {
    log_error("Unable to allocate space for header fragment");
    return false;
  }

  fragment->buffer = malloc(length);

  if (!fragment->buffer) {
    log_error("Unable to allocate space for header fragment");
    free(fragment);
    return false;
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

  return true;
}

static bool http_parse_header_fragments(http_connection_t * const connection, http_stream_t * const stream)
{
  size_t headers_length = 0;
  http_header_fragment_t * current = stream->header_fragments;

  for (; current; current = current->next) {
    log_trace("Counting header fragment lengths: %ld", current->length);

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
    log_trace("Appending header fragment (%ld octets)", current->length);

    memcpy(header_appender, current->buffer, current->length);
    header_appender += current->length;
    http_header_fragment_t * prev = current;
    current = current->next;
    free(prev->buffer);
    free(prev);
  }

  *header_appender = '\0';

  log_trace("Got headers: (%ld octets), decoding", headers, headers_length);

  stream->headers = hpack_decode(connection->decoding_context, headers, headers_length);

  if (!stream->headers) {
    emit_error_and_close(connection, stream->id, HTTP_ERROR_COMPRESSION_ERROR, "Unable to decode headers");
    free(headers);
    return false;
  }

  // TODO - check that the stream is in a valid state to be opened first
  stream->state = STREAM_STATE_OPEN;
  connection->incoming_concurrent_streams++;

  free(headers);

  // TODO - check that the stream is not closed?
  if (!connection->closing) {
    return http_trigger_request(connection, stream);
  }

  return true;
}

static bool http_parse_frame_headers(http_connection_t * const connection, const http_frame_headers_t * const frame)
{
  uint8_t * buf = connection->buffer + connection->buffer_position;
  size_t buf_length = frame->length;
  http_stream_t * stream = http_stream_init(connection, frame->stream_id);

  if (!stream) {
    return false;
  }

  bool padded = FRAME_FLAG(frame, FLAG_PADDED);

  if (!strip_padding(&buf, &buf_length, padded)) {
    emit_error_and_close(connection, 0, HTTP_ERROR_PROTOCOL_ERROR,
                         "Problem with padding on header frame");
    return false;
  }

  if (FRAME_FLAG(frame, FLAG_PRIORITY)) {

    stream->priority_exclusive = get_bit(buf, 0);
    stream->priority_dependency = get_bits32(buf, 0x7FFFFFFF);
    // add 1 to get a value between 1 and 256
    stream->priority_weight = get_bits8(buf + 4, 0xFF) + 1;

    log_trace("Stream #%d priority: exclusive: %s, dependency: %d, weight: %d",
              stream->id, stream->priority_exclusive ? "yes" : "no", stream->priority_dependency,
              stream->priority_weight);

    buf += 5;
    buf_length -= 5;
  }

  if (!http_stream_add_header_fragment(stream, buf, buf_length)) {
    return false;
  }

  if (FRAME_FLAG(frame, FLAG_END_HEADERS)) {
    // parse the headers
    log_trace("Parsing headers");

    bool success = http_parse_header_fragments(connection, stream);

    if (!success) {
      emit_error_and_close(connection, stream->id, HTTP_ERROR_INTERNAL_ERROR, "Unable to process stream");
    }
  } else {
    // TODO mark stream as waiting for continuation frame
  }

  return true;
}

static bool http_parse_frame_continuation(http_connection_t * const connection,
    const http_frame_continuation_t * const frame)
{
  uint8_t * buf = connection->buffer + connection->buffer_position;
  size_t buf_length = frame->length;
  http_stream_t * stream = http_stream_get(connection, frame->stream_id);

  bool padded = FRAME_FLAG(frame, FLAG_PADDED);

  if (!strip_padding(&buf, &buf_length, padded)) {
    emit_error_and_close(connection, 0, HTTP_ERROR_PROTOCOL_ERROR,
                         "Problem with padding on data frame");
    return false;
  }

  if (!http_stream_add_header_fragment(stream, buf, buf_length)) {
    return false;
  }

  if (FRAME_FLAG(frame, FLAG_END_HEADERS)) {
    // TODO unmark stream as waiting for continuation frame
    // parse the headers
    log_trace("Parsing headers + continuations");

    return http_parse_header_fragments(connection, stream);
  }

  return true;
}

static bool http_parse_frame_settings(http_connection_t * const connection, const http_frame_settings_t * const frame)
{

  if (FRAME_FLAG(frame, FLAG_ACK)) {

    if (frame->length != 0) {
      emit_error_and_close(connection, 0, HTTP_ERROR_FRAME_SIZE_ERROR, "Non-zero frame size for ACK settings frame: %ld",
                           frame->length);
      return false;
    }

    log_trace("Received settings ACK");

    // Mark the settings frame we sent as acknowledged.
    // We currently don't send any settings that require
    // synchonization
    return true;

  } else {
    uint8_t * pos = connection->buffer + connection->buffer_position;
    size_t num_settings = frame->length / SETTING_SIZE;

    log_trace("Settings: Found #%ld settings", num_settings);

    size_t i;

    for (i = 0; i < num_settings; i++) {
      uint8_t * curr_setting = pos + (i * SETTING_SIZE);
      uint16_t setting_id = get_bits16(curr_setting, 0xFFFF);
      uint32_t setting_value = get_bits32(curr_setting + SETTING_ID_SIZE, 0xFFFFFFFF);

      if (!http_setting_set(connection, setting_id, setting_value)) {
        return false;
      }
    }

    connection->received_settings = true;

    log_trace("Settings: %ld, %d, %ld, %ld", connection->header_table_size, connection->enable_push,
              connection->max_concurrent_streams, connection->initial_window_size);

    return http_emit_settings_ack(connection);
  }

}

static bool http_parse_frame_ping(http_connection_t * const connection, const http_frame_ping_t * const frame)
{
  UNUSED(frame);

  uint8_t * opaque_data = connection->buffer + connection->buffer_position;
  return http_emit_ping_ack(connection, opaque_data);

}

static bool http_increment_connection_window_size(http_connection_t * const connection, const uint32_t increment)
{
  connection->outgoing_window_size += increment;

  log_trace("Connection window size incremented to: %ld", connection->outgoing_window_size);

  return http_trigger_send_data(connection, NULL);
}

static bool http_increment_stream_window_size(http_connection_t * const connection, const uint32_t stream_id,
    const uint32_t increment)
{

  if (http_stream_closed(connection, stream_id)) {
    log_trace("Can't update stream #%ld's window size, already closed", stream_id);
    // the stream may have been recently closed, ignore
    return true;
  }

  http_stream_t * stream = http_stream_get(connection, stream_id);

  if (!stream) {
    emit_error_and_close(connection, stream_id, HTTP_ERROR_PROTOCOL_ERROR,
                         "Could not find stream #%d to update it's window size", stream_id);
    return false;
  }

  stream->outgoing_window_size += increment;

  log_trace("Stream window size incremented to: %ld", stream->outgoing_window_size);

  return http_trigger_send_data(connection, stream);

}

static bool http_parse_frame_window_update(http_connection_t * const connection,
    http_frame_window_update_t * const frame)
{
  uint8_t * buf = connection->buffer + connection->buffer_position;
  frame->increment = get_bits32(buf, 0x7FFFFFFF);

  bool success = false;

  if (frame->stream_id > 0) {
    success = http_increment_stream_window_size(connection, frame->stream_id, frame->increment);
  } else {
    success = http_increment_connection_window_size(connection, frame->increment);
  }

  log_trace("Received window update, stream: %d, increment: %ld",
            frame->stream_id, frame->increment);

  return success;
}

static bool http_parse_frame_rst_stream(http_connection_t * const connection, http_frame_rst_stream_t * const frame)
{
  uint8_t * buf = connection->buffer + connection->buffer_position;
  frame->error_code = get_bits32(buf, 0xFFFFFFFF);

  log_warning("Received reset stream: stream #%d, error code: %s (%d)",
              frame->stream_id, http_connection_errors[frame->error_code], frame->error_code);

  http_stream_t * stream = http_stream_get(connection, frame->stream_id);

  http_stream_close(connection, stream, true);

  return true;
}

static bool http_parse_frame_priority(http_connection_t * const connection, http_frame_priority_t * const frame)
{
  uint8_t * buf = connection->buffer + connection->buffer_position;

  http_stream_t * stream = http_stream_get(connection, frame->stream_id);

  if (!stream) {
    emit_error_and_close(connection, frame->stream_id, HTTP_ERROR_PROTOCOL_ERROR, "Unknown stream id: %d",
                         frame->stream_id);
    return true;
  }

  stream->priority_exclusive = get_bit(buf, 0);
  stream->priority_dependency = get_bits32(buf, 0x7FFFFFFF);
  // add 1 to get a value between 1 and 256
  stream->priority_weight = get_bits8(buf + 4, 0xFF) + 1;

  return true;
}

static bool http_parse_frame_goaway(http_connection_t * const connection, http_frame_goaway_t * const frame)
{

  uint8_t * buf = connection->buffer + connection->buffer_position;
  frame->last_stream_id = get_bits32(buf, 0x7FFFFFFF);
  frame->error_code = get_bits32(buf + 4, 0xFFFFFFFF);
  size_t debug_data_length = (frame->length - 8);

  uint8_t debug_data[debug_data_length + 1];
  memcpy(debug_data, buf + 8, debug_data_length);
  debug_data[debug_data_length] = '\0';
  frame->debug_data = debug_data;

  if (frame->error_code == HTTP_ERROR_NO_ERROR) {
    log_trace("Received goaway, last stream: %d, error code: %s (%d), debug_data: %s",
              frame->last_stream_id, http_connection_errors[frame->error_code],
              frame->error_code, frame->debug_data);
    http_connection_mark_closing(connection);
  } else {
    log_error("Received goaway, last stream: %d, error code: %s (%d), debug_data: %s",
              frame->last_stream_id, http_connection_errors[frame->error_code],
              frame->error_code, frame->debug_data);
  }

  frame->debug_data = NULL;

  return true;
}

static http_frame_t * http_frame_init(http_connection_t * const connection, const uint32_t length, const uint8_t type,
                                      const uint8_t flags, const uint32_t stream_id)
{
  http_frame_t * frame;

  switch (type) {
    case FRAME_TYPE_DATA:
      frame = (http_frame_t *) malloc(sizeof(http_frame_data_t));
      break;

    case FRAME_TYPE_HEADERS:
      frame = (http_frame_t *) malloc(sizeof(http_frame_headers_t));
      break;

    case FRAME_TYPE_PRIORITY:
      frame = (http_frame_t *) malloc(sizeof(http_frame_priority_t));
      break;

    case FRAME_TYPE_RST_STREAM:
      frame = (http_frame_t *) malloc(sizeof(http_frame_rst_stream_t));
      break;

    case FRAME_TYPE_SETTINGS:
      frame = (http_frame_t *) malloc(sizeof(http_frame_settings_t));
      break;

    case FRAME_TYPE_PUSH_PROMISE:
      frame = (http_frame_t *) malloc(sizeof(http_frame_push_promise_t));
      break;

    case FRAME_TYPE_PING:
      frame = (http_frame_t *) malloc(sizeof(http_frame_ping_t));
      break;

    case FRAME_TYPE_GOAWAY:
      frame = (http_frame_t *) malloc(sizeof(http_frame_goaway_t));
      break;

    case FRAME_TYPE_WINDOW_UPDATE:
      frame = (http_frame_t *) malloc(sizeof(http_frame_window_update_t));
      break;

    case FRAME_TYPE_CONTINUATION:
      frame = (http_frame_t *) malloc(sizeof(http_frame_continuation_t));
      break;

    default:
      emit_error_and_close(connection, stream_id, HTTP_ERROR_INTERNAL_ERROR, "Unhandled frame type");
      return NULL;
  }

  frame->type = type;
  frame->flags = flags;
  frame->length = length;
  frame->stream_id = stream_id;
  return frame;
}

static bool is_valid_frame_type(enum frame_type_e frame_type)
{

  return frame_type >= FRAME_TYPE_MIN && frame_type <= FRAME_TYPE_MAX;

}

static bool is_valid_frame(http_connection_t * const connection, http_frame_t * frame)
{
  enum frame_type_e frame_type = frame->type;
  frame_parser_definition_t def = frame_parser_definitions[frame_type];

  if (frame->length < def.length_min) {
    emit_error_and_close(connection, frame->stream_id, HTTP_ERROR_FRAME_SIZE_ERROR, "Invalid frame length");
    return false;
  }

  if (frame->length > def.length_max) {
    emit_error_and_close(connection, frame->stream_id, HTTP_ERROR_FRAME_SIZE_ERROR, "Invalid frame length");
    return false;
  }

  size_t i;

  for (i = 0; i < 8; i++) {
    bool can_be_set = def.flags[i];

    if (!can_be_set) {
      uint8_t mask = 1 << i;

      if (frame->flags & mask) {
        emit_error_and_close(connection, frame->stream_id, HTTP_ERROR_PROTOCOL_ERROR, "Invalid flag set");
        return false;
      }
    }
  }

  if (frame->stream_id == 0 && def.must_have_stream_id) {
    emit_error_and_close(connection, frame->stream_id, HTTP_ERROR_FRAME_SIZE_ERROR, "Stream ID must be set");
    return false;
  }

  if (frame->stream_id > 0 && def.must_not_have_stream_id) {
    emit_error_and_close(connection, frame->stream_id, HTTP_ERROR_FRAME_SIZE_ERROR, "Stream ID must not be set");
    return false;
  }

  return true;
}

/**
 * Processes the next frame in the buffer.
 *
 * Returns true a frame was processed.
 * Returns false if there was no frame to process.
 */
static bool http_connection_add_from_buffer(http_connection_t * const connection)
{
  log_trace("Reading %ld bytes", connection->buffer_length);

  if (connection->buffer_position == connection->buffer_length) {
    log_trace("Finished with current buffer");

    return false;
  }

  // is there enough in the buffer to read a frame header?
  if (connection->buffer_position + FRAME_HEADER_SIZE > connection->buffer_length) {
    // TODO off-by-one?
    log_trace("Not enough in buffer to read frame header");

    return false;
  }

  uint8_t * pos = connection->buffer + connection->buffer_position;

  // Read the frame header
  // get first 3 bytes
  uint32_t frame_length = get_bits32(pos, 0xFFFFFF00) >> 8;

  // is there enough in the buffer to read the frame payload?
  if (connection->buffer_position + FRAME_HEADER_SIZE + frame_length <= connection->buffer_length) {

    uint8_t frame_type = pos[3];
    uint8_t frame_flags = pos[4];
    // get 31 bits
    uint32_t stream_id = get_bits32(pos + 5, 0x7FFFFFFF);

    // is this a valid frame type?
    if (!is_valid_frame_type(frame_type)) {
      // invalid frame type is always a connection error
      emit_error_and_close(connection, 0, HTTP_ERROR_PROTOCOL_ERROR, "Invalid Frame Type: %d", frame_type);
      return false;
    }

    // TODO - if the previous frame type was headers, and headers haven't been completed,
    // this frame must be a continuation frame, or else this is a protocol error

    http_frame_t * frame = http_frame_init(connection, frame_length, frame_type, frame_flags, stream_id);

    if (frame == NULL || !is_valid_frame(connection, frame)) {
      return false;
    }

    connection->buffer_position += FRAME_HEADER_SIZE;
    // TODO off-by-one?
    bool success = false;

    if (!connection->received_settings && frame->type != FRAME_TYPE_SETTINGS) {
      emit_error_and_close(connection, 0, HTTP_ERROR_PROTOCOL_ERROR, "Expected Settings frame as first frame");
    } else {
      /**
       * The http_parse_frame_xxx functions should return true if the next frame should be allowed to
       * continue to be processed. Connection errors usually prevent the rest of the frames from
       * being processed.
       */
      switch (frame->type) {
        case FRAME_TYPE_DATA:
          success = http_parse_frame_data(connection, (http_frame_data_t *) frame);
          break;

        case FRAME_TYPE_HEADERS:
          success = http_parse_frame_headers(connection, (http_frame_headers_t *) frame);
          break;

        case FRAME_TYPE_PRIORITY:
          success = http_parse_frame_priority(connection, (http_frame_priority_t *) frame);
          break;

        case FRAME_TYPE_RST_STREAM:
          success = http_parse_frame_rst_stream(connection, (http_frame_rst_stream_t *) frame);
          break;

        case FRAME_TYPE_SETTINGS:
          success = http_parse_frame_settings(connection, (http_frame_settings_t *) frame);
          break;

        case FRAME_TYPE_PUSH_PROMISE:
          emit_error_and_close(connection, 0, HTTP_ERROR_PROTOCOL_ERROR, "Server does not accept PUSH_PROMISE frames");
          return false;

        case FRAME_TYPE_PING:
          success = http_parse_frame_ping(connection, (http_frame_ping_t *) frame);
          break;

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
    log_trace("Not enough in buffer to read %ld byte frame payload", frame_length);
  }

  return false;
}

/**
 * Reads the given buffer and acts on it. Caller must give up ownership of the
 * buffer.
 */
void http_connection_read(http_connection_t * const connection, uint8_t * const buffer, const size_t len)
{
  log_trace("Reading from buffer: %ld", len);

  size_t unprocessed_bytes = connection->buffer_length;

  if (unprocessed_bytes > 0) {
    log_trace("Appending new data to uncprocessed bytes %ld + %ld = %ld", unprocessed_bytes, len, unprocessed_bytes + len);
    // there are still unprocessed bytes
    connection->buffer = realloc(connection->buffer, unprocessed_bytes + len);

    if (!connection->buffer) {
      emit_error_and_close(connection, 0, HTTP_ERROR_INTERNAL_ERROR, "Unable to allocate memory for reading full frame");
      free(buffer);
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

  if (!connection->received_connection_preface) {
    if (http_connection_recognize_connection_preface(connection)) {
      connection->received_connection_preface = true;

      log_trace("Found HTTP2 connection");
    } else {
      log_warning("Found non-HTTP2 connection, closing connection");

      http_connection_mark_closing(connection);
      http_connection_close(connection);
      return;
    }
  }

  connection->reading_from_client = true;

  while (http_connection_add_from_buffer(connection));

  connection->reading_from_client = false;

  if (!http_connection_flush(connection, 0)) {
    log_warning("Could not flush write buffer");
  }

  if (connection->buffer_position > connection->buffer_length) {
    // buffer overflow
    emit_error_and_close(connection, 0, HTTP_ERROR_INTERNAL_ERROR, NULL);
    return;
  }

  // if there is still unprocessed data in the buffer, save it for when we
  // get the rest of the frame
  unprocessed_bytes = connection->buffer_length - connection->buffer_position;

  if (!connection->closing && unprocessed_bytes > 0) {
    log_trace("Unable to process last %ld bytes", unprocessed_bytes);
    // use memmove because it might overlap
    memmove(connection->buffer, connection->buffer + connection->buffer_position, unprocessed_bytes);
    connection->buffer = realloc(connection->buffer, unprocessed_bytes);
    connection->buffer_length = unprocessed_bytes;
    connection->buffer_position = 0;
  } else {
    free(connection->buffer);
    connection->buffer = NULL;
    connection->buffer_length = 0;
  }

}

void http_connection_eof(http_connection_t * const connection)
{
  http_connection_mark_closing(connection);
  http_connection_close(connection);
}

bool http_response_write(http_response_t * const response, uint8_t * data, const size_t data_length, bool last)
{
  char status_buf[10];
  snprintf(status_buf, 10, "%d", response->status);
  // add the status header
  http_response_pseudo_header_add(response, ":status", status_buf);

  http_connection_t * connection = (http_connection_t *)response->request->connection;
  http_stream_t * stream = (http_stream_t *)response->request->stream;

  if (stream->state != STREAM_STATE_CLOSED) {
    if (!http_emit_headers(connection, stream, response->headers)) {
      emit_error_and_close(connection, stream->id, HTTP_ERROR_INTERNAL_ERROR, "Unable to emit headers");
      return false;
    }

    if (data || last) {
      if (!http_emit_data(connection, stream, data, data_length, last)) {
        emit_error_and_close(connection, stream->id, HTTP_ERROR_INTERNAL_ERROR, "Unable to emit data");
        return false;
      }
    }
  }

  if (last && !connection->reading_from_client) {
    http_connection_flush(connection, 0);
  }

  if (last) {
    http_response_free(response);

    http_stream_mark_closing(connection, stream);
  }

  return true;
}

bool http_response_write_data(http_response_t * const response, uint8_t * data, const size_t data_length, bool last)
{

  http_connection_t * connection = (http_connection_t *)response->request->connection;
  http_stream_t * stream = (http_stream_t *)response->request->stream;

  if (data || last) {
    if (!http_emit_data(connection, stream, data, data_length, last)) {
      emit_error_and_close(connection, stream->id, HTTP_ERROR_INTERNAL_ERROR, "Unable to emit data");
      return false;
    }
  }

  if (last && !connection->reading_from_client) {
    http_connection_flush(connection, 0);
  }

  if (last) {
    http_response_free(response);

    http_stream_mark_closing(connection, stream);
  }

  return true;

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

  if (!PUSH_ENABLED) {
    return NULL;
  }

  http_connection_t * connection = (http_connection_t *) original_request->connection;

  if (!connection->enable_push) {
    return NULL;
  }

  http_stream_t * stream = (http_stream_t *) original_request->stream;

  if (connection->outgoing_concurrent_streams >= connection->max_concurrent_streams) {
    log_debug("Tried opening more than %ld outgoing concurrent streams: stream #%d",
              connection->max_concurrent_streams, stream->id);
    return NULL;
  } else {
    log_debug("Push #%ld for stream: stream #%d\n",
              connection->outgoing_concurrent_streams, stream->id);
  }

  http_stream_t * pushed_stream = http_stream_init(connection, connection->current_stream_id);
  ASSERT_OR_RETURN_NULL(pushed_stream);
  connection->current_stream_id += 2;

  pushed_stream->state = STREAM_STATE_RESERVED_LOCAL;
  connection->outgoing_concurrent_streams++;

  pushed_stream->associated_stream_id = stream->id;

  http_request_t * pushed_request = http_request_init(connection, pushed_stream, NULL);
  ASSERT_OR_RETURN_NULL(pushed_request);

  pushed_stream->request = pushed_request;

  return pushed_request;

}

bool http_push_promise(http_request_t * const request)
{

  http_connection_t * connection = (http_connection_t *) request->connection;
  http_stream_t * stream = (http_stream_t *) request->stream;
  http_stream_t * associated_stream = http_stream_get(connection, stream->associated_stream_id);

  return http_emit_push_promise(connection, associated_stream, request->headers, stream->id);

}

http_response_t * http_push_response_get(http_request_t * const request)
{

  http_stream_t * stream = (http_stream_t *) request->stream;

  http_response_t * pushed_response = http_response_init(request);
  stream->response = pushed_response;

  return pushed_response;

}

