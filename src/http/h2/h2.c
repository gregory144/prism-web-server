#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "base64url.h"
#include "util.h"

#include "h2.h"
#include "http/request.h"
#include "http/response.h"

#define FRAME_HEADER_SIZE 9 // octets
#define DEFAULT_STREAM_EXCLUSIVE_FLAG 0
#define DEFAULT_STREAM_DEPENDENCY 0
#define DEFAULT_STREAM_WEIGHT 16
#define SETTING_ID_SIZE 2
#define SETTING_VALUE_SIZE 4
#define SETTING_SIZE (SETTING_ID_SIZE + SETTING_VALUE_SIZE)

#define MAX_WINDOW_SIZE 0x7FFFFFFF // 2^31 - 1
#define MAX_CONNECTION_BUFFER_SIZE 0x100000 // 2^20

#define PING_OPAQUE_DATA_LENGTH 8

const char * H2_CONNECTION_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const size_t H2_CONNECTION_PREFACE_LENGTH = 24;

static const char * const H2_ERRORS[] = {
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

static const char * const HTTP2_CIPHERS[] = {
  "ECDHE-RSA-AES128-GCM-SHA256",
  "ECDHE-ECDSA-AES128-GCM-SHA256",
  "ECDHE-RSA-AES256-GCM-SHA384",
  "ECDHE-ECDSA-AES256-GCM-SHA384",
  "DHE-RSA-AES128-GCM-SHA256"
  "DHE-DSS-AES128-GCM-SHA256"
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

bool h2_detect_connection(uint8_t * buffer, size_t buffer_length)
{
  if (buffer_length >= H2_CONNECTION_PREFACE_LENGTH) {
    if (memcmp(buffer, H2_CONNECTION_PREFACE, H2_CONNECTION_PREFACE_LENGTH) == 0) {
      return true;
    }
  }

  return false;
}

static void h2_stream_free(void * value)
{
  h2_stream_t * stream = value;

  if (stream->headers) {
    header_list_free(stream->headers);
  }

  // Free any remaining data frames. This may need to happen
  // for streams that have been reset
  while (stream->queued_data_frames) {

    h2_queued_frame_t * frame = stream->queued_data_frames;

    stream->queued_data_frames = frame->next;

    if (frame->buf_begin) {
      free(frame->buf_begin);
    }

    free(frame);

  }

  free(stream);
}

static h2_stream_t * h2_stream_get(h2_t * const h2, const uint32_t stream_id)
{

  return hash_table_get(h2->streams, &stream_id);

}

static void h2_stream_close(h2_t * const h2, h2_stream_t * const stream, bool force)
{
  if (stream->state == STREAM_STATE_CLOSED) {
    return;
  }

  if (force || (stream->closing && !stream->queued_data_frames)) {

    log_append(h2->log, LOG_TRACE, "Closing stream #%d", stream->id);

    stream->state = STREAM_STATE_CLOSED;

  }

}

static bool h2_stream_closed(h2_t * const h2, const uint32_t stream_id)
{

  h2_stream_t * stream = h2_stream_get(h2, stream_id);

  if (stream) {
    return stream->state == STREAM_STATE_CLOSED;
  }

  return false;

}

static void h2_stream_mark_closing(h2_t * const h2, h2_stream_t * const stream)
{

  if (stream->state != STREAM_STATE_CLOSED && !stream->queued_data_frames) {
    stream->closing = true;

    if (stream->id % 2 == 0) {
      h2->outgoing_concurrent_streams--;
    } else {
      h2->incoming_concurrent_streams--;
    }

  }

}

h2_t * h2_init(void * const data, log_context_t * log, log_context_t * hpack_log, const char * tls_version,
    const char * cipher, int cipher_key_size_in_bits, const h2_request_cb request_handler,
    const h2_data_cb data_handler, const h2_write_cb writer, const h2_close_cb closer,
    const h2_request_init_cb request_init)
{
  h2_t * h2 = malloc(sizeof(h2_t));
  ASSERT_OR_RETURN_NULL(h2);

  h2->data = data;
  h2->log = log;

  h2->request_handler = request_handler;
  h2->data_handler = data_handler;
  h2->writer = writer;
  h2->closer = closer;
  h2->request_init = request_init;

  h2->tls_version = tls_version;
  h2->cipher = cipher;
  h2->cipher_key_size_in_bits = cipher_key_size_in_bits;
  h2->verified_tls_settings = false;
  h2->received_connection_preface = false;
  h2->received_settings = false;
  h2->last_stream_id = 0;
  h2->current_stream_id = 2;
  h2->outgoing_window_size = DEFAULT_INITIAL_WINDOW_SIZE;
  h2->incoming_window_size = DEFAULT_INITIAL_WINDOW_SIZE;
  h2->closing = false;
  h2->closed = false;

  h2->outgoing_concurrent_streams = 0;
  h2->incoming_concurrent_streams = 0;

  h2->buffer = NULL;
  h2->buffer_length = 0;
  h2->buffer_position = 0;
  h2->reading_from_client = false;

  h2->header_table_size = DEFAULT_HEADER_TABLE_SIZE;
  h2->enable_push = DEFAULT_ENABLE_PUSH;
  h2->max_concurrent_streams = DEFAULT_MAX_CONNCURRENT_STREAMS;
  h2->initial_window_size = DEFAULT_INITIAL_WINDOW_SIZE;
  h2->max_frame_size = DEFAULT_MAX_FRAME_SIZE;
  h2->max_header_list_size = DEFAULT_MAX_HEADER_LIST_SIZE;

  /**
   * Set these to NULL, http_h2_free requires the values to be set
   * to something other than garbage
   */
  h2->encoding_context = NULL;
  h2->decoding_context = NULL;
  h2->streams = NULL;

  h2->encoding_context = hpack_context_init(DEFAULT_HEADER_TABLE_SIZE, hpack_log);

  if (!h2->encoding_context) {
    h2_free(h2);
    return NULL;
  }

  h2->decoding_context = hpack_context_init(h2->header_table_size, hpack_log);

  if (!h2->decoding_context) {
    h2_free(h2);
    return NULL;
  }

  h2->streams = hash_table_init_with_int_keys(h2_stream_free);

  if (!h2->streams) {
    h2_free(h2);
    return NULL;
  }

  binary_buffer_init(&h2->write_buffer, 0);

  return h2;
}

void h2_free(h2_t * const h2)
{
  hash_table_free(h2->streams);
  hpack_context_free(h2->encoding_context);
  hpack_context_free(h2->decoding_context);

  binary_buffer_free(&h2->write_buffer);

  free(h2);
}

static void h2_mark_closing(h2_t * const h2)
{
  h2->closing = true;
}

static void h2_close(h2_t * const h2)
{
  if (h2->closed) {
    return;
  }

  if (h2->closing) {
    // TODO loop through streams + close them
    h2->closer(h2->data);
    h2->closed = true;
  }
}

void h2_finished_writes(h2_t * const h2)
{
  log_append(h2->log, LOG_TRACE, "Finished write");
  h2_close(h2);
}

static bool h2_flush(const h2_t * const h2, size_t new_length)
{

  size_t buf_length = binary_buffer_size(&h2->write_buffer);

  if (buf_length > 0) {

    uint8_t * buf = binary_buffer_start(&h2->write_buffer);
    h2->writer(h2->data, buf, buf_length);

    binary_buffer_t * const wb = (binary_buffer_t * const) &h2->write_buffer;
    ASSERT_OR_RETURN_FALSE(binary_buffer_reset(wb, new_length));
  }

  return true;
}

static bool h2_write(const h2_t * const h2, uint8_t * const buf, size_t buf_length)
{

  size_t existing_length = binary_buffer_size(&h2->write_buffer);

  if (existing_length + buf_length >= MAX_CONNECTION_BUFFER_SIZE) {
    // if the write buffer doesn't have enough space to accommodate the new buffer then
    // flush the buffer
    ASSERT_OR_RETURN_FALSE(
      h2_flush(h2, buf_length < MAX_CONNECTION_BUFFER_SIZE ? buf_length : 0)
    );
  }

  // if the given buffer's size is greater than MAX_CONNECTION_BUFFER_SIZE
  // then just write it directly - don't add it to the write buffer
  if (buf_length > MAX_CONNECTION_BUFFER_SIZE) {
    return h2->writer(h2->data, buf, buf_length);
  }

  binary_buffer_t * const wb = (binary_buffer_t * const) &h2->write_buffer;
  ASSERT_OR_RETURN_FALSE(
    binary_buffer_write(wb, buf, buf_length)
  );

  size_t new_length = binary_buffer_size(&h2->write_buffer);

  if (new_length + buf_length >= MAX_CONNECTION_BUFFER_SIZE) {
    ASSERT_OR_RETURN_FALSE(
      h2_flush(h2, 0)
    );
  }

  return true;
}

static void h2_frame_header_write(uint8_t * const buf, const uint32_t length, const uint8_t type, const uint8_t flags,
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

static bool h2_emit_goaway(const h2_t * const h2, enum h2_error_code_e error_code, char * debug)
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

  h2_frame_header_write(buf, payload_length, FRAME_TYPE_GOAWAY, flags, 0);
  pos += FRAME_HEADER_SIZE;

  size_t stream_id = h2->last_stream_id;

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

  log_append(h2->log, LOG_DEBUG, "Writing goaway frame");

  return h2_write(h2, buf, buf_length);
}

static bool h2_emit_rst_stream(const h2_t * const h2, uint32_t stream_id,
                               enum h2_error_code_e error_code)
{

  size_t error_code_length = 4; // 32 bits

  size_t payload_length = error_code_length;
  size_t buf_length = FRAME_HEADER_SIZE + payload_length;

  size_t pos = 0;
  uint8_t buf[buf_length];

  uint8_t flags = 0; // no flags

  h2_frame_header_write(buf, payload_length, FRAME_TYPE_RST_STREAM, flags, stream_id);
  pos += FRAME_HEADER_SIZE;

  buf[pos++] = (error_code >> 24) & 0xFF;
  buf[pos++] = (error_code >> 16) & 0xFF;
  buf[pos++] = (error_code >> 8) & 0xFF;
  buf[pos++] = (error_code) & 0xFF;

  log_append(h2->log, LOG_DEBUG, "Writing reset stream frame");

  return h2_write(h2, buf, buf_length);
}

static bool emit_error_and_close(h2_t * const h2, uint32_t stream_id,
                                 enum h2_error_code_e error_code, char * format, ...)
{

  size_t buf_length = 1024;
  char buf[buf_length];

  if (format) {
    va_list ap;
    va_start(ap, format);
    vsnprintf(buf, buf_length, format, ap);
    va_end(ap);

    if (error_code != H2_ERROR_NO_ERROR) {
      log_append(h2->log, LOG_ERROR, buf);
    }
  }

  if (stream_id > 0) {

    bool success = h2_emit_rst_stream(h2, stream_id, error_code);

    if (!success) {
      log_append(h2->log, LOG_ERROR, "Unable to emit reset stream frame");
    }

    return success;

  } else {
    bool success = h2_emit_goaway(h2, error_code, format ? buf : NULL);

    if (!success) {
      log_append(h2->log, LOG_ERROR, "Unable to emit goaway frame");
    }

    h2_close(h2);

    return success;
  }

}

static bool h2_emit_headers(h2_t * const h2, const h2_stream_t * const stream,
                            const header_list_t * const headers)
{
  // TODO split large headers into multiple frames
  size_t headers_length = 0;
  uint8_t * hpack_buf = NULL;

  if (headers != NULL) {
    binary_buffer_t encoded;

    if (!hpack_encode(h2->encoding_context, headers, &encoded)) {
      // don't send stream ID because we want to generate a goaway - the
      // encoding context may have been corrupted
      emit_error_and_close(h2, 0, H2_ERROR_INTERNAL_ERROR, "Error encoding headers");
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

  h2_frame_header_write(buf, headers_length, FRAME_TYPE_HEADERS, flags, stream->id);

  if (hpack_buf) {
    size_t pos = FRAME_HEADER_SIZE;
    memcpy(buf + pos, hpack_buf, headers_length);
    free(hpack_buf);
  }

  log_append(h2->log, LOG_DEBUG, "Writing headers frame: stream %d, %ld octets", stream->id, buf_length);

  h2_write(h2, buf, buf_length);

  return true;
}

static bool h2_emit_push_promise(h2_t * const h2, const h2_stream_t * const stream,
                                 const header_list_t * const headers, const uint32_t associated_stream_id)
{

  // TODO split large headers into multiple frames
  size_t headers_length = 0;
  uint8_t * hpack_buf = NULL;

  if (headers != NULL) {
    binary_buffer_t encoded;

    if (!hpack_encode(h2->encoding_context, headers, &encoded)) {
      // don't send stream ID because we want to generate a goaway - the
      // encoding context may have been corrupted
      emit_error_and_close(h2, 0, H2_ERROR_INTERNAL_ERROR, "Error encoding headers");
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

  h2_frame_header_write(buf, payload_length, FRAME_TYPE_PUSH_PROMISE, flags, stream->id);

  size_t pos = FRAME_HEADER_SIZE;

  buf[pos++] = (associated_stream_id >> 24) & 0x7F; // only the first 7 bits (first bit is reserved)
  buf[pos++] = (associated_stream_id >> 16) & 0xFF;
  buf[pos++] = (associated_stream_id >> 8) & 0xFF;
  buf[pos++] = (associated_stream_id) & 0xFF;

  if (hpack_buf) {
    memcpy(buf + pos, hpack_buf, headers_length);
    free(hpack_buf);
  }

  log_append(h2->log, LOG_DEBUG, "Writing push promise frame: associated stream %d, new stream %d, %ld octets", stream->id,
            associated_stream_id, buf_length);

  return h2_write(h2, buf, buf_length);
}

static bool h2_emit_data_frame(const h2_t * const h2, const h2_stream_t * const stream,
                               const h2_queued_frame_t * const frame)
{
  // buffer data frames per connection? - only trigger connection->writer after all emit_data_frames have been written
  // or size threshold has been reached

  size_t header_length = FRAME_HEADER_SIZE;
  uint8_t header_buf[header_length];
  uint8_t flags = 0;

  if (frame->end_stream) {
    flags |= FLAG_END_STREAM;
  }

  h2_frame_header_write(header_buf, frame->buf_length, FRAME_TYPE_DATA, flags, stream->id);

  if (!h2_write(h2, header_buf, header_length)) {
    return false;
  }

  log_append(h2->log, LOG_DEBUG, "Writing data frame: stream %d, %ld octets", stream->id, frame->buf_length);

  return h2_write(h2, frame->buf, frame->buf_length);
}

static bool h2_stream_trigger_send_data(h2_t * const h2, h2_stream_t * const stream)
{

  while (stream->queued_data_frames) {
    log_append(h2->log, LOG_TRACE, "Sending queued data for stream: %d", stream->id);

    h2_queued_frame_t * frame = stream->queued_data_frames;
    size_t frame_payload_size = frame->buf_length;

    bool connection_window_open = (long)frame_payload_size <= h2->outgoing_window_size;
    bool stream_window_open = (long)frame_payload_size <= stream->outgoing_window_size;

    if (connection_window_open && stream_window_open) {
      bool success = h2_emit_data_frame(h2, stream, frame);

      if (success) {
        h2->outgoing_window_size -= frame_payload_size;
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

      // make sure we dont have any queued up data that needs to be sent
      return h2_flush(h2, 0);

    }

  }

  log_append(h2->log, LOG_TRACE, "Connection window size: %ld, stream window: %ld",
      h2->outgoing_window_size, stream->outgoing_window_size);

  return true;
}

static bool h2_trigger_send_data(h2_t * const h2, h2_stream_t * stream)
{

  if (stream) {

    return h2_stream_trigger_send_data(h2, stream);

  } else {

    log_append(h2->log, LOG_TRACE, "Sending queued data for open frames");

    // loop through open streams
    hash_table_iter_t iter;
    h2_stream_t * prev = NULL;
    hash_table_iterator_init(&iter, h2->streams);

    while (hash_table_iterate(&iter)) {

      if (prev) {
        h2_stream_close(h2, prev, false);
        prev = NULL;
      }

      stream = iter.value;

      if (stream->state != STREAM_STATE_CLOSED) {

        if (!h2_stream_trigger_send_data(h2, stream)) {
          return false;
        }

        prev = stream;

      }
    }

    if (prev) {
      h2_stream_close(h2, prev, false);
      prev = NULL;
    }

    log_append(h2->log, LOG_TRACE, "Connection window size: %ld", h2->outgoing_window_size);

    return true;
  }

}

static h2_queued_frame_t * h2_queue_data_frame(h2_stream_t * const stream, uint8_t * buf, const size_t buf_length,
    const bool end_stream, void * const buf_begin)
{
  h2_queued_frame_t * new_frame = malloc(sizeof(h2_queued_frame_t));

  if (!new_frame) {
    log_append(stream->h2->log, LOG_ERROR, "Unable to allocate space for new data frame");
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
    h2_queued_frame_t * curr = stream->queued_data_frames;

    while (curr->next) {
      curr = curr->next;
    }

    curr->next = new_frame;
  }

  return new_frame;
}

static bool h2_emit_data(h2_t * const h2, h2_stream_t * const stream, uint8_t * in,
                         const size_t in_length, bool last_in)
{
  // TODO support padding?

  if (in_length == 0) {
    if (!h2_queue_data_frame(stream, in, in_length, last_in, in)) {
      free(in);
      return false;
    }

    return h2_trigger_send_data(h2, stream);
  }

  size_t remaining_length = in_length;
  size_t per_frame_length;
  uint8_t * per_frame_data = in;
  bool last_frame = false;

  bool in_freed = false;

  while (remaining_length > 0) {
    if (remaining_length > h2->max_frame_size) {
      per_frame_length = h2->max_frame_size;
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

    if (!h2_queue_data_frame(stream, curr_frame_data, curr_frame_length, last_in && last_frame, buf_begin)) {

      free(in);
      return false;
    }

    remaining_length -= per_frame_length;
    per_frame_data += per_frame_length;
  }

  bool success = h2_trigger_send_data(h2, stream);

  // use after free possible - if a frame in the middle doesn't get compressed (possibly due to the output being bigger than the
  // input, which is unlikely), we will free the input here, but it may be needed afterwards
  if (!in_freed) {
    free(in);
  }

  return success;

}

static bool h2_emit_settings_ack(const h2_t * const h2)
{
  size_t buf_length = FRAME_HEADER_SIZE;
  uint8_t buf[buf_length];
  uint8_t flags = 0;
  bool ack = true;

  if (ack) {
    flags |= FLAG_ACK;
  }

  h2_frame_header_write(buf, 0, FRAME_TYPE_SETTINGS, flags, 0);

  log_append(h2->log, LOG_DEBUG, "Writing settings ack frame");

  return h2_write(h2, buf, buf_length);
}

static bool h2_emit_ping_ack(const h2_t * const h2, uint8_t * opaque_data)
{
  size_t payload_length = PING_OPAQUE_DATA_LENGTH;
  size_t buf_length = FRAME_HEADER_SIZE + payload_length;
  uint8_t buf[buf_length];

  uint8_t flags = 0;
  bool ack = true;

  if (ack) {
    flags |= FLAG_ACK;
  }

  h2_frame_header_write(buf, payload_length, FRAME_TYPE_PING, flags, 0);

  log_append(h2->log, LOG_DEBUG, "Writing ping ack frame");

  memcpy(buf + FRAME_HEADER_SIZE, opaque_data, payload_length);

  return h2_write(h2, buf, buf_length);
}

static bool h2_emit_window_update(const h2_t * const h2, const uint32_t stream_id,
                                  const size_t increment)
{

  size_t payload_length = 4;
  size_t buf_length = FRAME_HEADER_SIZE + payload_length;

  size_t pos = 0;
  uint8_t buf[buf_length];

  uint8_t flags = 0; // no flags

  h2_frame_header_write(buf, payload_length, FRAME_TYPE_WINDOW_UPDATE, flags, stream_id);
  pos += FRAME_HEADER_SIZE;

  buf[pos++] = (increment >> 24) & 0xFF;
  buf[pos++] = (increment >> 16) & 0xFF;
  buf[pos++] = (increment >> 8) & 0xFF;
  buf[pos++] = (increment) & 0xFF;

  log_append(h2->log, LOG_DEBUG, "Writing window update frame");

  if (!h2_write(h2, buf, buf_length)) {
    return false;
  }

  // flush the connection so that we write the window update as soon as possible
  if (!h2_flush(h2, 0)) {
    log_append(h2->log, LOG_WARN, "Could not flush write buffer after window update");
  }

  return true;
}

#define FRAME_FLAG(frame, mask) \
  h2_frame_flag_get((h2_frame_t *) frame, mask)

static bool h2_frame_flag_get(const h2_frame_t * const frame, int mask)
{
  return frame->flags & mask;
}

/**
 * Returns true if the first part of data is the http connection
 * header string
 */
static bool h2_recognize_connection_preface(h2_t * const h2)
{

  if (h2_detect_connection(h2->buffer, h2->buffer_length)) {
    h2->buffer_position = H2_CONNECTION_PREFACE_LENGTH;
    return true;
  }

  return false;
}

static void h2_adjust_initial_window_size(h2_t * const h2, const long difference)
{
  hash_table_iter_t iter;
  hash_table_iterator_init(&iter, h2->streams);

  while (hash_table_iterate(&iter)) {
    h2_stream_t * stream = iter.value;

    stream->outgoing_window_size += difference;

    if (stream->outgoing_window_size > MAX_WINDOW_SIZE) {
      emit_error_and_close(h2, stream->id, H2_ERROR_FLOW_CONTROL_ERROR, NULL);
    }
  }
}

static bool h2_setting_set(h2_t * const h2, const enum settings_e id, const uint32_t value)
{
  log_append(h2->log, LOG_TRACE, "Settings: %d: %d", id, value);

  switch (id) {
    case SETTINGS_HEADER_TABLE_SIZE:
      log_append(h2->log, LOG_TRACE, "Settings: Got table size: %d", value);

      h2->header_table_size = value;
      hpack_header_table_adjust_size(h2->decoding_context, value);
      break;

    case SETTINGS_ENABLE_PUSH:
      log_append(h2->log, LOG_TRACE, "Settings: Enable push? %s", value ? "yes" : "no");

      h2->enable_push = value;
      break;

    case SETTINGS_MAX_CONCURRENT_STREAMS:
      log_append(h2->log, LOG_TRACE, "Settings: Max concurrent streams: %d", value);

      h2->max_concurrent_streams = value;
      break;

    case SETTINGS_INITIAL_WINDOW_SIZE:
      log_append(h2->log, LOG_TRACE, "Settings: Initial window size: %d", value);

      h2_adjust_initial_window_size(h2, value - h2->initial_window_size);
      h2->initial_window_size = value;
      break;

    case SETTINGS_MAX_FRAME_SIZE:
      log_append(h2->log, LOG_TRACE, "Settings: Initial max frame size: %d", value);

      h2->max_frame_size = value;
      break;

    case SETTINGS_MAX_HEADER_LIST_SIZE:
      log_append(h2->log, LOG_TRACE, "Settings: Initial max header list size: %d", value);

      // TODO - send to hpack encoding context
      h2->max_header_list_size = value;
      break;

    default:
      emit_error_and_close(h2, 0, H2_ERROR_PROTOCOL_ERROR, "Invalid setting: %d", id);
      return false;
  }

  return true;
}

static h2_stream_t * h2_stream_init(h2_t * const h2, const uint32_t stream_id)
{

  log_append(h2->log, LOG_TRACE, "Opening stream #%d", stream_id);

  h2_stream_t * stream = h2_stream_get(h2, stream_id);

  if (stream != NULL) {
    emit_error_and_close(h2, stream_id, H2_ERROR_PROTOCOL_ERROR,
                         "Got a headers frame for an existing stream");
    return NULL;
  }

  stream = malloc(sizeof(h2_stream_t));

  if (!stream) {
    emit_error_and_close(h2, stream_id, H2_ERROR_INTERNAL_ERROR,
                         "Unable to initialize stream: %ld", stream_id);
    return NULL;
  }

  stream->h2 = h2;

  long * stream_id_key = malloc(sizeof(long));

  if (!stream_id_key) {
    emit_error_and_close(h2, stream_id, H2_ERROR_INTERNAL_ERROR,
                         "Unable to initialize stream (stream identifier): %ld", stream_id);
    free(stream);
    return NULL;
  }

  * stream_id_key = stream_id;
  hash_table_put(h2->streams, stream_id_key, stream);

  stream->queued_data_frames = NULL;

  stream->id = stream_id;
  stream->state = STREAM_STATE_IDLE;
  stream->closing = false;
  stream->header_fragments = NULL;
  stream->headers = NULL;

  stream->priority_exclusive = DEFAULT_STREAM_EXCLUSIVE_FLAG;
  stream->priority_dependency = DEFAULT_STREAM_DEPENDENCY;
  stream->priority_weight = DEFAULT_STREAM_WEIGHT;

  stream->outgoing_window_size = h2->initial_window_size;
  stream->incoming_window_size = DEFAULT_INITIAL_WINDOW_SIZE;

  stream->associated_stream_id = 0;

  return stream;
}

static bool h2_trigger_request(h2_t * const h2, h2_stream_t * const stream)
{
  if (!h2->request_init) {
    log_append(h2->log, LOG_FATAL, "No request initializer set up");

    abort();
  }

  if (!h2->request_handler) {
    log_append(h2->log, LOG_FATAL, "No request handler set up");

    abort();
  }

  http_request_t * request = h2->request_init(h2->data, stream, stream->headers);

  if (!request) {
    return false;
  }

  stream->request = request;

  // transfer ownership of headers to the request
  stream->headers = NULL;

  http_response_t * response = http_response_init(request);
  stream->response = response;

  if (stream->id > h2->last_stream_id) {
    h2->last_stream_id = stream->id;
  }

  h2->request_handler(h2->data, request, response);

  return true;
}

bool h2_request_begin(h2_t * const h2, header_list_t * headers, uint8_t * buf, size_t buf_length)
{
  h2_stream_t * stream = h2_stream_init(h2, 1);
  ASSERT_OR_RETURN_FALSE(stream);
  stream->headers = headers;

  if (!h2_trigger_request(h2, stream)) {
    return false;
  }

  if (buf && buf_length > 0) {
    h2_read(h2, buf, buf_length);
  } else {
    h2_flush(h2, 0);
  }

  return true;
}

static bool strip_padding(h2_t * const h2, uint8_t ** payload, size_t * payload_length, bool padded_on)
{
  if (padded_on) {
    size_t padding_length = get_bits8(*payload, 0xFF);

    (*payload_length)--;
    (*payload)++;
    *payload_length -= padding_length;
    log_append(h2->log, LOG_TRACE, "Stripped %ld octets of padding from frame", padding_length);
  }

  return true;
}

static bool h2_parse_frame_data(h2_t * const h2, const h2_frame_data_t * const frame)
{
  if (!h2->data_handler) {
    log_append(h2->log, LOG_FATAL, "No data handler set up");

    abort();
  }

  h2_stream_t * stream = h2_stream_get(h2, frame->stream_id);

  if (!stream) {
    emit_error_and_close(h2, frame->stream_id, H2_ERROR_PROTOCOL_ERROR,
                         "Unable to find stream #%d", frame->stream_id);
    return true;
  }

  // adjust window sizes
  h2->incoming_window_size -= frame->length;
  stream->incoming_window_size -= frame->length;

  // pass on to application
  uint8_t * buf = h2->buffer + h2->buffer_position;
  size_t buf_length = frame->length;
  bool last_data_frame = FRAME_FLAG(frame, FLAG_END_STREAM);

  bool padded = FRAME_FLAG(frame, FLAG_PADDED);

  if (!strip_padding(h2, &buf, &buf_length, padded)) {
    emit_error_and_close(h2, 0, H2_ERROR_PROTOCOL_ERROR,
                         "Problem with padding on data frame");
    return false;
  }

  h2->data_handler(h2->data, stream->request, stream->response, buf, buf_length, last_data_frame, false);

  // do we need to send WINDOW_UPDATE?
  if (h2->incoming_window_size < 0) {

    emit_error_and_close(h2, 0, H2_ERROR_FLOW_CONTROL_ERROR, "Connection window size is less than 0: %ld",
                         h2->incoming_window_size);

  } else if (h2->incoming_window_size < 0.75 * DEFAULT_INITIAL_WINDOW_SIZE) {

    size_t increment = DEFAULT_INITIAL_WINDOW_SIZE - h2->incoming_window_size;

    if (!h2_emit_window_update(h2, 0, increment)) {
      emit_error_and_close(h2, 0, H2_ERROR_INTERNAL_ERROR, "Unable to emit window update frame");
      return false;
    }

    h2->incoming_window_size += increment;

  }

  if (stream->incoming_window_size < 0) {

    emit_error_and_close(h2, stream->id, H2_ERROR_FLOW_CONTROL_ERROR,
                         "Stream #%d: window size is less than 0: %ld", stream->incoming_window_size);

  } else if (!last_data_frame && (stream->incoming_window_size < 0.75 * DEFAULT_INITIAL_WINDOW_SIZE)) {

    size_t increment = DEFAULT_INITIAL_WINDOW_SIZE - stream->incoming_window_size;

    if (!h2_emit_window_update(h2, stream->id, increment)) {
      emit_error_and_close(h2, stream->id, H2_ERROR_INTERNAL_ERROR, "Unable to emit window update frame");
      // don't return false - the connection is still OK
    } else {
      stream->incoming_window_size += increment;
    }

  }

  return true;
}

static bool h2_stream_add_header_fragment(h2_stream_t * const stream, const uint8_t * const buffer,
    const size_t length)
{
  h2_header_fragment_t * fragment = malloc(sizeof(h2_header_fragment_t));

  if (!fragment) {
    log_append(stream->h2->log, LOG_ERROR, "Unable to allocate space for header fragment");
    return false;
  }

  fragment->buffer = malloc(length);

  if (!fragment->buffer) {
    log_append(stream->h2->log, LOG_ERROR, "Unable to allocate space for header fragment");
    free(fragment);
    return false;
  }

  memcpy(fragment->buffer, buffer, length);
  fragment->length = length;
  fragment->next = NULL;

  h2_header_fragment_t * current = stream->header_fragments;

  for (; current && current->next; current = current->next);

  if (current == NULL) {
    stream->header_fragments = fragment;
  } else {
    current->next = fragment;
  }

  return true;
}

static bool h2_parse_header_fragments(h2_t * const h2, h2_stream_t * const stream)
{
  size_t headers_length = 0;
  h2_header_fragment_t * current = stream->header_fragments;

  for (; current; current = current->next) {
    log_append(h2->log, LOG_TRACE, "Counting header fragment lengths: %ld", current->length);

    headers_length += current->length;
  }

  uint8_t * headers = malloc(headers_length + 1);

  if (!headers) {
    emit_error_and_close(h2, stream->id, H2_ERROR_INTERNAL_ERROR, "Unable to allocate memory for headers");
    return false;
  }

  uint8_t * header_appender = headers;
  current = stream->header_fragments;

  while (current) {
    log_append(h2->log, LOG_TRACE, "Appending header fragment (%ld octets)", current->length);

    memcpy(header_appender, current->buffer, current->length);
    header_appender += current->length;
    h2_header_fragment_t * prev = current;
    current = current->next;
    free(prev->buffer);
    free(prev);
  }

  *header_appender = '\0';

  log_append(h2->log, LOG_TRACE, "Got headers: (%ld octets), decoding", headers_length);

  stream->headers = hpack_decode(h2->decoding_context, headers, headers_length);

  if (!stream->headers) {
    emit_error_and_close(h2, stream->id, H2_ERROR_COMPRESSION_ERROR, "Unable to decode headers");
    free(headers);
    return false;
  }

  // TODO - check that the stream is in a valid state to be opened first
  stream->state = STREAM_STATE_OPEN;
  h2->incoming_concurrent_streams++;

  free(headers);

  // TODO - check that the stream is not closed?
  if (!h2->closing) {
    return h2_trigger_request(h2, stream);
  }

  return true;
}

static bool h2_parse_frame_headers(h2_t * const h2, const h2_frame_headers_t * const frame)
{
  uint8_t * buf = h2->buffer + h2->buffer_position;
  size_t buf_length = frame->length;
  h2_stream_t * stream = h2_stream_init(h2, frame->stream_id);

  if (!stream) {
    return false;
  }

  bool padded = FRAME_FLAG(frame, FLAG_PADDED);

  if (!strip_padding(h2, &buf, &buf_length, padded)) {
    emit_error_and_close(h2, 0, H2_ERROR_PROTOCOL_ERROR,
                         "Problem with padding on header frame");
    return false;
  }

  if (FRAME_FLAG(frame, FLAG_PRIORITY)) {

    stream->priority_exclusive = get_bit(buf, 0);
    stream->priority_dependency = get_bits32(buf, 0x7FFFFFFF);
    // add 1 to get a value between 1 and 256
    stream->priority_weight = get_bits8(buf + 4, 0xFF) + 1;

    log_append(h2->log, LOG_TRACE, "Stream #%d priority: exclusive: %s, dependency: %d, weight: %d",
              stream->id, stream->priority_exclusive ? "yes" : "no", stream->priority_dependency,
              stream->priority_weight);

    buf += 5;
    buf_length -= 5;
  }

  if (!h2_stream_add_header_fragment(stream, buf, buf_length)) {
    return false;
  }

  if (FRAME_FLAG(frame, FLAG_END_HEADERS)) {
    // parse the headers
    log_append(h2->log, LOG_TRACE, "Parsing headers");

    bool success = h2_parse_header_fragments(h2, stream);

    if (!success) {
      emit_error_and_close(h2, stream->id, H2_ERROR_INTERNAL_ERROR, "Unable to process stream");
    }
  } else {
    // TODO mark stream as waiting for continuation frame
  }

  return true;
}

static bool h2_parse_frame_continuation(h2_t * const h2,
                                        const h2_frame_continuation_t * const frame)
{
  uint8_t * buf = h2->buffer + h2->buffer_position;
  size_t buf_length = frame->length;
  h2_stream_t * stream = h2_stream_get(h2, frame->stream_id);

  bool padded = FRAME_FLAG(frame, FLAG_PADDED);

  if (!strip_padding(h2, &buf, &buf_length, padded)) {
    emit_error_and_close(h2, 0, H2_ERROR_PROTOCOL_ERROR,
                         "Problem with padding on data frame");
    return false;
  }

  if (!h2_stream_add_header_fragment(stream, buf, buf_length)) {
    return false;
  }

  if (FRAME_FLAG(frame, FLAG_END_HEADERS)) {
    // TODO unmark stream as waiting for continuation frame
    // parse the headers
    log_append(h2->log, LOG_TRACE, "Parsing headers + continuations");

    return h2_parse_header_fragments(h2, stream);
  }

  return true;
}

static bool h2_settings_parse(h2_t * const h2, uint8_t * pos, size_t buf_length)
{
  size_t num_settings = buf_length / SETTING_SIZE;

  log_append(h2->log, LOG_TRACE, "Settings: Found %ld settings", num_settings);

  size_t i;

  for (i = 0; i < num_settings; i++) {
    uint8_t * curr_setting = pos + (i * SETTING_SIZE);
    uint16_t setting_id = get_bits16(curr_setting, 0xFFFF);
    uint32_t setting_value = get_bits32(curr_setting + SETTING_ID_SIZE, 0xFFFFFFFF);

    if (!h2_setting_set(h2, setting_id, setting_value)) {
      return false;
    }
  }

  h2->received_settings = true;

  log_append(h2->log, LOG_TRACE, "Settings: %ld, %d, %ld, %ld", h2->header_table_size, h2->enable_push,
            h2->max_concurrent_streams, h2->initial_window_size);

  return true;
}

static bool h2_parse_frame_settings(h2_t * const h2, const h2_frame_settings_t * const frame)
{

  if (FRAME_FLAG(frame, FLAG_ACK)) {

    if (frame->length != 0) {
      emit_error_and_close(h2, 0, H2_ERROR_FRAME_SIZE_ERROR, "Non-zero frame size for ACK settings frame: %ld",
                           frame->length);
      return false;
    }

    log_append(h2->log, LOG_TRACE, "Received settings ACK");

    // Mark the settings frame we sent as acknowledged.
    // We currently don't send any settings that require
    // synchonization
    return true;

  } else {
    uint8_t * pos = h2->buffer + h2->buffer_position;
    h2_settings_parse(h2, pos, frame->length);

    h2->received_settings = true;

    log_append(h2->log, LOG_TRACE, "Settings: %ld, %d, %ld, %ld", h2->header_table_size, h2->enable_push,
              h2->max_concurrent_streams, h2->initial_window_size);

    return h2_emit_settings_ack(h2);
  }

}

static bool h2_parse_frame_ping(h2_t * const h2, const h2_frame_ping_t * const frame)
{
  UNUSED(frame);

  uint8_t * opaque_data = h2->buffer + h2->buffer_position;
  return h2_emit_ping_ack(h2, opaque_data);

}

static bool h2_increment_connection_window_size(h2_t * const h2, const uint32_t increment)
{
  h2->outgoing_window_size += increment;

  log_append(h2->log, LOG_TRACE, "Connection window size incremented to: %ld", h2->outgoing_window_size);

  return h2_trigger_send_data(h2, NULL);
}

static bool h2_increment_stream_window_size(h2_t * const h2, const uint32_t stream_id,
    const uint32_t increment)
{

  if (h2_stream_closed(h2, stream_id)) {
    log_append(h2->log, LOG_TRACE, "Can't update stream #%ld's window size, already closed", stream_id);
    // the stream may have been recently closed, ignore
    return true;
  }

  h2_stream_t * stream = h2_stream_get(h2, stream_id);

  if (!stream) {
    emit_error_and_close(h2, stream_id, H2_ERROR_PROTOCOL_ERROR,
                         "Could not find stream #%d to update it's window size", stream_id);
    return false;
  }

  stream->outgoing_window_size += increment;

  log_append(h2->log, LOG_TRACE, "Stream window size incremented to: %ld", stream->outgoing_window_size);

  return h2_trigger_send_data(h2, stream);

}

static bool h2_parse_frame_window_update(h2_t * const h2,
    h2_frame_window_update_t * const frame)
{
  uint8_t * buf = h2->buffer + h2->buffer_position;
  frame->increment = get_bits32(buf, 0x7FFFFFFF);

  bool success = false;

  if (frame->stream_id > 0) {
    success = h2_increment_stream_window_size(h2, frame->stream_id, frame->increment);
  } else {
    success = h2_increment_connection_window_size(h2, frame->increment);
  }

  log_append(h2->log, LOG_TRACE, "Received window update, stream: %d, increment: %ld",
            frame->stream_id, frame->increment);

  return success;
}

static bool h2_parse_frame_rst_stream(h2_t * const h2, h2_frame_rst_stream_t * const frame)
{
  uint8_t * buf = h2->buffer + h2->buffer_position;
  frame->error_code = get_bits32(buf, 0xFFFFFFFF);

  log_append(h2->log, LOG_WARN, "Received reset stream: stream #%d, error code: %s (%d)",
              frame->stream_id, H2_ERRORS[frame->error_code], frame->error_code);

  h2_stream_t * stream = h2_stream_get(h2, frame->stream_id);

  h2_stream_close(h2, stream, true);

  return true;
}

static bool h2_parse_frame_priority(h2_t * const h2, h2_frame_priority_t * const frame)
{
  uint8_t * buf = h2->buffer + h2->buffer_position;

  h2_stream_t * stream = h2_stream_get(h2, frame->stream_id);

  if (!stream) {
    emit_error_and_close(h2, frame->stream_id, H2_ERROR_PROTOCOL_ERROR, "Unknown stream id: %d",
                         frame->stream_id);
    return true;
  }

  stream->priority_exclusive = get_bit(buf, 0);
  stream->priority_dependency = get_bits32(buf, 0x7FFFFFFF);
  // add 1 to get a value between 1 and 256
  stream->priority_weight = get_bits8(buf + 4, 0xFF) + 1;

  return true;
}

static bool h2_parse_frame_goaway(h2_t * const h2, h2_frame_goaway_t * const frame)
{

  uint8_t * buf = h2->buffer + h2->buffer_position;
  frame->last_stream_id = get_bits32(buf, 0x7FFFFFFF);
  frame->error_code = get_bits32(buf + 4, 0xFFFFFFFF);
  size_t debug_data_length = (frame->length - 8);

  uint8_t debug_data[debug_data_length + 1];
  memcpy(debug_data, buf + 8, debug_data_length);
  debug_data[debug_data_length] = '\0';
  frame->debug_data = debug_data;

  if (frame->error_code == H2_ERROR_NO_ERROR) {
    log_append(h2->log, LOG_TRACE, "Received goaway, last stream: %d, error code: %s (%d), debug_data: %s",
              frame->last_stream_id, H2_ERRORS[frame->error_code],
              frame->error_code, frame->debug_data);
    h2_mark_closing(h2);
  } else {
    log_append(h2->log, LOG_ERROR, "Received goaway, last stream: %d, error code: %s (%d), debug_data: %s",
              frame->last_stream_id, H2_ERRORS[frame->error_code],
              frame->error_code, frame->debug_data);
  }

  frame->debug_data = NULL;

  return true;
}

static h2_frame_t * h2_frame_init(h2_t * const h2, const uint32_t length, const uint8_t type,
                                  const uint8_t flags, const uint32_t stream_id)
{
  h2_frame_t * frame;

  switch (type) {
    case FRAME_TYPE_DATA:
      frame = (h2_frame_t *) malloc(sizeof(h2_frame_data_t));
      break;

    case FRAME_TYPE_HEADERS:
      frame = (h2_frame_t *) malloc(sizeof(h2_frame_headers_t));
      break;

    case FRAME_TYPE_PRIORITY:
      frame = (h2_frame_t *) malloc(sizeof(h2_frame_priority_t));
      break;

    case FRAME_TYPE_RST_STREAM:
      frame = (h2_frame_t *) malloc(sizeof(h2_frame_rst_stream_t));
      break;

    case FRAME_TYPE_SETTINGS:
      frame = (h2_frame_t *) malloc(sizeof(h2_frame_settings_t));
      break;

    case FRAME_TYPE_PUSH_PROMISE:
      frame = (h2_frame_t *) malloc(sizeof(h2_frame_push_promise_t));
      break;

    case FRAME_TYPE_PING:
      frame = (h2_frame_t *) malloc(sizeof(h2_frame_ping_t));
      break;

    case FRAME_TYPE_GOAWAY:
      frame = (h2_frame_t *) malloc(sizeof(h2_frame_goaway_t));
      break;

    case FRAME_TYPE_WINDOW_UPDATE:
      frame = (h2_frame_t *) malloc(sizeof(h2_frame_window_update_t));
      break;

    case FRAME_TYPE_CONTINUATION:
      frame = (h2_frame_t *) malloc(sizeof(h2_frame_continuation_t));
      break;

    default:
      emit_error_and_close(h2, stream_id, H2_ERROR_INTERNAL_ERROR, "Unhandled frame type");
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

static bool is_valid_frame(h2_t * const h2, h2_frame_t * frame)
{
  enum frame_type_e frame_type = frame->type;
  frame_parser_definition_t def = frame_parser_definitions[frame_type];

  if (frame->length < def.length_min) {
    emit_error_and_close(h2, frame->stream_id, H2_ERROR_FRAME_SIZE_ERROR, "Invalid frame length");
    return false;
  }

  if (frame->length > def.length_max) {
    emit_error_and_close(h2, frame->stream_id, H2_ERROR_FRAME_SIZE_ERROR, "Invalid frame length");
    return false;
  }

  size_t i;

  for (i = 0; i < 8; i++) {
    bool can_be_set = def.flags[i];

    if (!can_be_set) {
      uint8_t mask = 1 << i;

      if (frame->flags & mask) {
        emit_error_and_close(h2, frame->stream_id, H2_ERROR_PROTOCOL_ERROR, "Invalid flag set");
        return false;
      }
    }
  }

  if (frame->stream_id == 0 && def.must_have_stream_id) {
    emit_error_and_close(h2, frame->stream_id, H2_ERROR_FRAME_SIZE_ERROR, "Stream ID must be set");
    return false;
  }

  if (frame->stream_id > 0 && def.must_not_have_stream_id) {
    emit_error_and_close(h2, frame->stream_id, H2_ERROR_FRAME_SIZE_ERROR, "Stream ID must not be set");
    return false;
  }

  return true;
}

bool h2_settings_apply(h2_t * const h2, char * base64)
{
  binary_buffer_t buf;
  binary_buffer_init(&buf, 0);

  base64url_decode(&buf, base64);

  h2_settings_parse(h2, binary_buffer_start(&buf), binary_buffer_size(&buf));
  h2->received_settings = true;

  binary_buffer_free(&buf);

  return true;
}

static bool h2_verify_tls_settings(h2_t * const h2)
{
  if (h2->tls_version) {
    // TODO support newer versions?
    log_append(h2->log, LOG_TRACE, "Comparing: %s == %s", h2->tls_version, "TLSv1.2");

    if (strcmp(h2->tls_version, "TLSv1.2") != 0) {
      return false;
    }
  }

  if (h2->cipher) {
    bool match = false;

    for (size_t i = 0; i < sizeof(HTTP2_CIPHERS); i++) {
      log_append(h2->log, LOG_TRACE, "Comparing: %s == %s", h2->cipher, HTTP2_CIPHERS[i]);

      if (strcmp(h2->cipher, HTTP2_CIPHERS[i]) == 0) {
        match = true;
        break;
      }
    }

    if (!match) {
      return false;
    }
  }

  // TODO check key size
  // TODO check for SNI extension

  return true;
}

/**
 * Processes the next frame in the buffer.
 *
 * Returns true a frame was processed.
 * Returns false if there was no frame to process.
 */
static bool h2_add_from_buffer(h2_t * const h2)
{
  log_append(h2->log, LOG_TRACE, "Reading %ld bytes", h2->buffer_length);

  if (h2->buffer_position == h2->buffer_length) {
    log_append(h2->log, LOG_TRACE, "Finished with current buffer");

    return false;
  }

  // is there enough in the buffer to read a frame header?
  if (h2->buffer_position + FRAME_HEADER_SIZE > h2->buffer_length) {
    // TODO off-by-one?
    log_append(h2->log, LOG_TRACE, "Not enough in buffer to read frame header");

    return false;
  }

  uint8_t * pos = h2->buffer + h2->buffer_position;

  // Read the frame header
  // get first 3 bytes
  uint32_t frame_length = get_bits32(pos, 0xFFFFFF00) >> 8;

  // is there enough in the buffer to read the frame payload?
  if (h2->buffer_position + FRAME_HEADER_SIZE + frame_length <= h2->buffer_length) {

    uint8_t frame_type = pos[3];
    uint8_t frame_flags = pos[4];
    // get 31 bits
    uint32_t stream_id = get_bits32(pos + 5, 0x7FFFFFFF);

    // is this a valid frame type?
    if (!is_valid_frame_type(frame_type)) {
      // invalid frame type is always a connection error
      emit_error_and_close(h2, 0, H2_ERROR_PROTOCOL_ERROR, "Invalid Frame Type: %d", frame_type);
      return false;
    }

    // TODO - if the previous frame type was headers, and headers haven't been completed,
    // this frame must be a continuation frame, or else this is a protocol error

    h2_frame_t * frame = h2_frame_init(h2, frame_length, frame_type, frame_flags, stream_id);

    if (frame == NULL || !is_valid_frame(h2, frame)) {
      return false;
    }

    h2->buffer_position += FRAME_HEADER_SIZE;
    // TODO off-by-one?
    bool success = false;

    if (!h2->received_settings && frame->type != FRAME_TYPE_SETTINGS) {
      emit_error_and_close(h2, 0, H2_ERROR_PROTOCOL_ERROR, "Expected Settings frame as first frame");
    } else {
      /**
       * The h2_parse_frame_xxx functions should return true if the next frame should be allowed to
       * continue to be processed. Connection errors usually prevent the rest of the frames from
       * being processed.
       */
      switch (frame->type) {
        case FRAME_TYPE_DATA:
          success = h2_parse_frame_data(h2, (h2_frame_data_t *) frame);
          break;

        case FRAME_TYPE_HEADERS:
          success = h2_parse_frame_headers(h2, (h2_frame_headers_t *) frame);
          break;

        case FRAME_TYPE_PRIORITY:
          success = h2_parse_frame_priority(h2, (h2_frame_priority_t *) frame);
          break;

        case FRAME_TYPE_RST_STREAM:
          success = h2_parse_frame_rst_stream(h2, (h2_frame_rst_stream_t *) frame);
          break;

        case FRAME_TYPE_SETTINGS:
          success = h2_parse_frame_settings(h2, (h2_frame_settings_t *) frame);
          break;

        case FRAME_TYPE_PUSH_PROMISE:
          emit_error_and_close(h2, 0, H2_ERROR_PROTOCOL_ERROR, "Server does not accept PUSH_PROMISE frames");
          return false;

        case FRAME_TYPE_PING:
          success = h2_parse_frame_ping(h2, (h2_frame_ping_t *) frame);
          break;

        case FRAME_TYPE_GOAWAY:
          success = h2_parse_frame_goaway(h2, (h2_frame_goaway_t *) frame);
          break;

        case FRAME_TYPE_WINDOW_UPDATE:
          success = h2_parse_frame_window_update(h2, (h2_frame_window_update_t *) frame);
          break;

        case FRAME_TYPE_CONTINUATION:
          success = h2_parse_frame_continuation(h2, (h2_frame_continuation_t *) frame);
          break;

        default:
          emit_error_and_close(h2, 0, H2_ERROR_INTERNAL_ERROR, "Unhandled frame type: %d", frame->type);
          return false;
      }
    }

    h2->buffer_position += frame->length;
    free(frame);
    return success;
  } else {
    log_append(h2->log, LOG_TRACE, "Not enough in buffer to read %ld byte frame payload", frame_length);
  }

  return false;
}

/**
 * Reads the given buffer and acts on it. Caller must give up ownership of the
 * buffer.
 */
void h2_read(h2_t * const h2, uint8_t * const buffer, const size_t len)
{
  log_append(h2->log, LOG_TRACE, "Reading from buffer: %ld", len);

  size_t unprocessed_bytes = h2->buffer_length;

  if (unprocessed_bytes > 0) {
    log_append(h2->log, LOG_TRACE, "Appending new data to unprocessed bytes %ld + %ld = %ld",
        unprocessed_bytes, len, unprocessed_bytes + len);
    // there are still unprocessed bytes
    h2->buffer = realloc(h2->buffer, unprocessed_bytes + len);

    if (!h2->buffer) {
      emit_error_and_close(h2, 0, H2_ERROR_INTERNAL_ERROR, "Unable to allocate memory for reading full frame");
      free(buffer);
      return;
    }

    memcpy(h2->buffer + unprocessed_bytes, buffer, len);
    h2->buffer_length = unprocessed_bytes + len;
    free(buffer);
  } else {
    h2->buffer = buffer;
    h2->buffer_length = len;
  }

  h2->buffer_position = 0;

  if (!h2->verified_tls_settings) {
    if (h2_verify_tls_settings(h2)) {
      h2->verified_tls_settings = true;
    } else {
      emit_error_and_close(h2, 0, H2_ERROR_INADEQUATE_SECURITY, "Inadequate security");
      return;
    }
  }

  if (!h2->received_connection_preface) {
    if (h2_recognize_connection_preface(h2)) {
      h2->received_connection_preface = true;

      log_append(h2->log, LOG_TRACE, "Found HTTP2 connection");
    } else {
      log_append(h2->log, LOG_WARN, "Found non-HTTP2 connection, closing connection");

      h2_mark_closing(h2);
      h2_close(h2);
      return;
    }
  }

  h2->reading_from_client = true;

  while (h2_add_from_buffer(h2));

  h2->reading_from_client = false;

  if (!h2_flush(h2, 0)) {
    log_append(h2->log, LOG_WARN, "Could not flush write buffer");
  }

  if (h2->buffer_position > h2->buffer_length) {
    // buffer overflow
    emit_error_and_close(h2, 0, H2_ERROR_INTERNAL_ERROR, NULL);
    return;
  }

  // if there is still unprocessed data in the buffer, save it for when we
  // get the rest of the frame
  unprocessed_bytes = h2->buffer_length - h2->buffer_position;

  if (!h2->closing && unprocessed_bytes > 0) {
    log_append(h2->log, LOG_TRACE, "Unable to process last %ld bytes", unprocessed_bytes);
    // use memmove because it might overlap
    memmove(h2->buffer, h2->buffer + h2->buffer_position, unprocessed_bytes);
    h2->buffer = realloc(h2->buffer, unprocessed_bytes);
    h2->buffer_length = unprocessed_bytes;
    h2->buffer_position = 0;
  } else {
    free(h2->buffer);
    h2->buffer = NULL;
    h2->buffer_length = 0;
  }

}

void h2_eof(h2_t * const h2)
{
  h2_mark_closing(h2);
  h2_close(h2);
}

bool h2_response_write(h2_stream_t * stream, http_response_t * const response, uint8_t * data, const size_t data_length,
                       bool last)
{
  h2_t * h2 = stream->h2;

  char status_buf[10];
  snprintf(status_buf, 10, "%d", response->status);
  // add the status header
  http_response_pseudo_header_add(response, ":status", status_buf);

  if (stream->state != STREAM_STATE_CLOSED) {
    if (!h2_emit_headers(h2, stream, response->headers)) {
      emit_error_and_close(h2, stream->id, H2_ERROR_INTERNAL_ERROR, "Unable to emit headers");
      return false;
    }

    if (data || last) {
      if (!h2_emit_data(h2, stream, data, data_length, last)) {
        emit_error_and_close(h2, stream->id, H2_ERROR_INTERNAL_ERROR, "Unable to emit data");
        return false;
      }
    }
  }

  if (last && !h2->reading_from_client) {
    h2_flush(h2, 0);
  }

  if (last) {
    http_response_free(response);

    h2_stream_mark_closing(h2, stream);
  }

  return true;
}

bool h2_response_write_data(h2_stream_t * stream, http_response_t * const response, uint8_t * data,
                            const size_t data_length, bool last)
{

  h2_t * h2 = stream->h2;

  if (data || last) {
    if (!h2_emit_data(h2, stream, data, data_length, last)) {
      emit_error_and_close(h2, stream->id, H2_ERROR_INTERNAL_ERROR, "Unable to emit data");
      return false;
    }
  }

  if (last && !h2->reading_from_client) {
    h2_flush(h2, 0);
  }

  if (last) {
    http_response_free(response);

    h2_stream_mark_closing(h2, stream);
  }

  return true;

}

http_request_t * h2_push_init(h2_stream_t * stream, http_request_t * const original_request)
{
  UNUSED(original_request);

  if (!PUSH_ENABLED) {
    return NULL;
  }

  h2_t * h2 = stream->h2;

  if (!h2->enable_push) {
    return NULL;
  }

  if (h2->outgoing_concurrent_streams >= h2->max_concurrent_streams) {
    log_append(h2->log, LOG_DEBUG, "Tried opening more than %ld outgoing concurrent streams: stream #%d",
              h2->max_concurrent_streams, stream->id);
    return NULL;
  } else {
    log_append(h2->log, LOG_DEBUG, "Push #%ld for stream: stream #%d\n",
              h2->outgoing_concurrent_streams, stream->id);
  }

  h2_stream_t * pushed_stream = h2_stream_init(h2, h2->current_stream_id);
  ASSERT_OR_RETURN_NULL(pushed_stream);
  h2->current_stream_id += 2;

  pushed_stream->state = STREAM_STATE_RESERVED_LOCAL;
  h2->outgoing_concurrent_streams++;

  pushed_stream->associated_stream_id = stream->id;

  http_request_t * pushed_request = http_request_init(pushed_stream, h2->log, NULL);
  ASSERT_OR_RETURN_NULL(pushed_request);

  pushed_stream->request = pushed_request;

  return pushed_request;

}

bool h2_push_promise(h2_stream_t * stream, http_request_t * const request)
{

  h2_t * h2 = stream->h2;
  h2_stream_t * associated_stream = h2_stream_get(h2, stream->associated_stream_id);

  return h2_emit_push_promise(h2, associated_stream, request->headers, stream->id);

}

http_response_t * h2_push_response_get(h2_stream_t * stream, http_request_t * const request)
{
  http_response_t * pushed_response = http_response_init(request);
  stream->response = pushed_response;

  return pushed_response;
}

