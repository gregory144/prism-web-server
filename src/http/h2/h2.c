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

#define MAX_WINDOW_SIZE 0x7FFFFFFF // 2^31 - 1
#define MAX_CONNECTION_BUFFER_SIZE 0x100000 // 2^20

const char * H2_CONNECTION_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const size_t H2_CONNECTION_PREFACE_LENGTH = 24;

static const char * const HTTP2_CIPHERS[] = {
  "ECDHE-RSA-AES128-GCM-SHA256",
  "ECDHE-ECDSA-AES128-GCM-SHA256",
  "ECDHE-RSA-AES256-GCM-SHA384",
  "ECDHE-ECDSA-AES256-GCM-SHA384",
  "DHE-RSA-AES128-GCM-SHA256"
  "DHE-DSS-AES128-GCM-SHA256"
};

enum h2_detect_result_e h2_detect_connection(uint8_t * buffer, size_t buffer_length)
{
  if (buffer_length < H2_CONNECTION_PREFACE_LENGTH) {
    return H2_DETECT_NEED_MORE_DATA;
  }
  if (memcmp(buffer, H2_CONNECTION_PREFACE, H2_CONNECTION_PREFACE_LENGTH) == 0) {
    return H2_DETECT_SUCCESS;
  }

  return H2_DETECT_FAILED;
}

static void h2_stream_free(void * value)
{
  h2_stream_t * stream = value;

  if (stream->headers) {
    header_list_free(stream->headers);
  }

  while (stream->header_fragments) {

    h2_header_fragment_t * fragment = stream->header_fragments;

    stream->header_fragments = fragment->next;

    if (fragment->buffer) {
      free(fragment->buffer);
    }

    free(fragment);

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

  if (stream->response) {
    http_response_free(stream->response);
    stream->response = NULL;
  }

  free(stream);
}

h2_stream_t * h2_stream_get(h2_t * const h2, const uint32_t stream_id)
{

  return hash_table_get(h2->streams, &stream_id);

}

static void h2_stream_close(h2_t * const h2, h2_stream_t * const stream, bool force)
{
  if (stream->state == STREAM_STATE_CLOSED) {
    return;
  }

  if (force || (stream->closing && !stream->queued_data_frames)) {

    log_append(h2->log, LOG_TRACE, "Closing stream #%u", stream->id);

    stream->state = STREAM_STATE_CLOSED;

  }

}

bool h2_stream_closed(h2_t * const h2, const uint32_t stream_id)
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

static bool h2_parse_error_cb(void * data, uint32_t stream_id, enum h2_error_code_e error_code,
    char * format, ...);

static bool h2_incoming_frame(void * data, const h2_frame_t * const frame);

h2_t * h2_init(void * const data, log_context_t * log, log_context_t * hpack_log, const char * tls_version,
               const char * cipher, int cipher_key_size_in_bits, struct plugin_invoker_t * plugin_invoker,
               const h2_write_cb writer, const h2_close_cb closer, const h2_request_init_cb request_init)
{
  h2_t * h2 = malloc(sizeof(h2_t));
  ASSERT_OR_RETURN_NULL(h2);

  h2->data = data;
  h2->log = log;

  h2->plugin_invoker = plugin_invoker;
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
  h2->continuation_stream_id = 0;
  h2->outgoing_window_size = DEFAULT_INITIAL_WINDOW_SIZE;
  h2->incoming_window_size = DEFAULT_INITIAL_WINDOW_SIZE;

  h2->settings_pending = false;
  h2->incoming_push_enabled = true;
  h2->incoming_push_enabled_pending = false;
  h2->incoming_push_enabled_pending_value = false;

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

  h2->frame_parser.data = h2;
  h2->frame_parser.parse_error = h2_parse_error_cb;
  h2->frame_parser.incoming_frame = h2_incoming_frame;
  h2->frame_parser.log = h2->log;
  h2->frame_parser.plugin_invoker = h2->plugin_invoker;

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

  h2->streams = hash_table_init_with_int_keys(NULL, h2_stream_free);

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

  if (h2->buffer) {
    free(h2->buffer);
  }

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

bool h2_frame_write(const h2_t * const h2, h2_frame_t * const frame)
{
  bool ret = h2_frame_emit(&h2->frame_parser, (binary_buffer_t *) &h2->write_buffer, (h2_frame_t *) frame);
  free(frame);
  if (!ret) {
    return false;
  }

  size_t new_length = binary_buffer_size(&h2->write_buffer);

  if (new_length >= MAX_CONNECTION_BUFFER_SIZE) {
    ASSERT_OR_RETURN_FALSE(
      h2_flush(h2, 0)
    );
  }

  return true;
}

static bool h2_send_goaway(const h2_t * const h2, enum h2_error_code_e error_code, char * debug)
{
  size_t debug_length = 0;

  if (debug) {
    debug_length = strlen(debug);
  }

  uint8_t flags = 0; // no flags

  h2_frame_goaway_t * frame = (h2_frame_goaway_t *) h2_frame_init(FRAME_TYPE_GOAWAY, flags, 0);
  frame->stream_id = h2->last_stream_id;
  frame->error_code = error_code;
  frame->last_stream_id = h2->last_stream_id;
  frame->debug_data = (uint8_t *) debug;
  frame->debug_data_length = debug_length;

  return h2_frame_write(h2, (h2_frame_t *) frame);
}

static bool h2_send_rst_stream(const h2_t * const h2, uint32_t stream_id,
                               enum h2_error_code_e error_code)
{
  uint8_t flags = 0; // no flags

  h2_frame_rst_stream_t * frame = (h2_frame_rst_stream_t *) h2_frame_init(FRAME_TYPE_RST_STREAM, flags, stream_id);
  frame->error_code = error_code;

  return h2_frame_write(h2, (h2_frame_t *) frame);
}

/**
 * If stream_id is zero: Emits a GOAWAY frame
 * Otherwise: Emits a RST_STREAM
 *
 * If a goaway frame is sent, marks the connection as closed.
 */
static bool h2_emit_error_and_close_with_debug_data(h2_t * const h2, uint32_t stream_id,
                                 enum h2_error_code_e error_code, char * string)
{
  if (error_code != H2_ERROR_NO_ERROR && string) {
    log_append(h2->log, LOG_ERROR, string);
  }

  if (stream_id > 0) {

    if (!h2_send_rst_stream(h2, stream_id, error_code)) {
      log_append(h2->log, LOG_ERROR, "Unable to emit reset stream frame");
      return false;
    }

    return true;

  } else {
    bool success = h2_send_goaway(h2, error_code, string ? string : NULL);

    if (!success) {
      log_append(h2->log, LOG_ERROR, "Unable to emit goaway frame");
    }

    h2_close(h2);

    return success;
  }

}

static bool h2_emit_error_and_close(h2_t * const h2, uint32_t stream_id,
                                 enum h2_error_code_e error_code, char * format, ... )
{
  size_t buf_length = 1024;
  char buf[buf_length];

  if (format) {
    va_list ap;
    va_start(ap, format);
    vsnprintf(buf, buf_length, format, ap);
    va_end(ap);
  }

  return h2_emit_error_and_close_with_debug_data(h2, stream_id, error_code, format ? buf : NULL);
}

static bool h2_send_headers(h2_t * const h2, const h2_stream_t * const stream,
                            const header_list_t * const headers)
{
  binary_buffer_t encoded;

  if (!hpack_encode(h2->encoding_context, headers, &encoded)) {
    // don't send stream ID because we want to generate a goaway - the
    // encoding context may have been corrupted
    h2_emit_error_and_close_with_debug_data(h2, 0, H2_ERROR_INTERNAL_ERROR, "Error encoding headers");
    return false;
  }

  uint8_t * hpack_buf = encoded.buf;
  size_t headers_length = binary_buffer_size(&encoded);

  uint8_t flags = 0;
  // TODO - these should be dynamic
  const bool padded = false;
  if (padded) {
    flags |= FLAG_PADDED;
  }

  const bool priority = false;
  if (priority) {
    flags |= FLAG_PRIORITY;
  }

  const bool end_stream = false;
  if (end_stream) {
    flags |= FLAG_END_STREAM;
  }

  size_t max_first_fragment_length = h2->max_frame_size; // - padding - priority
  size_t first_fragment_length = headers_length;
  if (first_fragment_length > max_first_fragment_length) {
    first_fragment_length = max_first_fragment_length;
  } else {
    flags |= FLAG_END_HEADERS;
  }
  h2_frame_headers_t * frame = (h2_frame_headers_t *) h2_frame_init(FRAME_TYPE_HEADERS, flags, stream->id);
  frame->header_block_fragment = hpack_buf;
  frame->header_block_fragment_length = first_fragment_length;

  // padding is not currently supported
  frame->padding_length = 0;

  // these are not currently written on the wire because there is no mechanism for changing it
  frame->priority_exclusive = stream->priority_exclusive;
  frame->priority_stream_dependency = stream->priority_stream_dependency;
  frame->priority_weight = stream->priority_weight;

  log_append(h2->log, LOG_DEBUG, "Writing headers frame: stream %u", stream->id);

  if (!h2_frame_write(h2, (h2_frame_t *) frame)) {
    free(hpack_buf);
    return false;
  }

  if (first_fragment_length < headers_length) {
    // emit continuation frames
    size_t header_block_pos = first_fragment_length;
    do {
      uint8_t continuation_flags = 0;
      size_t headers_left = headers_length - header_block_pos;
      size_t continuation_frame_length = headers_left > h2->max_frame_size ?
        h2->max_frame_size : headers_left;

      if (continuation_frame_length == headers_left) {
        continuation_flags |= FLAG_END_HEADERS;
      }

      h2_frame_continuation_t * cont_frame = (h2_frame_continuation_t *) h2_frame_init(
          FRAME_TYPE_CONTINUATION, continuation_flags, stream->id);
      cont_frame->header_block_fragment = hpack_buf + header_block_pos;
      cont_frame->header_block_fragment_length = continuation_frame_length;

      if (!h2_frame_write(h2, (h2_frame_t *) cont_frame)) {
        free(hpack_buf);
        return false;
      }

      header_block_pos += continuation_frame_length;
    } while (header_block_pos < headers_length);
  }

  free(hpack_buf);

  return true;
}

static bool h2_send_push_promise(h2_t * const h2, const h2_stream_t * const pushed_stream,
                                 const header_list_t * const headers, const uint32_t associated_stream_id)
{
  // TODO split large headers into multiple frames

  binary_buffer_t encoded;

  if (!hpack_encode(h2->encoding_context, headers, &encoded)) {
    // don't send stream ID because we want to generate a goaway - the
    // encoding context may have been corrupted
    h2_emit_error_and_close_with_debug_data(h2, 0, H2_ERROR_INTERNAL_ERROR, "Error encoding headers");
    return false;
  }

  uint8_t * hpack_buf = encoded.buf;
  size_t headers_length = binary_buffer_size(&encoded);


  uint8_t flags = 0;

  const bool padded = false;
  if (padded) {
    flags |= FLAG_PADDED;
  }

  const bool end_stream = false;
  if (end_stream) {
    flags |= FLAG_END_STREAM;
  }

  const size_t stream_id_length = 4;
  size_t max_first_fragment_length = h2->max_frame_size - stream_id_length; // - padding
  size_t first_fragment_length = headers_length;
  if (first_fragment_length > max_first_fragment_length) {
    first_fragment_length = max_first_fragment_length;
  } else {
    flags |= FLAG_END_HEADERS;
  }
  h2_frame_push_promise_t * frame = (h2_frame_push_promise_t *) h2_frame_init(
      FRAME_TYPE_PUSH_PROMISE, flags, associated_stream_id);
  frame->promised_stream_id = pushed_stream->id;
  frame->header_block_fragment = hpack_buf;
  frame->header_block_fragment_length = first_fragment_length;

  // padding is not currently supported
  frame->padding_length = 0;

  log_append(h2->log, LOG_DEBUG, "Writing push promise frame: stream %u", pushed_stream->id);

  if (!h2_frame_write(h2, (h2_frame_t *) frame)) {
    free(hpack_buf);
    return false;
  }

  if (first_fragment_length < headers_length) {
    // emit continuation frames
    size_t header_block_pos = first_fragment_length;
    do {
      uint8_t continuation_flags = 0;
      size_t headers_left = headers_length - header_block_pos;
      size_t continuation_frame_length = headers_left > h2->max_frame_size ?
        h2->max_frame_size : headers_left;

      if (continuation_frame_length == headers_left) {
        continuation_flags |= FLAG_END_HEADERS;
      }

      h2_frame_continuation_t * cont_frame = (h2_frame_continuation_t *) h2_frame_init(
          FRAME_TYPE_CONTINUATION, continuation_flags, associated_stream_id);
      cont_frame->header_block_fragment = hpack_buf + header_block_pos;
      cont_frame->header_block_fragment_length = continuation_frame_length;

      if (!h2_frame_write(h2, (h2_frame_t *) cont_frame)) {
        free(hpack_buf);
        return false;
      }

      header_block_pos += continuation_frame_length;
    } while (header_block_pos < headers_length);
  }

  free(hpack_buf);

  return true;
}

static bool h2_send_data_frame(const h2_t * const h2, const h2_stream_t * const stream,
                               const h2_queued_frame_t * const queued_frame)
{
  // buffer data frames per connection? - only trigger connection->writer after all emit_data_frames have been written
  // or size threshold has been reached
  uint8_t flags = 0;

  if (queued_frame->end_stream) {
    flags |= FLAG_END_STREAM;
  }

  h2_frame_data_t * frame = (h2_frame_data_t *) h2_frame_init(FRAME_TYPE_DATA, flags, stream->id);
  frame->payload = queued_frame->buf;
  frame->payload_length = queued_frame->buf_length;

  log_append(h2->log, LOG_DEBUG, "Writing data frame: stream %u, %lu octets", stream->id, queued_frame->buf_length);

  return h2_frame_write(h2, (h2_frame_t *) frame);
}

static bool h2_stream_trigger_send_data(h2_t * const h2, h2_stream_t * const stream)
{

  while (stream->queued_data_frames) {
    log_append(h2->log, LOG_TRACE, "Sending queued data for stream: %u", stream->id);

    h2_queued_frame_t * frame = stream->queued_data_frames;
    size_t frame_payload_size = frame->buf_length;

    bool connection_window_open = (long)frame_payload_size <= h2->outgoing_window_size;
    bool stream_window_open = (long)frame_payload_size <= stream->outgoing_window_size;

    if (connection_window_open && stream_window_open) {
      bool success = h2_send_data_frame(h2, stream, frame);

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

static bool h2_send_data(h2_t * const h2, h2_stream_t * const stream, uint8_t * in,
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

static bool h2_send_settings_ack(const h2_t * const h2)
{
  uint8_t flags = 0;
  bool ack = true;

  if (ack) {
    flags |= FLAG_ACK;
  }

  h2_frame_settings_t * frame = (h2_frame_settings_t *) h2_frame_init(FRAME_TYPE_SETTINGS, flags, 0);
  frame->num_settings = 0;

  log_append(h2->log, LOG_DEBUG, "Writing settings ack frame");

  return h2_frame_write(h2, (h2_frame_t *) frame);
}

static bool h2_send_default_settings(h2_t * const h2)
{
  if (h2->settings_pending) {
    h2_emit_error_and_close_with_debug_data(h2, 0, H2_ERROR_INTERNAL_ERROR,
        "Tried to send 2 settings frames at once");
    return false;
  }

  uint8_t flags = 0;

  h2_frame_settings_t * frame = (h2_frame_settings_t *) h2_frame_init(FRAME_TYPE_SETTINGS, flags, 0);
  frame->num_settings = 1;
  frame->settings[0].id = SETTINGS_ENABLE_PUSH;
  frame->settings[0].value = 0;

  log_append(h2->log, LOG_DEBUG, "Writing default settings frame");

  h2->settings_pending = true;
  h2->incoming_push_enabled_pending = true;
  h2->incoming_push_enabled_pending_value = false;

  return h2_frame_write(h2, (h2_frame_t *) frame);
}

static bool h2_send_ping_ack(const h2_t * const h2, const uint8_t * const opaque_data)
{
  uint8_t flags = 0;
  bool ack = true;

  if (ack) {
    flags |= FLAG_ACK;
  }

  h2_frame_ping_t * frame = (h2_frame_ping_t *) h2_frame_init(FRAME_TYPE_PING, flags, 0);
  memcpy(frame->opaque_data, opaque_data, PING_OPAQUE_DATA_LENGTH);

  log_append(h2->log, LOG_DEBUG, "Writing ping ack frame");

  return h2_frame_write(h2, (h2_frame_t *) frame);
}

static bool h2_send_window_update(const h2_t * const h2, const uint32_t stream_id,
                                  const size_t increment)
{
  uint8_t flags = 0; // no flags

  h2_frame_window_update_t * frame = (h2_frame_window_update_t *) h2_frame_init(FRAME_TYPE_WINDOW_UPDATE, flags, stream_id);
  frame->increment = increment;

  log_append(h2->log, LOG_DEBUG, "Writing window update frame");

  if (!h2_frame_write(h2, (h2_frame_t *) frame)) {
    log_append(h2->log, LOG_WARN, "Could not write window update frame");
    return false;
  }

  // flush the connection so that we write the window update as soon as possible
  if (!h2_flush(h2, 0)) {
    log_append(h2->log, LOG_WARN, "Could not flush write buffer after window update");
    return false;
  }

  return true;
}

static bool h2_adjust_initial_window_size(h2_t * const h2, const long difference)
{
  hash_table_iter_t iter;
  hash_table_iterator_init(&iter, h2->streams);

  while (hash_table_iterate(&iter)) {
    h2_stream_t * stream = iter.value;

    stream->outgoing_window_size += difference;

    if (stream->outgoing_window_size > MAX_WINDOW_SIZE) {
      h2_emit_error_and_close_with_debug_data(h2, stream->id, H2_ERROR_FLOW_CONTROL_ERROR, NULL);
      return true;
    }
  }

  return true;
}

static bool h2_setting_set(h2_t * const h2, const h2_setting_t * setting)
{
  log_append(h2->log, LOG_TRACE, "Settings: %u: %u", setting->id, setting->value);

  enum settings_e value = setting->value;

  switch (setting->id) {
    case SETTINGS_HEADER_TABLE_SIZE:
      log_append(h2->log, LOG_TRACE, "Settings: Got table size: %u", value);

      h2->header_table_size = value;
      hpack_header_table_adjust_size(h2->decoding_context, value);
      break;

    case SETTINGS_ENABLE_PUSH:
      log_append(h2->log, LOG_TRACE, "Settings: Enable push? %s", value ? "yes" : "no");

      h2->enable_push = value;
      break;

    case SETTINGS_MAX_CONCURRENT_STREAMS:
      log_append(h2->log, LOG_TRACE, "Settings: Max concurrent streams: %u", value);

      h2->max_concurrent_streams = value;
      break;

    case SETTINGS_INITIAL_WINDOW_SIZE:
      log_append(h2->log, LOG_TRACE, "Settings: Initial window size: %u", value);

      if (!h2_adjust_initial_window_size(h2, value - h2->initial_window_size)) {
        return false;
      }
      h2->initial_window_size = value;
      break;

    case SETTINGS_MAX_FRAME_SIZE:
      log_append(h2->log, LOG_TRACE, "Settings: Initial max frame size: %u", value);

      h2->max_frame_size = value;
      break;

    case SETTINGS_MAX_HEADER_LIST_SIZE:
      log_append(h2->log, LOG_TRACE, "Settings: Initial max header list size: %u", value);

      // TODO - send to hpack encoding context
      h2->max_header_list_size = value;
      break;

    default:
      // unknown settings should be ignored
      log_append(h2->log, LOG_DEBUG, "Unknown setting: id: %u (0x%x), value: %u (0x%x)",
          setting->id, setting->id, value, value);
      return true;
  }

  return true;
}

static h2_stream_t * h2_stream_init(h2_t * const h2, const uint32_t stream_id, bool incoming_push)
{

  log_append(h2->log, LOG_TRACE, "Opening stream #%u", stream_id);

  h2_stream_t * stream = h2_stream_get(h2, stream_id);

  if (stream != NULL) {
    h2_emit_error_and_close(h2, 0, H2_ERROR_PROTOCOL_ERROR,
                         "Tried to initialize an existing stream: %u", stream_id);
    return NULL;
  }

  stream = malloc(sizeof(h2_stream_t));

  if (!stream) {
    h2_emit_error_and_close(h2, stream_id, H2_ERROR_INTERNAL_ERROR,
                         "Unable to initialize stream: %u", stream_id);
    return NULL;
  }

  stream->h2 = h2;

  long * stream_id_key = malloc(sizeof(long));

  if (!stream_id_key) {
    h2_emit_error_and_close(h2, stream_id, H2_ERROR_INTERNAL_ERROR,
                         "Unable to initialize stream (stream identifier): %u", stream_id);
    free(stream);
    return NULL;
  }

  * stream_id_key = stream_id;
  hash_table_put(h2->streams, stream_id_key, stream);

  stream->queued_data_frames = NULL;

  stream->id = stream_id;
  stream->incoming_push = incoming_push;
  stream->state = STREAM_STATE_IDLE;
  stream->closing = false;
  stream->header_fragments = NULL;
  stream->headers = NULL;

  stream->priority_exclusive = DEFAULT_PRIORITY_STREAM_EXCLUSIVE;
  stream->priority_stream_dependency = DEFAULT_PRIORITY_STREAM_DEPENDENCY;
  stream->priority_weight = DEFAULT_PRIORITY_WEIGHT;;

  stream->outgoing_window_size = h2->initial_window_size;
  stream->incoming_window_size = DEFAULT_INITIAL_WINDOW_SIZE;

  stream->associated_stream_id = 0;

  stream->request = NULL;
  stream->response = NULL;

  return stream;
}

static bool h2_trigger_request(h2_t * const h2, h2_stream_t * const stream)
{
  if (!h2->request_init) {
    log_append(h2->log, LOG_FATAL, "No request initializer set up");

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

  if (!plugin_invoke(h2->plugin_invoker, HANDLE_REQUEST, request, response)) {
    http_response_free(response);
    stream->response = NULL;

    log_append(h2->log, LOG_ERROR, "No plugin handled this request");
    return false;
  }

  return true;
}

bool h2_request_begin(h2_t * const h2, header_list_t * headers, uint8_t * buf, size_t buf_length)
{
  h2_stream_t * stream = h2_stream_init(h2, 1, false);
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

static bool h2_incoming_frame_data(h2_t * const h2, const h2_frame_data_t * const frame)
{
  // adjust connection window size before any other processing to ensure it stays consistent
  h2->incoming_window_size -= frame->length;


  h2_stream_t * stream = h2_stream_get(h2, frame->stream_id);
  if (!stream || h2_stream_closed(h2, frame->stream_id)) {
    h2_emit_error_and_close(h2, frame->stream_id, H2_ERROR_STREAM_CLOSED,
                         "Unable to find stream #%u", frame->stream_id);
    return true;
  }

  stream->incoming_window_size -= frame->length;

  // pass on to application
  bool last_data_frame = FRAME_FLAG(frame, FLAG_END_STREAM);

  plugin_invoke(h2->plugin_invoker, HANDLE_DATA, stream->request, stream->response,
                frame->payload, frame->payload_length, last_data_frame, false);

  // do we need to send WINDOW_UPDATE?
  if (h2->incoming_window_size < 0) {

    h2_emit_error_and_close(h2, 0, H2_ERROR_FLOW_CONTROL_ERROR,
        "Connection window size is less than 0: %ld", h2->incoming_window_size);
    return false;

  } else if (h2->incoming_window_size < 0.75 * DEFAULT_INITIAL_WINDOW_SIZE) {

    size_t increment = DEFAULT_INITIAL_WINDOW_SIZE - h2->incoming_window_size;

    if (!h2_send_window_update(h2, 0, increment)) {
      h2_emit_error_and_close_with_debug_data(h2, 0, H2_ERROR_INTERNAL_ERROR, "Unable to emit window update frame");
      return false;
    }

    h2->incoming_window_size += increment;

  }

  if (stream->incoming_window_size < 0) {

    h2_emit_error_and_close(h2, stream->id, H2_ERROR_FLOW_CONTROL_ERROR,
                         "Stream #%u: window size is less than 0: %ld", stream->id, stream->incoming_window_size);

  } else if (!last_data_frame && (stream->incoming_window_size < 0.75 * DEFAULT_INITIAL_WINDOW_SIZE)) {

    size_t increment = DEFAULT_INITIAL_WINDOW_SIZE - stream->incoming_window_size;

    if (!h2_send_window_update(h2, stream->id, increment)) {
      h2_emit_error_and_close(h2, stream->id, H2_ERROR_INTERNAL_ERROR, "Unable to emit window update frame");
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
    log_append(h2->log, LOG_TRACE, "Counting header fragment lengths: %lu", current->length);

    headers_length += current->length;
  }

  uint8_t * headers = malloc(headers_length + 1);

  if (!headers) {
    h2_emit_error_and_close(h2, stream->id, H2_ERROR_INTERNAL_ERROR, "Unable to allocate memory for headers");
    return true;
  }

  uint8_t * header_appender = headers;
  current = stream->header_fragments;

  while (current) {
    log_append(h2->log, LOG_TRACE, "Appending header fragment (%lu octets)", current->length);

    memcpy(header_appender, current->buffer, current->length);
    header_appender += current->length;
    h2_header_fragment_t * prev = current;
    current = current->next;
    free(prev->buffer);
    free(prev);
  }
  stream->header_fragments = NULL;

  *header_appender = '\0';

  log_append(h2->log, LOG_TRACE, "Got headers: (%lu octets), decoding", headers_length);

  stream->headers = hpack_decode(h2->decoding_context, headers, headers_length);

  if (!stream->headers) {
    h2_emit_error_and_close(h2, stream->id, H2_ERROR_COMPRESSION_ERROR, "Unable to decode headers");
    free(headers);
    return true;
  }

  free(headers);

  return true;
}

static bool h2_received_headers(h2_t * const h2, h2_stream_t * stream)
{
  if (!h2_parse_header_fragments(h2, stream)) {
    return false;
  }

  if (stream->priority_stream_dependency == stream->id) {
    h2_emit_error_and_close(h2, stream->id, H2_ERROR_PROTOCOL_ERROR,
        "%s (0x%x) frame stream dependency cannot match the stream id",
        frame_type_to_string(FRAME_TYPE_HEADERS), FRAME_TYPE_HEADERS);
    return true;
  }

  // TODO - check that the stream is in a valid state to be opened first
  stream->state = STREAM_STATE_OPEN;
  h2->incoming_concurrent_streams++;

  // TODO - check that the stream is not closed?
  if (!h2->closing) {
    return h2_trigger_request(h2, stream);
  }

  return true;
}

static bool h2_incoming_frame_headers(h2_t * const h2, const h2_frame_headers_t * const frame)
{
  h2_stream_t * stream = h2_stream_init(h2, frame->stream_id, false);

  if (!stream) {
    return false;
  }

  if (FRAME_FLAG(frame, FLAG_PRIORITY)) {
    stream->priority_exclusive = frame->priority_exclusive;
    stream->priority_stream_dependency = frame->priority_stream_dependency;
    stream->priority_weight = frame->priority_weight;
  }

  if (!h2_stream_add_header_fragment(stream, frame->header_block_fragment,
                                     frame->header_block_fragment_length)) {
    return false;
  }

  if (FRAME_FLAG(frame, FLAG_END_HEADERS)) {
    // parse the headers
    log_append(h2->log, LOG_TRACE, "Parsing headers");

    return h2_received_headers(h2, stream);

  } else {
    // mark the connection as waiting for a continuation frame
    h2->continuation_stream_id = frame->stream_id;
  }

  return true;
}

static bool h2_received_push_promise(h2_t * const h2, h2_stream_t * stream)
{
  if (!h2_parse_header_fragments(h2, stream)) {
    return false;
  }

  h2_stream_mark_closing(h2, stream);
  h2_stream_close(h2, stream, false);

  if (h2->incoming_push_enabled) {

    h2_emit_error_and_close(h2, stream->id, H2_ERROR_REFUSED_STREAM, NULL);
    return true;

  } else {

    h2_emit_error_and_close(h2, 0, H2_ERROR_PROTOCOL_ERROR,
        "Received %s (0x%x) frame, but SETTINGS_PUSH_ENABLED is off",
        frame_type_to_string(FRAME_TYPE_PUSH_PROMISE), FRAME_TYPE_PUSH_PROMISE);
    return false;

  }

}

static bool h2_incoming_frame_push_promise(h2_t * const h2, const h2_frame_push_promise_t * const frame)
{
  h2_stream_t * stream = h2_stream_init(h2, frame->promised_stream_id, true);
  if (!stream) {
    return false;
  }

  if (!h2_stream_add_header_fragment(stream, frame->header_block_fragment,
                                     frame->header_block_fragment_length)) {
    return false;
  }

  if (FRAME_FLAG(frame, FLAG_END_HEADERS)) {
    log_append(h2->log, LOG_TRACE, "Parsing push promise");

    return h2_received_push_promise(h2, stream);

  } else {
    // mark the connection as waiting for a continuation frame
    h2->continuation_stream_id = frame->promised_stream_id;
  }

  return true;
}

static bool h2_incoming_frame_continuation(h2_t * const h2, const h2_frame_continuation_t * const frame)
{
  if (h2->continuation_stream_id == 0) {
    h2_emit_error_and_close(h2, 0, H2_ERROR_PROTOCOL_ERROR,
        "Unexpected %s (0x%x) frame", frame_type_to_string(frame->type), frame->type);
    return false;
  }
  // for a push promise continuation, is this stream ID correct?
  h2_stream_t * stream = h2_stream_get(h2, h2->continuation_stream_id);

  if (!h2_stream_add_header_fragment(stream, frame->header_block_fragment,
        frame->header_block_fragment_length)) {
    return false;
  }

  if (FRAME_FLAG(frame, FLAG_END_HEADERS)) {
    // unmark connection as waiting for continuation frame
    h2->continuation_stream_id = 0;
    // parse the headers
    log_append(h2->log, LOG_TRACE, "Parsing headers + continuations");


    if (stream->incoming_push) {
      return h2_received_push_promise(h2, stream);
    } else {
      return h2_received_headers(h2, stream);
    }
  }

  return true;
}

static bool h2_incoming_frame_settings(h2_t * const h2, const h2_frame_settings_t * const frame)
{

  if (FRAME_FLAG(frame, FLAG_ACK)) {

    if (frame->length != 0) {
      h2_emit_error_and_close(h2, 0, H2_ERROR_FRAME_SIZE_ERROR,
                           "Non-zero frame size for ACK settings frame: %lu", frame->length);
      return false;
    }

    if (!h2->settings_pending) {
      h2_emit_error_and_close(h2, 0, H2_ERROR_INTERNAL_ERROR,
          "Received unknown %s (0x%x) ACK.", frame_type_to_string(frame->type), frame->type);
      return false;
    }

    log_append(h2->log, LOG_TRACE, "Received settings ACK");

    // Mark the settings frame we sent as acknowledged.
    // We currently don't send any settings that require
    // synchonization
    if (h2->incoming_push_enabled_pending) {
      h2->incoming_push_enabled = h2->incoming_push_enabled_pending_value;
      h2->incoming_push_enabled_pending = false;
    }

    h2->settings_pending = false;

    return true;

  } else {
    for (size_t i = 0; i < frame->num_settings; i++) {
      const h2_setting_t * setting = &frame->settings[i];
      h2_setting_set(h2, setting);
    }

    log_append(h2->log, LOG_TRACE, "Settings: %lu, %u, %lu, %lu", h2->header_table_size, h2->enable_push,
               h2->max_concurrent_streams, h2->initial_window_size);

    bool ret = h2_send_settings_ack(h2);

    if (!h2->received_settings) {
      h2->received_settings = true;
      if (!h2_send_default_settings(h2)) {
        return false;
      }
    }

    h2_flush(h2, 0);

    return ret;
  }

}

static bool h2_incoming_frame_ping(h2_t * const h2, const h2_frame_ping_t * const frame)
{
  return h2_send_ping_ack(h2, frame->opaque_data);
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
    log_append(h2->log, LOG_TRACE, "Can't update stream #%u's window size, already closed", stream_id);
    // the stream may have been recently closed, ignore
    return true;
  }

  h2_stream_t * stream = h2_stream_get(h2, stream_id);

  if (!stream) {
    h2_emit_error_and_close(h2, stream_id, H2_ERROR_PROTOCOL_ERROR,
                         "Could not find stream #%u to update it's window size", stream_id);
    return true;
  }

  stream->outgoing_window_size += increment;

  log_append(h2->log, LOG_TRACE, "Stream window size incremented to: %ld", stream->outgoing_window_size);

  return h2_trigger_send_data(h2, stream);

}

static bool h2_incoming_frame_window_update(h2_t * const h2,
    h2_frame_window_update_t * const frame)
{
  bool success = false;

  if (frame->stream_id > 0) {
    success = h2_increment_stream_window_size(h2, frame->stream_id, frame->increment);
  } else {
    success = h2_increment_connection_window_size(h2, frame->increment);
  }

  log_append(h2->log, LOG_TRACE, "Received window update, stream: %u, increment: %u",
             frame->stream_id, frame->increment);

  return success;
}

static bool h2_incoming_frame_rst_stream(h2_t * const h2, h2_frame_rst_stream_t * const frame)
{
  log_append(h2->log, LOG_WARN, "Received reset stream: stream #%u, error code: %s (0x%x)",
             frame->stream_id, h2_error_to_string(frame->error_code), frame->error_code);

  h2_stream_t * stream = h2_stream_get(h2, frame->stream_id);
  if (stream == NULL) {
    h2_emit_error_and_close(h2, 0, H2_ERROR_PROTOCOL_ERROR,
                         "Received %s (0x%x) for stream in IDLE state: %u",
                         frame_type_to_string(frame->type), frame->type, frame->stream_id);
    return false;
  }

  h2_stream_close(h2, stream, true);

  return true;
}

static bool h2_incoming_frame_priority(h2_t * const h2, h2_frame_priority_t * const frame)
{
  h2_stream_t * stream = h2_stream_get(h2, frame->stream_id);

  if (!stream) {
    log_append(h2->log, LOG_DEBUG, "Unknown stream id for priority frame: %u",
                         frame->stream_id);
    return true;
  }

  stream->priority_exclusive = frame->priority_exclusive;
  stream->priority_stream_dependency = frame->priority_stream_dependency;
  stream->priority_weight = frame->priority_weight;

  return true;
}

static bool h2_incoming_frame_goaway(h2_t * const h2, h2_frame_goaway_t * const frame)
{
  if (frame->error_code == H2_ERROR_NO_ERROR) {
    log_append(h2->log, LOG_TRACE, "Received goaway, last stream: %u, error code: %s (0x%x), debug_data: %s",
               frame->last_stream_id, h2_error_to_string(frame->error_code),
               frame->error_code, frame->debug_data_length > 0 ? frame->debug_data : NULL);
    h2_mark_closing(h2);
  } else {
    log_append(h2->log, LOG_ERROR, "Received goaway, last stream: %u, error code: %s (0x%x), debug_data: %s",
               frame->last_stream_id, h2_error_to_string(frame->error_code),
               frame->error_code, frame->debug_data_length > 0 ? frame->debug_data : NULL);
  }

  return true;
}

static bool h2_incoming_frame(void * data, const h2_frame_t * const frame)
{
  h2_t * h2 = data;
  bool success = false;

  if (!h2->received_settings && frame->type != FRAME_TYPE_SETTINGS) {
    h2_emit_error_and_close(h2, 0, H2_ERROR_PROTOCOL_ERROR,
        "Expected settings frame but got: %s (0x%x)", frame_type_to_string(frame->type), frame->type);
    return false;
  }

  if (h2->continuation_stream_id != 0 && frame->type != FRAME_TYPE_CONTINUATION) {
    h2_emit_error_and_close(h2, 0, H2_ERROR_PROTOCOL_ERROR,
        "Expected continuation frame but got: %s (0x%x)", frame_type_to_string(frame->type), frame->type);
    return false;
  }

  switch (frame->type) {
    case FRAME_TYPE_DATA:
      plugin_invoke(h2->plugin_invoker, INCOMING_FRAME_DATA, frame, h2->buffer_position);
      success = h2_incoming_frame_data(h2, (h2_frame_data_t *) frame);
      break;

    case FRAME_TYPE_HEADERS:
      plugin_invoke(h2->plugin_invoker, INCOMING_FRAME_HEADERS, frame, h2->buffer_position);
      success = h2_incoming_frame_headers(h2, (h2_frame_headers_t *) frame);
      break;

    case FRAME_TYPE_PRIORITY:
      plugin_invoke(h2->plugin_invoker, INCOMING_FRAME_PRIORITY, frame, h2->buffer_position);
      success = h2_incoming_frame_priority(h2, (h2_frame_priority_t *) frame);
      break;

    case FRAME_TYPE_RST_STREAM:
      plugin_invoke(h2->plugin_invoker, INCOMING_FRAME_RST_STREAM, frame, h2->buffer_position);
      success = h2_incoming_frame_rst_stream(h2, (h2_frame_rst_stream_t *) frame);
      break;

    case FRAME_TYPE_SETTINGS:
      plugin_invoke(h2->plugin_invoker, INCOMING_FRAME_SETTINGS, frame, h2->buffer_position);
      success = h2_incoming_frame_settings(h2, (h2_frame_settings_t *) frame);
      break;

    case FRAME_TYPE_PUSH_PROMISE:
      plugin_invoke(h2->plugin_invoker, INCOMING_FRAME_PUSH_PROMISE, frame, h2->buffer_position);
      success = h2_incoming_frame_push_promise(h2, (h2_frame_push_promise_t *) frame);
      break;

    case FRAME_TYPE_PING:
      plugin_invoke(h2->plugin_invoker, INCOMING_FRAME_PING, frame, h2->buffer_position);
      success = h2_incoming_frame_ping(h2, (h2_frame_ping_t *) frame);
      break;

    case FRAME_TYPE_GOAWAY:
      plugin_invoke(h2->plugin_invoker, INCOMING_FRAME_GOAWAY, frame, h2->buffer_position);
      success = h2_incoming_frame_goaway(h2, (h2_frame_goaway_t *) frame);
      break;

    case FRAME_TYPE_WINDOW_UPDATE:
      plugin_invoke(h2->plugin_invoker, INCOMING_FRAME_WINDOW_UPDATE, frame, h2->buffer_position);
      success = h2_incoming_frame_window_update(h2, (h2_frame_window_update_t *) frame);
      break;

    case FRAME_TYPE_CONTINUATION:
      plugin_invoke(h2->plugin_invoker, INCOMING_FRAME_CONTINUATION, frame, h2->buffer_position);
      success = h2_incoming_frame_continuation(h2, (h2_frame_continuation_t *) frame);
      break;

    default:
      h2_emit_error_and_close(h2, 0, H2_ERROR_INTERNAL_ERROR, "Unhandled frame type: %s (0x%x)",
          frame_type_to_string(frame->type), frame->type);
      success = false;
      break;
  }

  if (success) {
    plugin_invoke(h2->plugin_invoker, POSTPROCESS_INCOMING_FRAME, frame);
  }

  return success;
}

bool h2_settings_apply(h2_t * const h2, char * base64)
{
  binary_buffer_t buf;
  binary_buffer_init(&buf, 0);

  base64url_decode(&buf, base64);

  h2_frame_settings_t frame;
  frame.type = FRAME_TYPE_SETTINGS;
  frame.flags = 0;
  frame.length = strlen(base64);
  frame.stream_id = 0;

  h2_parse_settings_payload(&h2->frame_parser, binary_buffer_start(&buf), binary_buffer_size(&buf),
      &frame.num_settings, frame.settings);
  binary_buffer_free(&buf);

  plugin_invoke(h2->plugin_invoker, INCOMING_FRAME_SETTINGS, &frame);
  h2_incoming_frame_settings(h2, &frame);

  h2->received_settings = true;

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

static bool h2_parse_error_cb(void * data, uint32_t stream_id, enum h2_error_code_e error_code,
    char * format, ...)
{
  h2_t * h2 = data;
  size_t buf_length = 1024;
  char buf[buf_length];

  va_list args;
  va_start(args, format);
  if (format) {
    vsnprintf(buf, buf_length, format, args);
  }
  va_end(args);

  return h2_emit_error_and_close_with_debug_data(h2, stream_id, error_code, format ? buf : NULL);
}

/**
 * Processes the next frame in the buffer.
 *
 * Returns true a frame was processed.
 * Returns false if there was no frame to process.
 */
static bool h2_add_from_buffer(h2_t * const h2)
{
  h2_frame_t * frame = h2_frame_parse(&h2->frame_parser, h2->buffer, h2->buffer_length, &h2->buffer_position);

  if (frame) {
    free(frame);
    return true;
  }
  return false;
}

/**
 * Reads the given buffer and acts on it. Caller must give up ownership of the
 * buffer.
 */
void h2_read(h2_t * const h2, uint8_t * const buffer, const size_t len)
{
  log_append(h2->log, LOG_TRACE, "Reading from buffer: %zu", len);

  size_t unprocessed_bytes = h2->buffer_length;

  if (unprocessed_bytes > 0) {
    log_append(h2->log, LOG_TRACE, "Appending new data to unprocessed bytes %zu + %zu = %zu",
               unprocessed_bytes, len, unprocessed_bytes + len);
    // there are still unprocessed bytes
    h2->buffer = realloc(h2->buffer, unprocessed_bytes + len);

    if (!h2->buffer) {
      h2_emit_error_and_close_with_debug_data(h2, 0, H2_ERROR_INTERNAL_ERROR,
          "Unable to allocate memory for reading full frame");
      free(buffer);
      h2->buffer_length = 0;
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
      h2_emit_error_and_close_with_debug_data(h2, 0, H2_ERROR_INADEQUATE_SECURITY, "Inadequate security");
      free(h2->buffer);
      h2->buffer = NULL;
      h2->buffer_length = 0;
      return;
    }
  }

  if (!h2->received_connection_preface) {
    enum h2_detect_result_e result = h2_detect_connection(h2->buffer, h2->buffer_length);
    if (result == H2_DETECT_SUCCESS) {
      h2->received_connection_preface = true;
      h2->buffer_position = H2_CONNECTION_PREFACE_LENGTH;

      log_append(h2->log, LOG_TRACE, "Found HTTP2 connection");
    } else if (result == H2_DETECT_NEED_MORE_DATA) {
      log_append(h2->log, LOG_WARN, "Need more data to detect connection");
      goto handle_buffer;
      return;
    } else {
      log_append(h2->log, LOG_WARN, "Found non-HTTP2 connection, closing connection");
      free(h2->buffer);
      h2->buffer = NULL;
      h2->buffer_length = 0;

      h2_mark_closing(h2);
      h2_close(h2);
      return;
    }
  }

  h2->reading_from_client = true;

  while (h2_add_from_buffer(h2));

  h2->reading_from_client = false;

handle_buffer:

  if (!h2_flush(h2, 0)) {
    log_append(h2->log, LOG_WARN, "Could not flush write buffer");
  }

  if (h2->buffer_position > h2->buffer_length) {
    // buffer overflow
    h2_emit_error_and_close_with_debug_data(h2, 0, H2_ERROR_INTERNAL_ERROR, NULL);
    h2->buffer = NULL;
    h2->buffer_length = 0;
    free(h2->buffer);
    return;
  }

  // if there is still unprocessed data in the buffer, save it for when we
  // get the rest of the frame
  unprocessed_bytes = h2->buffer_length - h2->buffer_position;

  if (!h2->closing && unprocessed_bytes > 0) {
    log_append(h2->log, LOG_TRACE, "Unable to process last %zu bytes", unprocessed_bytes);
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
  snprintf(status_buf, 10, "%u", response->status);
  // add the status header
  http_response_pseudo_header_add(response, ":status", status_buf);

  if (stream->state != STREAM_STATE_CLOSED) {
    if (!h2_send_headers(h2, stream, response->headers)) {
      h2_emit_error_and_close_with_debug_data(h2, stream->id, H2_ERROR_INTERNAL_ERROR,
          "Unable to emit headers");
      return false;
    }

    if (data || last) {
      if (!h2_send_data(h2, stream, data, data_length, last)) {
        h2_emit_error_and_close_with_debug_data(h2, stream->id, H2_ERROR_INTERNAL_ERROR,
            "Unable to emit data");
        return false;
      }
    }
  }

  if (last && !h2->reading_from_client) {
    h2_flush(h2, 0);
  }

  if (last) {
    http_response_free(response);
    stream->response = NULL;

    h2_stream_mark_closing(h2, stream);
  }

  return true;
}

bool h2_response_write_data(h2_stream_t * stream, http_response_t * const response, uint8_t * data,
                            const size_t data_length, bool last)
{

  h2_t * h2 = stream->h2;

  if (data || last) {
    if (!h2_send_data(h2, stream, data, data_length, last)) {
      h2_emit_error_and_close_with_debug_data(h2, stream->id, H2_ERROR_INTERNAL_ERROR,
          "Unable to emit data");
      return false;
    }
  }

  if (last && !h2->reading_from_client) {
    h2_flush(h2, 0);
  }

  if (last) {
    http_response_free(response);
    stream->response = NULL;

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

  if (!h2->request_init) {
    return NULL;
  }

  if (!h2->enable_push) {
    return NULL;
  }

  if (h2->outgoing_concurrent_streams >= h2->max_concurrent_streams) {
    log_append(h2->log, LOG_DEBUG, "Tried opening more than %zu outgoing concurrent streams: stream #%u",
               h2->max_concurrent_streams, stream->id);
    return NULL;
  } else {
    log_append(h2->log, LOG_DEBUG, "Push #%zu for stream: stream #%u\n",
               h2->outgoing_concurrent_streams, stream->id);
  }

  h2_stream_t * pushed_stream = h2_stream_init(h2, h2->current_stream_id, false);
  ASSERT_OR_RETURN_NULL(pushed_stream);
  h2->current_stream_id += 2;

  pushed_stream->state = STREAM_STATE_RESERVED_LOCAL;
  h2->outgoing_concurrent_streams++;

  pushed_stream->associated_stream_id = stream->id;

  http_request_t * pushed_request = h2->request_init(h2->data, pushed_stream, NULL);
  ASSERT_OR_RETURN_NULL(pushed_request);

  pushed_stream->request = pushed_request;
  pushed_stream->response = NULL;

  return pushed_request;
}

bool h2_push_promise(h2_stream_t * pushed_stream, http_request_t * const pushed_request)
{

  h2_t * h2 = pushed_stream->h2;

  return h2_send_push_promise(h2, pushed_stream, pushed_request->headers,
                              pushed_stream->associated_stream_id);

}

http_response_t * h2_push_response_get(h2_stream_t * stream, http_request_t * const request)
{
  http_response_t * pushed_response = http_response_init(request);
  stream->response = pushed_response;

  return pushed_response;
}

