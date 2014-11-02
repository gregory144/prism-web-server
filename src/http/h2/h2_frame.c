#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "util.h"

#include "h2_frame.h"
#include "h2.h"

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

bool h2_frame_flag_get(const h2_frame_t * const frame, int mask)
{
  return frame->flags & mask;
}

h2_frame_t * h2_frame_init(const h2_t * const h2, const uint32_t length, const uint8_t type,
                                  const uint8_t flags, const uint32_t stream_id)
{
  UNUSED(h2);

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
      return NULL;
  }

  frame->type = type;
  frame->flags = flags;
  frame->length = length;
  frame->stream_id = stream_id;
  return frame;
}

void h2_frame_free(h2_frame_t * frame)
{
  free(frame);
}

/**
 * We assume the input buffer is at least 8 octets
 */
static void h2_frame_header_write(uint8_t * const buf, h2_frame_t * frame)
{
  size_t pos = 0;
  const uint32_t length = frame->length;
  const uint8_t type = frame->type;
  const uint8_t flags = frame->flags;
  uint32_t stream_id = frame->stream_id;

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

static bool h2_frame_emit_data(const h2_t * const h2, h2_frame_data_t * frame)
{
  uint8_t buf[FRAME_HEADER_SIZE];
  h2_frame_header_write(buf, (h2_frame_t *) frame);

  if (!h2_write(h2, buf, FRAME_HEADER_SIZE)) {
    log_append(h2->log, LOG_ERROR, "Unable to write data frame header");
    return false;
  }

  return h2_write(h2, frame->payload, frame->payload_length);
}

static bool h2_frame_emit_headers(const h2_t * const h2, h2_frame_headers_t * frame)
{
  const size_t buf_length = FRAME_HEADER_SIZE;
  uint8_t buf[buf_length];

  h2_frame_header_write(buf, (h2_frame_t *) frame);

  if (!h2_write(h2, buf, FRAME_HEADER_SIZE)) {
    log_append(h2->log, LOG_ERROR, "Unable to write headers frame header");
    return false;
  }

  return h2_write(h2, frame->header_block_fragment, frame->header_block_fragment_length);
}

static bool h2_frame_emit_rst_stream(const h2_t * const h2, h2_frame_rst_stream_t * frame)
{
  size_t error_code_length = 4; // 32 bits

  size_t payload_length = error_code_length;
  size_t buf_length = FRAME_HEADER_SIZE + payload_length;

  size_t pos = 0;
  uint8_t buf[buf_length];

  h2_frame_header_write(buf, (h2_frame_t *) frame);
  pos += FRAME_HEADER_SIZE;

  uint32_t error_code = frame->error_code;
  buf[pos++] = (error_code >> 24) & 0xFF;
  buf[pos++] = (error_code >> 16) & 0xFF;
  buf[pos++] = (error_code >> 8) & 0xFF;
  buf[pos++] = (error_code) & 0xFF;

  log_append(h2->log, LOG_DEBUG, "Writing reset stream frame");

  return h2_write(h2, buf, buf_length);
}

static bool h2_frame_emit_settings(const h2_t * const h2, h2_frame_settings_t * frame)
{
  if (!FRAME_FLAG(frame, FLAG_ACK)) {
    log_append(h2->log, LOG_FATAL, "Can't emit settings frame: Not implemented yet");
    abort();
  }

  size_t buf_length = FRAME_HEADER_SIZE;

  uint8_t buf[buf_length];

  h2_frame_header_write(buf, (h2_frame_t *) frame);

  return h2_write(h2, buf, buf_length);
}

static bool h2_frame_emit_push_promise(const h2_t * const h2, h2_frame_push_promise_t * frame)
{
  const size_t stream_id_length = 4;
  const size_t payload_length = stream_id_length;
  const size_t buf_length = FRAME_HEADER_SIZE + payload_length;
  uint8_t buf[buf_length];

  h2_frame_header_write(buf, (h2_frame_t *) frame);

  size_t pos = FRAME_HEADER_SIZE;

  buf[pos++] = (frame->promised_stream_id >> 24) & 0x7F; // only the first 7 bits (first bit is reserved)
  buf[pos++] = (frame->promised_stream_id >> 16) & 0xFF;
  buf[pos++] = (frame->promised_stream_id >> 8) & 0xFF;
  buf[pos++] = (frame->promised_stream_id) & 0xFF;

  if (!h2_write(h2, buf, buf_length)) {
    log_append(h2->log, LOG_ERROR, "Unable to write push promise frame header");
    return false;
  }

  return h2_write(h2, frame->header_block_fragment, frame->header_block_fragment_length);
}

static bool h2_frame_emit_ping(const h2_t * const h2, h2_frame_ping_t * frame)
{
  if (!FRAME_FLAG(frame, FLAG_ACK)) {
    log_append(h2->log, LOG_FATAL, "Can't emit ping frame: Not implemented yet");
    abort();
  }

  size_t payload_length = PING_OPAQUE_DATA_LENGTH;
  size_t buf_length = FRAME_HEADER_SIZE + payload_length;
  uint8_t buf[buf_length];

  h2_frame_header_write(buf, (h2_frame_t *) frame);
  memcpy(buf + FRAME_HEADER_SIZE, frame->opaque_data, PING_OPAQUE_DATA_LENGTH);

  return h2_write(h2, buf, buf_length);
}

static bool h2_frame_emit_goaway(const h2_t * const h2, h2_frame_goaway_t * frame)
{
  size_t last_stream_id_length = 4; // 1 bit + 31 bits
  size_t error_code_length = 4; // 32 bits

  size_t debug_length = frame->debug_data_length;

  size_t payload_length = last_stream_id_length + error_code_length + debug_length;
  size_t buf_length = FRAME_HEADER_SIZE + payload_length;

  size_t pos = 0;
  uint8_t buf[buf_length];

  h2_frame_header_write(buf, (h2_frame_t *) frame);
  pos += FRAME_HEADER_SIZE;

  size_t stream_id = frame->last_stream_id;
  size_t error_code = frame->error_code;

  buf[pos++] = (stream_id >> 24) & 0x7F; // only the first 7 bits (first bit is reserved)
  buf[pos++] = (stream_id >> 16) & 0xFF;
  buf[pos++] = (stream_id >> 8) & 0xFF;
  buf[pos++] = (stream_id) & 0xFF;

  buf[pos++] = (error_code >> 24) & 0xFF;
  buf[pos++] = (error_code >> 16) & 0xFF;
  buf[pos++] = (error_code >> 8) & 0xFF;
  buf[pos++] = (error_code) & 0xFF;

  if (frame->debug_data) {
    memcpy(buf + pos, frame->debug_data, debug_length);
  }

  log_append(h2->log, LOG_DEBUG, "Writing goaway frame");

  return h2_write(h2, buf, buf_length);
}

static bool h2_frame_emit_window_update(const h2_t * const h2, h2_frame_window_update_t * frame)
{
  size_t increment_length = 4; // 32 bits

  size_t buf_length = FRAME_HEADER_SIZE + increment_length;

  size_t pos = 0;
  uint8_t buf[buf_length];

  h2_frame_header_write(buf, (h2_frame_t *) frame);
  pos += FRAME_HEADER_SIZE;

  buf[pos++] = (frame->increment >> 24) & 0xFF;
  buf[pos++] = (frame->increment >> 16) & 0xFF;
  buf[pos++] = (frame->increment >> 8) & 0xFF;
  buf[pos++] = (frame->increment) & 0xFF;

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

static bool h2_frame_emit_continuation(const h2_t * const h2, h2_frame_continuation_t * frame)
{
  const size_t buf_length = FRAME_HEADER_SIZE;
  uint8_t buf[buf_length];

  h2_frame_header_write(buf, (h2_frame_t *) frame);

  if (!h2_write(h2, buf, buf_length)) {
    log_append(h2->log, LOG_ERROR, "Unable to write continuation frame header");
    return false;
  }

  return h2_write(h2, frame->header_block_fragment, frame->header_block_fragment_length);
}

bool h2_frame_emit(const h2_t * const h2, h2_frame_t * frame)
{
  plugin_invoke(h2->plugin_invoker, OUTGOING_FRAME, frame);

  bool success = false;

  switch (frame->type) {
    case FRAME_TYPE_DATA:
      plugin_invoke(h2->plugin_invoker, OUTGOING_FRAME_DATA, frame);
      success = h2_frame_emit_data(h2, (h2_frame_data_t *) frame);
      break;

    case FRAME_TYPE_HEADERS:
      plugin_invoke(h2->plugin_invoker, OUTGOING_FRAME_HEADERS, frame);
      success = h2_frame_emit_headers(h2, (h2_frame_headers_t *) frame);
      break;

    case FRAME_TYPE_PRIORITY:
      log_append(h2->log, LOG_FATAL, "Unable to emit priority frame: Not implemented yet");
      abort();
      break;

    case FRAME_TYPE_RST_STREAM:
      plugin_invoke(h2->plugin_invoker, OUTGOING_FRAME_RST_STREAM, frame);
      success = h2_frame_emit_rst_stream(h2, (h2_frame_rst_stream_t *) frame);
      break;

    case FRAME_TYPE_SETTINGS:
      plugin_invoke(h2->plugin_invoker, OUTGOING_FRAME_SETTINGS, frame);
      success = h2_frame_emit_settings(h2, (h2_frame_settings_t *) frame);
      break;

    case FRAME_TYPE_PUSH_PROMISE:
      plugin_invoke(h2->plugin_invoker, OUTGOING_FRAME_PUSH_PROMISE, frame);
      success = h2_frame_emit_push_promise(h2, (h2_frame_push_promise_t *) frame);
      break;

    case FRAME_TYPE_PING:
      plugin_invoke(h2->plugin_invoker, OUTGOING_FRAME_PING, frame);
      success = h2_frame_emit_ping(h2, (h2_frame_ping_t *) frame);
      break;

    case FRAME_TYPE_GOAWAY:
      plugin_invoke(h2->plugin_invoker, OUTGOING_FRAME_GOAWAY, frame);
      success = h2_frame_emit_goaway(h2, (h2_frame_goaway_t *) frame);
      break;

    case FRAME_TYPE_WINDOW_UPDATE:
      plugin_invoke(h2->plugin_invoker, OUTGOING_FRAME_WINDOW_UPDATE, frame);
      success = h2_frame_emit_window_update(h2, (h2_frame_window_update_t *) frame);
      break;

    case FRAME_TYPE_CONTINUATION:
      plugin_invoke(h2->plugin_invoker, OUTGOING_FRAME_CONTINUATION, frame);
      success = h2_frame_emit_continuation(h2, (h2_frame_continuation_t *) frame);
      break;

    default:
      return false;
  }

  h2_frame_free(frame);

  return success;
}

static bool strip_padding(h2_t * const h2, uint8_t * padding_length, uint8_t ** payload, size_t * payload_length,
                          bool padded_on)
{
  if (padded_on) {
    // padding length is actually 1 less than you would expect because the padding length field
    // is one octet as well. So to pad 100 octets, the padding length field is 99 + the implicit
    // one octet from the padding length field
    *padding_length = get_bits8(*payload, 0xFF);

    (*payload_length)--;
    (*payload)++;
    *payload_length -= *padding_length;
    log_append(h2->log, LOG_TRACE, "Stripped %ld octets of padding from frame", padding_length);
  }

  return true;
}

bool h2_frame_parse_data(h2_t * const h2, h2_frame_data_t * const frame)
{
  // pass on to application
  uint8_t * buf = h2->buffer + h2->buffer_position;
  size_t buf_length = frame->length;

  bool padded = FRAME_FLAG(frame, FLAG_PADDED);
  uint8_t padding_length = 0;

  if (!strip_padding(h2, &padding_length, &buf, &buf_length, padded)) {
    h2_emit_error_and_close(h2, 0, H2_ERROR_PROTOCOL_ERROR,
                         "Problem with padding on data frame");
    return false;
  }

  frame->padding_length = padding_length;

  frame->payload = buf;
  frame->payload_length = buf_length;


  return true;
}

bool h2_frame_parse_headers(h2_t * const h2, h2_frame_headers_t * const frame)
{
  uint8_t * buf = h2->buffer + h2->buffer_position;
  size_t buf_length = frame->length;

  bool padded = FRAME_FLAG(frame, FLAG_PADDED);
  uint8_t padding_length = 0;

  if (!strip_padding(h2, &padding_length, &buf, &buf_length, padded)) {
    h2_emit_error_and_close(h2, 0, H2_ERROR_PROTOCOL_ERROR,
                         "Problem with padding on header frame");
    return false;
  }

  frame->padding_length = padding_length;

  if (FRAME_FLAG(frame, FLAG_PRIORITY)) {

    frame->priority_exclusive = get_bit(buf, 0);
    frame->priority_stream_dependency = get_bits32(buf, 0x7FFFFFFF);
    // this is the transmitted value - we'll need to add 1 to get a value between 1 and 256
    frame->priority_weight = get_bits8(buf + 4, 0xFF);

    buf += 5;
    buf_length -= 5;
  }

  frame->header_block_fragment = buf;
  frame->header_block_fragment_length = buf_length;

  return true;
}

bool h2_frame_parse_continuation(h2_t * const h2,
                                        h2_frame_continuation_t * const frame)
{
  uint8_t * buf = h2->buffer + h2->buffer_position;
  size_t buf_length = frame->length;

  frame->header_block_fragment = buf;
  frame->header_block_fragment_length = buf_length;

  return true;
}

bool h2_parse_settings_payload(h2_t * const h2, uint8_t * buffer, size_t buffer_length, size_t * num_settings,
                                      h2_setting_t * settings)
{
  *num_settings = buffer_length / SETTING_SIZE;

  if (*num_settings > 6) {
    h2_emit_error_and_close(h2, 0, H2_ERROR_INTERNAL_ERROR, "Up to 6 settings per frame supported: %ld",
                         *num_settings);
    return false;
  }

  log_append(h2->log, LOG_TRACE, "Settings: Found %ld settings", *num_settings);

  for (size_t i = 0; i < *num_settings; i++) {
    h2_setting_t * curr = &settings[i];
    uint8_t * curr_setting = buffer + (i * SETTING_SIZE);
    curr->id = get_bits16(curr_setting, 0xFFFF);
    curr->value = get_bits32(curr_setting + SETTING_ID_SIZE, 0xFFFFFFFF);
  }

  return true;
}

bool h2_frame_parse_settings(h2_t * const h2, h2_frame_settings_t * const frame)
{
  if (!FRAME_FLAG(frame, FLAG_ACK)) {
    uint8_t * pos = h2->buffer + h2->buffer_position;

    return h2_parse_settings_payload(h2, pos, frame->length, &frame->num_settings, frame->settings);
  } else {
    frame->num_settings = 0;
  }

  return true;
}

bool h2_frame_parse_ping(h2_t * const h2, h2_frame_ping_t * const frame)
{
  frame->opaque_data = h2->buffer + h2->buffer_position;

  return true;
}

bool h2_frame_parse_window_update(h2_t * const h2,
    h2_frame_window_update_t * const frame)
{
  uint8_t * buf = h2->buffer + h2->buffer_position;
  frame->increment = get_bits32(buf, 0x7FFFFFFF);

  return true;
}

bool h2_frame_parse_rst_stream(h2_t * const h2, h2_frame_rst_stream_t * const frame)
{
  uint8_t * buf = h2->buffer + h2->buffer_position;
  frame->error_code = get_bits32(buf, 0xFFFFFFFF);

  return true;
}

bool h2_frame_parse_priority(h2_t * const h2, h2_frame_priority_t * const frame)
{
  uint8_t * buf = h2->buffer + h2->buffer_position;

  frame->priority_exclusive = get_bit(buf, 0);
  frame->priority_stream_dependency = get_bits32(buf, 0x7FFFFFFF);
  // this is the transmitted value - we'll need to add 1 to get a value between 1 and 256
  frame->priority_weight = get_bits8(buf + 4, 0xFF);

  return true;
}

bool h2_frame_parse_goaway(h2_t * const h2, h2_frame_goaway_t * const frame)
{
  uint8_t * buf = h2->buffer + h2->buffer_position;
  frame->last_stream_id = get_bits32(buf, 0x7FFFFFFF);
  frame->error_code = get_bits32(buf + 4, 0xFFFFFFFF);
  frame->debug_data_length = (frame->length - 8);

  frame->debug_data = malloc(frame->debug_data_length + 1);
  memcpy(frame->debug_data, buf + 8, frame->debug_data_length);
  frame->debug_data[frame->debug_data_length] = '\0';

  return true;
}

bool h2_frame_is_valid_frame_type(enum frame_type_e frame_type)
{
  return frame_type >= FRAME_TYPE_MIN && frame_type <= FRAME_TYPE_MAX;
}

bool h2_frame_is_valid(h2_t * const h2, h2_frame_t * frame)
{
  enum frame_type_e frame_type = frame->type;
  frame_parser_definition_t def = frame_parser_definitions[frame_type];

  if (frame->length < def.length_min) {
    h2_emit_error_and_close(h2, frame->stream_id, H2_ERROR_FRAME_SIZE_ERROR, "Invalid frame length");
    return false;
  }

  if (frame->length > def.length_max) {
    h2_emit_error_and_close(h2, frame->stream_id, H2_ERROR_FRAME_SIZE_ERROR, "Invalid frame length");
    return false;
  }

  size_t i;

  for (i = 0; i < 8; i++) {
    bool can_be_set = def.flags[i];

    if (!can_be_set) {
      uint8_t mask = 1 << i;

      if (frame->flags & mask) {
        h2_emit_error_and_close(h2, frame->stream_id, H2_ERROR_PROTOCOL_ERROR, "Invalid flag set");
        return false;
      }
    }
  }

  if (frame->stream_id == 0 && def.must_have_stream_id) {
    h2_emit_error_and_close(h2, frame->stream_id, H2_ERROR_PROTOCOL_ERROR, "Stream ID must be set");
    return false;
  }

  if (frame->stream_id > 0 && def.must_not_have_stream_id) {
    h2_emit_error_and_close(h2, frame->stream_id, H2_ERROR_PROTOCOL_ERROR, "Stream ID must not be set");
    return false;
  }

  return true;
}

