#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "util.h"

#include "h2_frame.h"

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

h2_frame_t * h2_frame_init(const h2_frame_parser_t * const parser, const uint32_t length, const uint8_t type,
                                  const uint8_t flags, const uint32_t stream_id)
{
  UNUSED(parser);

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

void h2_frame_free(h2_frame_t * const frame)
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

static bool h2_frame_emit_data(const h2_frame_parser_t * const parser, binary_buffer_t * const bb, h2_frame_data_t * frame)
{
  uint8_t buf[FRAME_HEADER_SIZE];
  h2_frame_header_write(buf, (h2_frame_t *) frame);

  if (!binary_buffer_write(bb, buf, FRAME_HEADER_SIZE)) {
    log_append(parser->log, LOG_ERROR, "Unable to write data frame header");
    return false;
  }

  return binary_buffer_write(bb, frame->payload, frame->payload_length);
}

static bool h2_frame_emit_headers(const h2_frame_parser_t * const parser, binary_buffer_t * const bb,
    h2_frame_headers_t * frame)
{
  const size_t buf_length = FRAME_HEADER_SIZE;
  uint8_t buf[buf_length];

  h2_frame_header_write(buf, (h2_frame_t *) frame);

  if (!binary_buffer_write(bb, buf, FRAME_HEADER_SIZE)) {
    log_append(parser->log, LOG_ERROR, "Unable to write headers frame header");
    return false;
  }

  return binary_buffer_write(bb, frame->header_block_fragment, frame->header_block_fragment_length);
}

static bool h2_frame_emit_rst_stream(const h2_frame_parser_t * const parser, binary_buffer_t * const bb,
    h2_frame_rst_stream_t * frame)
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

  log_append(parser->log, LOG_DEBUG, "Writing reset stream frame");

  return binary_buffer_write(bb, buf, buf_length);
}

static bool h2_frame_emit_settings(const h2_frame_parser_t * const parser, binary_buffer_t * const bb,
    h2_frame_settings_t * frame)
{
  if (!FRAME_FLAG(frame, FLAG_ACK)) {
    log_append(parser->log, LOG_FATAL, "Can't emit settings frame: Not implemented yet");
    abort();
  }

  size_t buf_length = FRAME_HEADER_SIZE;

  uint8_t buf[buf_length];

  h2_frame_header_write(buf, (h2_frame_t *) frame);

  return binary_buffer_write(bb, buf, buf_length);
}

static bool h2_frame_emit_push_promise(const h2_frame_parser_t * const parser, binary_buffer_t * const bb, h2_frame_push_promise_t * frame)
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

  if (!binary_buffer_write(bb, buf, buf_length)) {
    log_append(parser->log, LOG_ERROR, "Unable to write push promise frame header");
    return false;
  }

  return binary_buffer_write(bb, frame->header_block_fragment, frame->header_block_fragment_length);
}

static bool h2_frame_emit_ping(const h2_frame_parser_t * const parser, binary_buffer_t * const bb,
    h2_frame_ping_t * frame)
{
  if (!FRAME_FLAG(frame, FLAG_ACK)) {
    log_append(parser->log, LOG_FATAL, "Can't emit ping frame: Not implemented yet");
    abort();
  }

  size_t payload_length = PING_OPAQUE_DATA_LENGTH;
  size_t buf_length = FRAME_HEADER_SIZE + payload_length;
  uint8_t buf[buf_length];

  h2_frame_header_write(buf, (h2_frame_t *) frame);
  memcpy(buf + FRAME_HEADER_SIZE, frame->opaque_data, PING_OPAQUE_DATA_LENGTH);

  return binary_buffer_write(bb, buf, buf_length);
}

static bool h2_frame_emit_goaway(const h2_frame_parser_t * const parser, binary_buffer_t * const bb,
    h2_frame_goaway_t * frame)
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

  log_append(parser->log, LOG_DEBUG, "Writing goaway frame");

  return binary_buffer_write(bb, buf, buf_length);
}

static bool h2_frame_emit_window_update(const h2_frame_parser_t * const parser, binary_buffer_t * const bb,
    h2_frame_window_update_t * frame)
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

  log_append(parser->log, LOG_DEBUG, "Writing window update frame");

  if (!binary_buffer_write(bb, buf, buf_length)) {
    return false;
  }

  return true;
}

static bool h2_frame_emit_continuation(const h2_frame_parser_t * const parser, binary_buffer_t * const bb,
    h2_frame_continuation_t * frame)
{
  const size_t buf_length = FRAME_HEADER_SIZE;
  uint8_t buf[buf_length];

  h2_frame_header_write(buf, (h2_frame_t *) frame);

  if (!binary_buffer_write(bb, buf, buf_length)) {
    log_append(parser->log, LOG_ERROR, "Unable to write continuation frame header");
    return false;
  }

  return binary_buffer_write(bb, frame->header_block_fragment, frame->header_block_fragment_length);
}

bool h2_frame_emit(const h2_frame_parser_t * const parser, binary_buffer_t * const bb, h2_frame_t * frame)
{
  plugin_invoke(parser->plugin_invoker, OUTGOING_FRAME, frame);

  bool success = false;

  switch (frame->type) {
    case FRAME_TYPE_DATA:
      plugin_invoke(parser->plugin_invoker, OUTGOING_FRAME_DATA, frame);
      success = h2_frame_emit_data(parser, bb, (h2_frame_data_t *) frame);
      break;

    case FRAME_TYPE_HEADERS:
      plugin_invoke(parser->plugin_invoker, OUTGOING_FRAME_HEADERS, frame);
      success = h2_frame_emit_headers(parser, bb, (h2_frame_headers_t *) frame);
      break;

    case FRAME_TYPE_PRIORITY:
      log_append(parser->log, LOG_FATAL, "Unable to emit priority frame: Not implemented yet");
      abort();
      break;

    case FRAME_TYPE_RST_STREAM:
      plugin_invoke(parser->plugin_invoker, OUTGOING_FRAME_RST_STREAM, frame);
      success = h2_frame_emit_rst_stream(parser, bb, (h2_frame_rst_stream_t *) frame);
      break;

    case FRAME_TYPE_SETTINGS:
      plugin_invoke(parser->plugin_invoker, OUTGOING_FRAME_SETTINGS, frame);
      success = h2_frame_emit_settings(parser, bb, (h2_frame_settings_t *) frame);
      break;

    case FRAME_TYPE_PUSH_PROMISE:
      plugin_invoke(parser->plugin_invoker, OUTGOING_FRAME_PUSH_PROMISE, frame);
      success = h2_frame_emit_push_promise(parser, bb, (h2_frame_push_promise_t *) frame);
      break;

    case FRAME_TYPE_PING:
      plugin_invoke(parser->plugin_invoker, OUTGOING_FRAME_PING, frame);
      success = h2_frame_emit_ping(parser, bb, (h2_frame_ping_t *) frame);
      break;

    case FRAME_TYPE_GOAWAY:
      plugin_invoke(parser->plugin_invoker, OUTGOING_FRAME_GOAWAY, frame);
      success = h2_frame_emit_goaway(parser, bb, (h2_frame_goaway_t *) frame);
      break;

    case FRAME_TYPE_WINDOW_UPDATE:
      plugin_invoke(parser->plugin_invoker, OUTGOING_FRAME_WINDOW_UPDATE, frame);
      success = h2_frame_emit_window_update(parser, bb, (h2_frame_window_update_t *) frame);
      break;

    case FRAME_TYPE_CONTINUATION:
      plugin_invoke(parser->plugin_invoker, OUTGOING_FRAME_CONTINUATION, frame);
      success = h2_frame_emit_continuation(parser, bb, (h2_frame_continuation_t *) frame);
      break;

    default:
      return false;
  }

  h2_frame_free(frame);

  return success;
}

static bool strip_padding(const h2_frame_parser_t * const parser, uint8_t * padding_length, uint8_t ** payload, size_t * payload_length,
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
    log_append(parser->log, LOG_TRACE, "Stripped %ld octets of padding from frame", padding_length);
  }

  return true;
}

static bool h2_frame_parse_data(const h2_frame_parser_t * const parser, uint8_t * buf,
    h2_frame_data_t * const frame)
{
  // pass on to application
  size_t buf_length = frame->length;

  bool padded = FRAME_FLAG(frame, FLAG_PADDED);
  uint8_t padding_length = 0;

  if (!strip_padding(parser, &padding_length, &buf, &buf_length, padded)) {
    log_append(parser->log, LOG_ERROR, "Problem with padding on data frame");
    return false;
  }

  frame->padding_length = padding_length;

  frame->payload = buf;
  frame->payload_length = buf_length;

  return true;
}

static bool h2_frame_parse_headers(const h2_frame_parser_t * const parser, uint8_t * buf,
    h2_frame_headers_t * const frame)
{
  size_t buf_length = frame->length;

  bool padded = FRAME_FLAG(frame, FLAG_PADDED);
  uint8_t padding_length = 0;

  if (!strip_padding(parser, &padding_length, &buf, &buf_length, padded)) {
    log_append(parser->log, LOG_ERROR, "Problem with padding on header frame");
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

static bool h2_frame_parse_continuation(const h2_frame_parser_t * const parser, uint8_t * buf,
                                        h2_frame_continuation_t * const frame)
{
  UNUSED(parser);

  size_t buf_length = frame->length;

  frame->header_block_fragment = buf;
  frame->header_block_fragment_length = buf_length;

  return true;
}

bool h2_parse_settings_payload(const h2_frame_parser_t * const parser, uint8_t * buf,
    size_t buffer_length, size_t * num_settings,
                                      h2_setting_t * settings)
{
  *num_settings = buffer_length / SETTING_SIZE;

  if (*num_settings > 6) {
    log_append(parser->log, LOG_ERROR, "Up to 6 settings per frame supported: %ld", *num_settings);
    return false;
  }

  log_append(parser->log, LOG_TRACE, "Settings: Found %ld settings", *num_settings);

  for (size_t i = 0; i < *num_settings; i++) {
    h2_setting_t * curr = &settings[i];
    uint8_t * curr_setting = buf + (i * SETTING_SIZE);
    curr->id = get_bits16(curr_setting, 0xFFFF);
    curr->value = get_bits32(curr_setting + SETTING_ID_SIZE, 0xFFFFFFFF);
  }

  return true;
}

static bool h2_frame_parse_settings(const h2_frame_parser_t * const parser, uint8_t * buf,
    h2_frame_settings_t * const frame)
{
  if (!FRAME_FLAG(frame, FLAG_ACK)) {
    return h2_parse_settings_payload(parser, buf, frame->length, &frame->num_settings, frame->settings);
  } else {
    frame->num_settings = 0;
  }

  return true;
}

static bool h2_frame_parse_ping(const h2_frame_parser_t * const parser, uint8_t * buf,
    h2_frame_ping_t * const frame)
{
  UNUSED(parser);

  frame->opaque_data = buf;

  return true;
}

static bool h2_frame_parse_window_update(const h2_frame_parser_t * const parser, uint8_t * buf,
    h2_frame_window_update_t * const frame)
{
  UNUSED(parser);

  frame->increment = get_bits32(buf, 0x7FFFFFFF);

  return true;
}

static bool h2_frame_parse_rst_stream(const h2_frame_parser_t * const parser, uint8_t * buf,
    h2_frame_rst_stream_t * const frame)
{
  UNUSED(parser);

  frame->error_code = get_bits32(buf, 0xFFFFFFFF);

  return true;
}

static bool h2_frame_parse_priority(const h2_frame_parser_t * const parser, uint8_t * buf,
    h2_frame_priority_t * const frame)
{
  UNUSED(parser);

  frame->priority_exclusive = get_bit(buf, 0);
  frame->priority_stream_dependency = get_bits32(buf, 0x7FFFFFFF);
  // this is the transmitted value - we'll need to add 1 to get a value between 1 and 256
  frame->priority_weight = get_bits8(buf + 4, 0xFF);

  return true;
}

static bool h2_frame_parse_goaway(const h2_frame_parser_t * const parser, uint8_t * buf,
    h2_frame_goaway_t * const frame)
{
  UNUSED(parser);

  frame->last_stream_id = get_bits32(buf, 0x7FFFFFFF);
  frame->error_code = get_bits32(buf + 4, 0xFFFFFFFF);
  frame->debug_data_length = (frame->length - 8);

  frame->debug_data = malloc(frame->debug_data_length + 1);
  memcpy(frame->debug_data, buf + 8, frame->debug_data_length);
  frame->debug_data[frame->debug_data_length] = '\0';

  return true;
}

static bool h2_frame_is_valid_frame_type(enum frame_type_e frame_type)
{
  return frame_type >= FRAME_TYPE_MIN && frame_type <= FRAME_TYPE_MAX;
}

static bool h2_frame_is_valid(const h2_frame_parser_t * const parser, h2_frame_t * frame)
{
  UNUSED(parser);

  enum frame_type_e frame_type = frame->type;
  frame_parser_definition_t def = frame_parser_definitions[frame_type];

  if (frame->length < def.length_min) {
    parser->parse_error(parser->data, 0, H2_ERROR_FRAME_SIZE_ERROR,
        "Invalid frame length (below min) for frame type (0x%x): 0x%x, %d",
        frame->type, frame->length, frame->length);
    return false;
  }

  if (frame->length > def.length_max) {
    parser->parse_error(parser->data, 0, H2_ERROR_FRAME_SIZE_ERROR,
        "Invalid frame length (above max) for frame type (0x%x): 0x%x, %d",
        frame->type, frame->length, frame->length);
    return false;
  }

  size_t i;

  for (i = 0; i < 8; i++) {
    bool can_be_set = def.flags[i];

    if (!can_be_set) {
      uint8_t mask = 1 << i;

      if (frame->flags & mask) {
        parser->parse_error(parser->data, 0, H2_ERROR_PROTOCOL_ERROR,
            "Invalid flag set for frame type (0x%x): 0x%x", frame->type, frame->flags);
        return false;
      }
    }
  }

  if (frame->stream_id == 0 && def.must_have_stream_id) {
    parser->parse_error(parser->data, 0, H2_ERROR_PROTOCOL_ERROR,
        "Stream ID must be set for frame type: 0x%x", frame->type);
    return false;
  }

  if (frame->stream_id > 0 && def.must_not_have_stream_id) {
    parser->parse_error(parser->data, 0, H2_ERROR_PROTOCOL_ERROR,
        "Stream ID must not be set for frame type: 0x%x", frame->type);
    return false;
  }

  return true;
}


bool h2_frame_parse(const h2_frame_parser_t * const parser, uint8_t * const buffer,
    const size_t buffer_length, size_t * buffer_position)
{
  log_append(parser->log, LOG_TRACE, "Reading %ld bytes", buffer_length);

  if (*buffer_position == buffer_length) {
    log_append(parser->log, LOG_TRACE, "Finished with current buffer");

    return false;
  }

  // is there enough in the buffer to read a frame header?
  if (*buffer_position + FRAME_HEADER_SIZE > buffer_length) {
    // TODO off-by-one?
    log_append(parser->log, LOG_TRACE, "Not enough in buffer to read frame header");

    return false;
  }

  uint8_t * pos = buffer + *buffer_position;

  // Read the frame header
  // get first 3 bytes
  uint32_t frame_length = get_bits32(pos, 0xFFFFFF00) >> 8;

  // is there enough in the buffer to read the frame payload?
  if (*buffer_position + FRAME_HEADER_SIZE + frame_length <= buffer_length) {

    uint8_t frame_type = pos[3];
    uint8_t frame_flags = pos[4];
    // get 31 bits
    uint32_t stream_id = get_bits32(pos + 5, 0x7FFFFFFF);

    // is this a valid frame type?
    if (!h2_frame_is_valid_frame_type(frame_type)) {
      // invalid frame type is always a connection error
      parser->parse_error(parser->data, 0, H2_ERROR_PROTOCOL_ERROR,
          "Invalid frame type: %d", frame_type);
      return false;
    }

    // TODO - if the previous frame type was headers, and headers haven't been completed,
    // this frame must be a continuation frame, or else this is a protocol error

    h2_frame_t * frame = h2_frame_init(parser, frame_length, frame_type, frame_flags, stream_id);

    if (frame == NULL) {
      parser->parse_error(parser->data, 0, H2_ERROR_PROTOCOL_ERROR,
          "Unhandled frame type: %d", frame_type);
      return false;
    } else if (!h2_frame_is_valid(parser, frame)) {
      return false;
    }

    *buffer_position += FRAME_HEADER_SIZE;

    plugin_invoke(parser->plugin_invoker, INCOMING_FRAME, frame, *buffer_position);

    bool success = false;

    /**
     * The h2_frame_parse_xxx functions should return true if the next frame should be allowed to
     * continue to be processed. Connection errors usually prevent the rest of the frames from
     * being processed.
     */
    switch (frame->type) {
      case FRAME_TYPE_DATA:
        success = h2_frame_parse_data(parser, buffer + *buffer_position,
            (h2_frame_data_t *) frame);
        break;

      case FRAME_TYPE_HEADERS:
        success = h2_frame_parse_headers(parser, buffer + *buffer_position,
            (h2_frame_headers_t *) frame);
        break;

      case FRAME_TYPE_PRIORITY:
        success = h2_frame_parse_priority(parser, buffer + *buffer_position,
            (h2_frame_priority_t *) frame);
        break;

      case FRAME_TYPE_RST_STREAM:
        success = h2_frame_parse_rst_stream(parser, buffer + *buffer_position,
              (h2_frame_rst_stream_t *) frame);
        break;

      case FRAME_TYPE_SETTINGS:
        success = h2_frame_parse_settings(parser, buffer + *buffer_position,
            (h2_frame_settings_t *) frame);
        break;

      case FRAME_TYPE_PUSH_PROMISE:
        log_append(parser->log, LOG_ERROR, "Server should not receive push promise frame");
        success = false;

      case FRAME_TYPE_PING:
        success = h2_frame_parse_ping(parser, buffer + *buffer_position,
            (h2_frame_ping_t *) frame);
        break;

      case FRAME_TYPE_GOAWAY:
        success = h2_frame_parse_goaway(parser, buffer + *buffer_position,
            (h2_frame_goaway_t *) frame);
        break;

      case FRAME_TYPE_WINDOW_UPDATE:
        success = h2_frame_parse_window_update(parser, buffer + *buffer_position,
            (h2_frame_window_update_t *) frame);
        break;

      case FRAME_TYPE_CONTINUATION:
        success = h2_frame_parse_continuation(parser, buffer + *buffer_position,
          (h2_frame_continuation_t *) frame);
        break;

      default:
        success = false;
    }

    if (success) {
      success = success && parser->incoming_frame(parser->data, frame);
    }

    *buffer_position += frame->length;
    free(frame);
    return success;
  } else {
    log_append(parser->log, LOG_TRACE, "Not enough in buffer to read %ld byte frame payload", frame_length);
    return false;
  }

}
