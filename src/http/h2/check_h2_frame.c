#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <check.h>
#include <limits.h>
#include <inttypes.h>

#include "plugin.c"
#include "h2_error.c"
#include "h2_frame.c"

#include "h2.h"

#define OUT(index) binary_buffer_read_index(&bb, (index))

typedef struct {
  uint32_t stream_id;
  enum h2_error_code_e error_code;
  char * error_string;
} caught_error_t;

binary_buffer_t bb;
h2_frame_parser_t parser;
plugin_invoker_t invoker;

bool should_continue_parsing = true;
size_t num_frames_parsed = 0;
h2_frame_t * last_frames[8];

bool num_errors = 0;
caught_error_t * caught_errors[8];

static bool parse_error_cb(void * data, uint32_t stream_id, enum h2_error_code_e error_code,
    char * format, ...)
{
  UNUSED(data);

  caught_error_t * ce = malloc(sizeof(caught_error_t));
  ce->stream_id = stream_id;
  ce->error_code = error_code;
  const size_t error_string_length = 1024;

  va_list args;

  char buf[error_string_length];
  va_start(args, format);
  vsnprintf(buf, error_string_length, format, args);
  va_end(args);
  ce->error_string = strdup(buf);

  fprintf(stdout, "Parser error: stream id: %" PRIu32 ", error code: %s (0x%x), error_string: %s\n",
      stream_id, h2_error_to_string(error_code), error_code, buf);

  caught_errors[num_errors++] = ce;

  return true;
}

static bool incoming_frame_cb(void * data, const h2_frame_t * const frame)
{
  UNUSED(data);
  printf("Got frame: %" PRIu16 "\n", frame->length);

  last_frames[num_frames_parsed++] = (h2_frame_t *) frame;

  return true;
}

void setup()
{
  invoker.plugins = NULL;
  invoker.client = NULL;

  parser.log = NULL;
  parser.data = NULL;
  parser.plugin_invoker = (struct plugin_invoker_t *) &invoker;
  parser.parse_error = parse_error_cb;
  parser.incoming_frame = incoming_frame_cb;

  binary_buffer_init(&bb, 0);

  should_continue_parsing = true;
  num_frames_parsed = 0;
  for (size_t i = 0; i < 8; i++) {
    last_frames[i] = NULL;
  }

  num_errors = 0;
  for (size_t i = 0; i < 8; i++) {
    caught_errors[i] = NULL;
  }
}

void teardown()
{
  binary_buffer_free(&bb);

  for (size_t i = 0; i < num_frames_parsed; i++) {
    free(last_frames[i]);
  }
  for (size_t i = 0; i < num_errors; i++) {
    free(caught_errors[i]);
  }
}

START_TEST(test_h2_frame_emit_ping_ack)
{
  h2_frame_ping_t * frame = (h2_frame_ping_t *) h2_frame_init(&parser, FRAME_TYPE_PING, FLAG_ACK, 0);
  ck_assert_uint_eq(frame->stream_id, 0);
  ck_assert_uint_eq(frame->type, FRAME_TYPE_PING);
  ck_assert_uint_eq(frame->flags, FLAG_ACK);
  ck_assert_uint_eq(frame->length, 0);

  uint8_t d[] = {
    0xde, 0xad, 0xbe, 0xef,
    0xde, 0xad, 0xbe, 0xef
  };
  frame->opaque_data = d;

  h2_frame_emit(&parser, &bb, (h2_frame_t *) frame);

  ck_assert_uint_eq(binary_buffer_size(&bb), 17);
  ck_assert_uint_eq(OUT(0), 0);
  ck_assert_uint_eq(OUT(1), 0);
  ck_assert_uint_eq(OUT(2), 8);
  ck_assert_uint_eq(OUT(3), FRAME_TYPE_PING);
  ck_assert_uint_eq(OUT(4), FLAG_ACK);
  ck_assert_uint_eq(OUT(5), 0);
  ck_assert_uint_eq(OUT(6), 0);
  ck_assert_uint_eq(OUT(7), 0);
  ck_assert_uint_eq(OUT(8), 0);
  ck_assert_uint_eq(OUT(9), 0xde);
  ck_assert_uint_eq(OUT(10), 0xad);
  ck_assert_uint_eq(OUT(11), 0xbe);
  ck_assert_uint_eq(OUT(12), 0xef);
  ck_assert_uint_eq(OUT(13), 0xde);
  ck_assert_uint_eq(OUT(14), 0xad);
  ck_assert_uint_eq(OUT(15), 0xbe);
  ck_assert_uint_eq(OUT(16), 0xef);
}
END_TEST

START_TEST(test_h2_frame_emit_data_empty)
{
  h2_frame_data_t * frame = (h2_frame_data_t *) h2_frame_init(&parser, FRAME_TYPE_DATA, FLAG_END_STREAM, 1);
  ck_assert_uint_eq(frame->stream_id, 1);
  ck_assert_uint_eq(frame->type, FRAME_TYPE_DATA);
  ck_assert_uint_eq(frame->flags, FLAG_END_STREAM);
  ck_assert_uint_eq(frame->length, 0);

  frame->payload = NULL;
  frame->payload_length = 0;

  h2_frame_emit(&parser, &bb, (h2_frame_t *) frame);

  ck_assert_uint_eq(binary_buffer_size(&bb), 9);
  ck_assert_uint_eq(OUT(0), 0);
  ck_assert_uint_eq(OUT(1), 0);
  ck_assert_uint_eq(OUT(2), 0);
  ck_assert_uint_eq(OUT(3), FRAME_TYPE_DATA);
  ck_assert_uint_eq(OUT(4), FLAG_END_STREAM);
  ck_assert_uint_eq(OUT(5), 0);
  ck_assert_uint_eq(OUT(6), 0);
  ck_assert_uint_eq(OUT(7), 0);
  ck_assert_uint_eq(OUT(8), 1);
}
END_TEST

START_TEST(test_h2_frame_emit_data_with_payload)
{
  h2_frame_data_t * frame = (h2_frame_data_t *) h2_frame_init(&parser, FRAME_TYPE_DATA, FLAG_END_STREAM, 1);
  ck_assert_uint_eq(frame->type, FRAME_TYPE_DATA);
  ck_assert_uint_eq(frame->flags, FLAG_END_STREAM);
  ck_assert_uint_eq(frame->length, 0);

  uint8_t d[] = {
    0xde, 0xad, 0xbe, 0xef
  };
  frame->payload = d;
  frame->payload_length = 4;

  h2_frame_emit(&parser, &bb, (h2_frame_t *) frame);

  ck_assert_uint_eq(binary_buffer_size(&bb), 13);
  ck_assert_uint_eq(OUT(0), 0);
  ck_assert_uint_eq(OUT(1), 0);
  ck_assert_uint_eq(OUT(2), 4);
  ck_assert_uint_eq(OUT(3), FRAME_TYPE_DATA);
  ck_assert_uint_eq(OUT(4), FLAG_END_STREAM);
  ck_assert_uint_eq(OUT(5), 0);
  ck_assert_uint_eq(OUT(6), 0);
  ck_assert_uint_eq(OUT(7), 0);
  ck_assert_uint_eq(OUT(8), 1);
  ck_assert_uint_eq(OUT(9), 0xde);
  ck_assert_uint_eq(OUT(10), 0xad);
  ck_assert_uint_eq(OUT(11), 0xbe);
  ck_assert_uint_eq(OUT(12), 0xef);
}
END_TEST

START_TEST(test_h2_frame_emit_data_with_large_payload)
{
  uint8_t * d = malloc(DEFAULT_MAX_FRAME_SIZE);
  memset(d, 0, DEFAULT_MAX_FRAME_SIZE);
  h2_frame_data_t * frame = (h2_frame_data_t *) h2_frame_init(&parser, FRAME_TYPE_DATA, FLAG_END_STREAM, 1);
  frame->payload = d;
  frame->payload_length = DEFAULT_MAX_FRAME_SIZE;
  ck_assert_uint_eq(frame->type, FRAME_TYPE_DATA);
  ck_assert_uint_eq(frame->flags, FLAG_END_STREAM);
  ck_assert_uint_eq(frame->length, 0);

  h2_frame_emit(&parser, &bb, (h2_frame_t *) frame);

  ck_assert_uint_eq(binary_buffer_size(&bb), DEFAULT_MAX_FRAME_SIZE + FRAME_HEADER_SIZE);
  ck_assert_uint_eq(OUT(0), 0);
  ck_assert_uint_eq(OUT(1), 0x40);
  ck_assert_uint_eq(OUT(2), 0x00);
  ck_assert_uint_eq(OUT(3), FRAME_TYPE_DATA);
  ck_assert_uint_eq(OUT(4), FLAG_END_STREAM);
  ck_assert_uint_eq(OUT(5), 0);
  ck_assert_uint_eq(OUT(6), 0);
  ck_assert_uint_eq(OUT(7), 0);
  ck_assert_uint_eq(OUT(8), 1);
  for (size_t i = 0; i < DEFAULT_MAX_FRAME_SIZE; i++) {
    ck_assert_uint_eq(OUT(9 + i), 0);
  }
}
END_TEST

START_TEST(test_h2_frame_emit_data_twice)
{
  uint8_t * d1 = malloc(DEFAULT_MAX_FRAME_SIZE);
  memset(d1, 0, DEFAULT_MAX_FRAME_SIZE);
  h2_frame_data_t * frame = (h2_frame_data_t *) h2_frame_init(&parser, FRAME_TYPE_DATA, 0, 1);
  frame->payload = d1;
  frame->payload_length = DEFAULT_MAX_FRAME_SIZE;
  ck_assert_uint_eq(frame->type, FRAME_TYPE_DATA);
  ck_assert_uint_eq(frame->flags, 0);
  ck_assert_uint_eq(frame->length, 0);

  h2_frame_data_t * frame2 = (h2_frame_data_t *) h2_frame_init(&parser, FRAME_TYPE_DATA, FLAG_END_STREAM, 1);
  uint8_t d2[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
  frame2->payload = d2;
  frame2->payload_length = 10;
  ck_assert_uint_eq(frame2->type, FRAME_TYPE_DATA);
  ck_assert_uint_eq(frame2->flags, FLAG_END_STREAM);
  ck_assert_uint_eq(frame2->length, 0);

  h2_frame_emit(&parser, &bb, (h2_frame_t *) frame);
  ck_assert_uint_eq(binary_buffer_size(&bb), DEFAULT_MAX_FRAME_SIZE + FRAME_HEADER_SIZE);

  h2_frame_emit(&parser, &bb, (h2_frame_t *) frame2);
  ck_assert_uint_eq(binary_buffer_size(&bb), DEFAULT_MAX_FRAME_SIZE + FRAME_HEADER_SIZE + 10 + FRAME_HEADER_SIZE);
  ck_assert_uint_eq(OUT(0), 0);
  ck_assert_uint_eq(OUT(1), 0x40);
  ck_assert_uint_eq(OUT(2), 0x00);
  ck_assert_uint_eq(OUT(3), FRAME_TYPE_DATA);
  ck_assert_uint_eq(OUT(4), 0);
  ck_assert_uint_eq(OUT(5), 0);
  ck_assert_uint_eq(OUT(6), 0);
  ck_assert_uint_eq(OUT(7), 0);
  ck_assert_uint_eq(OUT(8), 1);
  for (size_t i = 0; i < DEFAULT_MAX_FRAME_SIZE; i++) {
    ck_assert_uint_eq(OUT(9 + i), 0);
  }
  size_t frame2_offset = FRAME_HEADER_SIZE + DEFAULT_MAX_FRAME_SIZE;
  ck_assert_uint_eq(OUT(frame2_offset + 0), 0);
  ck_assert_uint_eq(OUT(frame2_offset + 1), 0);
  ck_assert_uint_eq(OUT(frame2_offset + 2), 0xa);
  ck_assert_uint_eq(OUT(frame2_offset + 3), FRAME_TYPE_DATA);
  ck_assert_uint_eq(OUT(frame2_offset + 4), FLAG_END_STREAM);
  ck_assert_uint_eq(OUT(frame2_offset + 5), 0);
  ck_assert_uint_eq(OUT(frame2_offset + 6), 0);
  ck_assert_uint_eq(OUT(frame2_offset + 7), 0);
  ck_assert_uint_eq(OUT(frame2_offset + 8), 1);
  ck_assert_uint_eq(OUT(frame2_offset + 9), 1);
  ck_assert_uint_eq(OUT(frame2_offset + 10), 2);
  ck_assert_uint_eq(OUT(frame2_offset + 11), 3);
  ck_assert_uint_eq(OUT(frame2_offset + 12), 4);
  ck_assert_uint_eq(OUT(frame2_offset + 13), 5);
  ck_assert_uint_eq(OUT(frame2_offset + 14), 6);
  ck_assert_uint_eq(OUT(frame2_offset + 15), 7);
  ck_assert_uint_eq(OUT(frame2_offset + 16), 8);
  ck_assert_uint_eq(OUT(frame2_offset + 17), 9);
  ck_assert_uint_eq(OUT(frame2_offset + 18), 10);
}
END_TEST

START_TEST(test_h2_frame_emit_headers_empty)
{
  h2_frame_headers_t * frame = (h2_frame_headers_t *) h2_frame_init(&parser, FRAME_TYPE_HEADERS, FLAG_END_HEADERS, 1);
  ck_assert_uint_eq(frame->stream_id, 1);
  ck_assert_uint_eq(frame->type, FRAME_TYPE_HEADERS);
  ck_assert_uint_eq(frame->flags, FLAG_END_HEADERS);
  ck_assert_uint_eq(frame->length, 0);

  frame->header_block_fragment = NULL;
  frame->header_block_fragment_length = 0;

  h2_frame_emit(&parser, &bb, (h2_frame_t *) frame);

  ck_assert_uint_eq(binary_buffer_size(&bb), 9);
  ck_assert_uint_eq(OUT(0), 0);
  ck_assert_uint_eq(OUT(1), 0);
  ck_assert_uint_eq(OUT(2), 0);
  ck_assert_uint_eq(OUT(3), FRAME_TYPE_HEADERS);
  ck_assert_uint_eq(OUT(4), FLAG_END_HEADERS);
  ck_assert_uint_eq(OUT(5), 0);
  ck_assert_uint_eq(OUT(6), 0);
  ck_assert_uint_eq(OUT(7), 0);
  ck_assert_uint_eq(OUT(8), 1);
}
END_TEST

START_TEST(test_h2_frame_emit_headers_end_stream)
{
  h2_frame_headers_t * frame = (h2_frame_headers_t *) h2_frame_init(&parser, FRAME_TYPE_HEADERS, FLAG_END_STREAM | FLAG_END_HEADERS, 1);
  ck_assert_uint_eq(frame->stream_id, 1);
  ck_assert_uint_eq(frame->type, FRAME_TYPE_HEADERS);
  ck_assert_uint_eq(frame->flags, FLAG_END_HEADERS | FLAG_END_STREAM);
  ck_assert_uint_eq(frame->length, 0);

  frame->header_block_fragment = NULL;
  frame->header_block_fragment_length = 0;

  h2_frame_emit(&parser, &bb, (h2_frame_t *) frame);

  ck_assert_uint_eq(binary_buffer_size(&bb), 9);
  ck_assert_uint_eq(OUT(0), 0);
  ck_assert_uint_eq(OUT(1), 0);
  ck_assert_uint_eq(OUT(2), 0);
  ck_assert_uint_eq(OUT(3), FRAME_TYPE_HEADERS);
  ck_assert_uint_eq(OUT(4), FLAG_END_HEADERS | FLAG_END_STREAM);
  ck_assert_uint_eq(OUT(5), 0);
  ck_assert_uint_eq(OUT(6), 0);
  ck_assert_uint_eq(OUT(7), 0);
  ck_assert_uint_eq(OUT(8), 1);
}
END_TEST

START_TEST(test_h2_frame_emit_headers_with_payload)
{
  h2_frame_headers_t * frame = (h2_frame_headers_t *) h2_frame_init(&parser, FRAME_TYPE_HEADERS, FLAG_END_HEADERS, 1);
  ck_assert_uint_eq(frame->stream_id, 1);
  ck_assert_uint_eq(frame->type, FRAME_TYPE_HEADERS);
  ck_assert_uint_eq(frame->flags, FLAG_END_HEADERS);
  ck_assert_uint_eq(frame->length, 0);

  uint8_t d[] = {
    0xde, 0xad, 0xbe, 0xef
  };
  frame->header_block_fragment = d;
  frame->header_block_fragment_length = 4;

  h2_frame_emit(&parser, &bb, (h2_frame_t *) frame);

  ck_assert_uint_eq(binary_buffer_size(&bb), 13);
  ck_assert_uint_eq(OUT(0), 0);
  ck_assert_uint_eq(OUT(1), 0);
  ck_assert_uint_eq(OUT(2), 4);
  ck_assert_uint_eq(OUT(3), FRAME_TYPE_HEADERS);
  ck_assert_uint_eq(OUT(4), FLAG_END_HEADERS);
  ck_assert_uint_eq(OUT(5), 0);
  ck_assert_uint_eq(OUT(6), 0);
  ck_assert_uint_eq(OUT(7), 0);
  ck_assert_uint_eq(OUT(8), 1);
  ck_assert_uint_eq(OUT(9), 0xde);
  ck_assert_uint_eq(OUT(10), 0xad);
  ck_assert_uint_eq(OUT(11), 0xbe);
  ck_assert_uint_eq(OUT(12), 0xef);
}
END_TEST

START_TEST(test_h2_frame_emit_rst_stream)
{
  h2_frame_rst_stream_t * frame = (h2_frame_rst_stream_t *) h2_frame_init(&parser, FRAME_TYPE_RST_STREAM, 0, 1);
  ck_assert_uint_eq(frame->stream_id, 1);
  ck_assert_uint_eq(frame->type, FRAME_TYPE_RST_STREAM);
  ck_assert_uint_eq(frame->flags, 0);
  ck_assert_uint_eq(frame->length, 0);

  frame->error_code = H2_ERROR_INTERNAL_ERROR;

  h2_frame_emit(&parser, &bb, (h2_frame_t *) frame);

  ck_assert_uint_eq(binary_buffer_size(&bb), 13);
  ck_assert_uint_eq(OUT(0), 0);
  ck_assert_uint_eq(OUT(1), 0);
  ck_assert_uint_eq(OUT(2), 4);
  ck_assert_uint_eq(OUT(3), FRAME_TYPE_RST_STREAM);
  ck_assert_uint_eq(OUT(4), 0);
  ck_assert_uint_eq(OUT(5), 0);
  ck_assert_uint_eq(OUT(6), 0);
  ck_assert_uint_eq(OUT(7), 0);
  ck_assert_uint_eq(OUT(8), 1);
  ck_assert_uint_eq(OUT(9), 0);
  ck_assert_uint_eq(OUT(10), 0);
  ck_assert_uint_eq(OUT(11), 0);
  ck_assert_uint_eq(OUT(12), 2); //H2_ERROR_INTERNAL_ERROR
}
END_TEST

START_TEST(test_h2_frame_emit_settings_ack)
{
  h2_frame_settings_t * frame = (h2_frame_settings_t *) h2_frame_init(&parser, FRAME_TYPE_SETTINGS, FLAG_ACK, 0);
  ck_assert_uint_eq(frame->stream_id, 0);
  ck_assert_uint_eq(frame->type, FRAME_TYPE_SETTINGS);
  ck_assert_uint_eq(frame->flags, FLAG_ACK);
  ck_assert_uint_eq(frame->length, 0);

  h2_frame_emit(&parser, &bb, (h2_frame_t *) frame);

  ck_assert_uint_eq(binary_buffer_size(&bb), 9);
  ck_assert_uint_eq(OUT(0), 0);
  ck_assert_uint_eq(OUT(1), 0);
  ck_assert_uint_eq(OUT(2), 0);
  ck_assert_uint_eq(OUT(3), FRAME_TYPE_SETTINGS);
  ck_assert_uint_eq(OUT(4), FLAG_ACK);
  ck_assert_uint_eq(OUT(5), 0);
  ck_assert_uint_eq(OUT(6), 0);
  ck_assert_uint_eq(OUT(7), 0);
  ck_assert_uint_eq(OUT(8), 0);
}
END_TEST

START_TEST(test_h2_frame_emit_push_promise_empty)
{
  h2_frame_push_promise_t * frame = (h2_frame_push_promise_t *) h2_frame_init(&parser, FRAME_TYPE_PUSH_PROMISE, FLAG_END_HEADERS, 1);
  ck_assert_uint_eq(frame->stream_id, 1);
  ck_assert_uint_eq(frame->type, FRAME_TYPE_PUSH_PROMISE);
  ck_assert_uint_eq(frame->flags, FLAG_END_HEADERS);
  ck_assert_uint_eq(frame->length, 0);

  frame->promised_stream_id = 2;
  frame->header_block_fragment = NULL;
  frame->header_block_fragment_length = 0;

  h2_frame_emit(&parser, &bb, (h2_frame_t *) frame);

  ck_assert_uint_eq(binary_buffer_size(&bb), 13);
  ck_assert_uint_eq(OUT(0), 0);
  ck_assert_uint_eq(OUT(1), 0);
  ck_assert_uint_eq(OUT(2), 4);
  ck_assert_uint_eq(OUT(3), FRAME_TYPE_PUSH_PROMISE);
  ck_assert_uint_eq(OUT(4), FLAG_END_HEADERS);
  ck_assert_uint_eq(OUT(5), 0);
  ck_assert_uint_eq(OUT(6), 0);
  ck_assert_uint_eq(OUT(7), 0);
  ck_assert_uint_eq(OUT(8), 1);
  ck_assert_uint_eq(OUT(9), 0);
  ck_assert_uint_eq(OUT(10), 0);
  ck_assert_uint_eq(OUT(11), 0);
  ck_assert_uint_eq(OUT(12), 2);
}
END_TEST

START_TEST(test_h2_frame_emit_push_promise_end_stream)
{
  h2_frame_push_promise_t * frame = (h2_frame_push_promise_t *) h2_frame_init(&parser, FRAME_TYPE_PUSH_PROMISE, FLAG_END_STREAM | FLAG_END_HEADERS, 1);
  ck_assert_uint_eq(frame->stream_id, 1);
  ck_assert_uint_eq(frame->type, FRAME_TYPE_PUSH_PROMISE);
  ck_assert_uint_eq(frame->flags, FLAG_END_HEADERS | FLAG_END_STREAM);
  ck_assert_uint_eq(frame->length, 0);

  frame->promised_stream_id = 2;
  frame->header_block_fragment = NULL;
  frame->header_block_fragment_length = 0;

  h2_frame_emit(&parser, &bb, (h2_frame_t *) frame);

  ck_assert_uint_eq(binary_buffer_size(&bb), 13);
  ck_assert_uint_eq(OUT(0), 0);
  ck_assert_uint_eq(OUT(1), 0);
  ck_assert_uint_eq(OUT(2), 4);
  ck_assert_uint_eq(OUT(3), FRAME_TYPE_PUSH_PROMISE);
  ck_assert_uint_eq(OUT(4), FLAG_END_HEADERS | FLAG_END_STREAM);
  ck_assert_uint_eq(OUT(5), 0);
  ck_assert_uint_eq(OUT(6), 0);
  ck_assert_uint_eq(OUT(7), 0);
  ck_assert_uint_eq(OUT(8), 1);
  ck_assert_uint_eq(OUT(9), 0);
  ck_assert_uint_eq(OUT(10), 0);
  ck_assert_uint_eq(OUT(11), 0);
  ck_assert_uint_eq(OUT(12), 2);
}
END_TEST

START_TEST(test_h2_frame_emit_push_promise_with_payload)
{
  h2_frame_push_promise_t * frame = (h2_frame_push_promise_t *) h2_frame_init(&parser, FRAME_TYPE_PUSH_PROMISE, FLAG_END_HEADERS, 1);
  ck_assert_uint_eq(frame->stream_id, 1);
  ck_assert_uint_eq(frame->type, FRAME_TYPE_PUSH_PROMISE);
  ck_assert_uint_eq(frame->flags, FLAG_END_HEADERS);
  ck_assert_uint_eq(frame->length, 0);

  frame->promised_stream_id = 2;
  uint8_t d[] = {
    0xde, 0xad, 0xbe, 0xef
  };
  frame->header_block_fragment = d;
  frame->header_block_fragment_length = 4;

  h2_frame_emit(&parser, &bb, (h2_frame_t *) frame);

  ck_assert_uint_eq(binary_buffer_size(&bb), 17);
  ck_assert_uint_eq(OUT(0), 0);
  ck_assert_uint_eq(OUT(1), 0);
  ck_assert_uint_eq(OUT(2), 8);
  ck_assert_uint_eq(OUT(3), FRAME_TYPE_PUSH_PROMISE);
  ck_assert_uint_eq(OUT(4), FLAG_END_HEADERS);
  ck_assert_uint_eq(OUT(5), 0);
  ck_assert_uint_eq(OUT(6), 0);
  ck_assert_uint_eq(OUT(7), 0);
  ck_assert_uint_eq(OUT(8), 1);
  ck_assert_uint_eq(OUT(9), 0);
  ck_assert_uint_eq(OUT(10), 0);
  ck_assert_uint_eq(OUT(11), 0);
  ck_assert_uint_eq(OUT(12), 2);
  ck_assert_uint_eq(OUT(13), 0xde);
  ck_assert_uint_eq(OUT(14), 0xad);
  ck_assert_uint_eq(OUT(15), 0xbe);
  ck_assert_uint_eq(OUT(16), 0xef);
}
END_TEST

START_TEST(test_h2_frame_emit_goaway)
{
  h2_frame_goaway_t * frame = (h2_frame_goaway_t *) h2_frame_init(&parser, FRAME_TYPE_GOAWAY, 0, 0);
  ck_assert_uint_eq(frame->stream_id, 0);
  ck_assert_uint_eq(frame->type, FRAME_TYPE_GOAWAY);
  ck_assert_uint_eq(frame->flags, 0);
  ck_assert_uint_eq(frame->length, 0);

  frame->last_stream_id = 0;
  frame->error_code = H2_ERROR_NO_ERROR;
  frame->debug_data = NULL;
  frame->debug_data_length = 0;

  h2_frame_emit(&parser, &bb, (h2_frame_t *) frame);

  ck_assert_uint_eq(binary_buffer_size(&bb), 17);
  ck_assert_uint_eq(OUT(0), 0);
  ck_assert_uint_eq(OUT(1), 0);
  ck_assert_uint_eq(OUT(2), 8);
  ck_assert_uint_eq(OUT(3), FRAME_TYPE_GOAWAY);
  ck_assert_uint_eq(OUT(4), 0);
  ck_assert_uint_eq(OUT(5), 0);
  ck_assert_uint_eq(OUT(6), 0);
  ck_assert_uint_eq(OUT(7), 0);
  ck_assert_uint_eq(OUT(8), 0);
  ck_assert_uint_eq(OUT(9), 0);
  ck_assert_uint_eq(OUT(10), 0);
  ck_assert_uint_eq(OUT(11), 0);
  ck_assert_uint_eq(OUT(12), 0); // last stream id
  ck_assert_uint_eq(OUT(13), 0);
  ck_assert_uint_eq(OUT(14), 0);
  ck_assert_uint_eq(OUT(15), 0);
  ck_assert_uint_eq(OUT(16), 0); //H2_ERROR_NO_ERROR
}
END_TEST

START_TEST(test_h2_frame_emit_goaway_with_debug_data)
{
  h2_frame_goaway_t * frame = (h2_frame_goaway_t *) h2_frame_init(&parser, FRAME_TYPE_GOAWAY, 0, 0);
  ck_assert_uint_eq(frame->stream_id, 0);
  ck_assert_uint_eq(frame->type, FRAME_TYPE_GOAWAY);
  ck_assert_uint_eq(frame->flags, 0);
  ck_assert_uint_eq(frame->length, 0);

  frame->last_stream_id = 1;
  frame->error_code = H2_ERROR_INTERNAL_ERROR;
  char * debug_data = "Well, we've screwed the pooch";
  frame->debug_data = (uint8_t *) debug_data;
  frame->debug_data_length = strlen(debug_data);

  h2_frame_emit(&parser, &bb, (h2_frame_t *) frame);

  ck_assert_uint_eq(binary_buffer_size(&bb), 17 + frame->debug_data_length);
  ck_assert_uint_eq(OUT(0), 0);
  ck_assert_uint_eq(OUT(1), 0);
  ck_assert_uint_eq(OUT(2), 8 + frame->debug_data_length);
  ck_assert_uint_eq(OUT(3), FRAME_TYPE_GOAWAY);
  ck_assert_uint_eq(OUT(4), 0);
  ck_assert_uint_eq(OUT(5), 0);
  ck_assert_uint_eq(OUT(6), 0);
  ck_assert_uint_eq(OUT(7), 0);
  ck_assert_uint_eq(OUT(8), 0);
  ck_assert_uint_eq(OUT(9), 0);
  ck_assert_uint_eq(OUT(10), 0);
  ck_assert_uint_eq(OUT(11), 0);
  ck_assert_uint_eq(OUT(12), 1); // last stream id
  ck_assert_uint_eq(OUT(13), 0);
  ck_assert_uint_eq(OUT(14), 0);
  ck_assert_uint_eq(OUT(15), 0);
  ck_assert_uint_eq(OUT(16), 2); // H2_ERROR_INTERNAL_ERROR
}
END_TEST

START_TEST(test_h2_frame_emit_window_update_for_connection)
{
  h2_frame_window_update_t * frame = (h2_frame_window_update_t *) h2_frame_init(&parser, FRAME_TYPE_WINDOW_UPDATE, 0, 0);
  ck_assert_uint_eq(frame->stream_id, 0);
  ck_assert_uint_eq(frame->type, FRAME_TYPE_WINDOW_UPDATE);
  ck_assert_uint_eq(frame->flags, 0);
  ck_assert_uint_eq(frame->length, 0);

  frame->increment = 0x4000;

  h2_frame_emit(&parser, &bb, (h2_frame_t *) frame);

  ck_assert_uint_eq(binary_buffer_size(&bb), 13);
  ck_assert_uint_eq(OUT(0), 0);
  ck_assert_uint_eq(OUT(1), 0);
  ck_assert_uint_eq(OUT(2), 4);
  ck_assert_uint_eq(OUT(3), FRAME_TYPE_WINDOW_UPDATE);
  ck_assert_uint_eq(OUT(4), 0);
  ck_assert_uint_eq(OUT(5), 0);
  ck_assert_uint_eq(OUT(6), 0);
  ck_assert_uint_eq(OUT(7), 0);
  ck_assert_uint_eq(OUT(8), 0);
  ck_assert_uint_eq(OUT(9), 0);
  ck_assert_uint_eq(OUT(10), 0);
  ck_assert_uint_eq(OUT(11), 0x40);
  ck_assert_uint_eq(OUT(12), 0);
}
END_TEST

START_TEST(test_h2_frame_emit_window_update_for_stream)
{
  h2_frame_window_update_t * frame = (h2_frame_window_update_t *) h2_frame_init(&parser, FRAME_TYPE_WINDOW_UPDATE, 0, 1);
  ck_assert_uint_eq(frame->stream_id, 1);
  ck_assert_uint_eq(frame->type, FRAME_TYPE_WINDOW_UPDATE);
  ck_assert_uint_eq(frame->flags, 0);
  ck_assert_uint_eq(frame->length, 0);

  frame->increment = 0x4000;

  h2_frame_emit(&parser, &bb, (h2_frame_t *) frame);

  ck_assert_uint_eq(binary_buffer_size(&bb), 13);
  ck_assert_uint_eq(OUT(0), 0);
  ck_assert_uint_eq(OUT(1), 0);
  ck_assert_uint_eq(OUT(2), 4);
  ck_assert_uint_eq(OUT(3), FRAME_TYPE_WINDOW_UPDATE);
  ck_assert_uint_eq(OUT(4), 0);
  ck_assert_uint_eq(OUT(5), 0);
  ck_assert_uint_eq(OUT(6), 0);
  ck_assert_uint_eq(OUT(7), 0);
  ck_assert_uint_eq(OUT(8), 1);
  ck_assert_uint_eq(OUT(9), 0);
  ck_assert_uint_eq(OUT(10), 0);
  ck_assert_uint_eq(OUT(11), 0x40);
  ck_assert_uint_eq(OUT(12), 0);
}
END_TEST

START_TEST(test_h2_frame_emit_continuation)
{
  h2_frame_continuation_t * frame = (h2_frame_continuation_t *) h2_frame_init(&parser, FRAME_TYPE_CONTINUATION, FLAG_END_HEADERS, 1);
  ck_assert_uint_eq(frame->stream_id, 1);
  ck_assert_uint_eq(frame->type, FRAME_TYPE_CONTINUATION);
  ck_assert_uint_eq(frame->flags, FLAG_END_HEADERS);
  ck_assert_uint_eq(frame->length, 0);

  uint8_t d[] = {
    0xde, 0xad, 0xbe, 0xef
  };
  frame->header_block_fragment = d;
  frame->header_block_fragment_length = 4;

  h2_frame_emit(&parser, &bb, (h2_frame_t *) frame);

  ck_assert_uint_eq(binary_buffer_size(&bb), 13);
  ck_assert_uint_eq(OUT(0), 0);
  ck_assert_uint_eq(OUT(1), 0);
  ck_assert_uint_eq(OUT(2), 4);
  ck_assert_uint_eq(OUT(3), FRAME_TYPE_CONTINUATION);
  ck_assert_uint_eq(OUT(4), FLAG_END_HEADERS);
  ck_assert_uint_eq(OUT(5), 0);
  ck_assert_uint_eq(OUT(6), 0);
  ck_assert_uint_eq(OUT(7), 0);
  ck_assert_uint_eq(OUT(8), 1);
  ck_assert_uint_eq(OUT(9), 0xde);
  ck_assert_uint_eq(OUT(10), 0xad);
  ck_assert_uint_eq(OUT(11), 0xbe);
  ck_assert_uint_eq(OUT(12), 0xef);
}
END_TEST

START_TEST(test_h2_frame_parse_invalid_frame_type)
{
  uint8_t buffer[] = {
    0x0, 0x0, 0x0, 0xff, 0x0, 0x0, 0x0, 0x0, 0x0
  };
  size_t buffer_position = 0;
  size_t buffer_length = sizeof(buffer) / sizeof(uint8_t);

  h2_frame_t * ret = h2_frame_parse(&parser, buffer, buffer_length, &buffer_position);
  ck_assert(ret == NULL);

  ck_assert_uint_eq(buffer_position, 0);
  ck_assert_uint_eq(num_frames_parsed, 0);

  ck_assert_uint_eq(num_errors, 1);
  caught_error_t * ce = caught_errors[0];
  ck_assert_uint_eq(ce->error_code, H2_ERROR_PROTOCOL_ERROR);
  ck_assert_str_eq(ce->error_string, "Invalid frame type: 0xff");
}
END_TEST

START_TEST(test_h2_frame_parse_data)
{
  uint8_t buffer[] = {
    0, 0, 0x4, FRAME_TYPE_DATA, FLAG_END_STREAM, 0, 0, 0, 1, 0xde, 0xad, 0xbe, 0xef
  };
  size_t buffer_position = 0;
  size_t buffer_length = sizeof(buffer) / sizeof(uint8_t);

  h2_frame_t * ret = h2_frame_parse(&parser, buffer, buffer_length, &buffer_position);
  ck_assert(ret != NULL);

  ck_assert_uint_eq(buffer_position, buffer_length);
  ck_assert_uint_eq(num_frames_parsed, 1);
  h2_frame_data_t * frame = (h2_frame_data_t *) last_frames[0];
  ck_assert_uint_eq(frame->length, 4);
  ck_assert_uint_eq(frame->type, FRAME_TYPE_DATA);
  ck_assert_uint_eq(frame->flags, FLAG_END_STREAM);
  ck_assert_uint_eq(frame->stream_id, 1);
  ck_assert_uint_eq(frame->payload_length, 4);
  ck_assert_uint_eq(frame->payload[0], 0xde);
  ck_assert_uint_eq(frame->payload[1], 0xad);
  ck_assert_uint_eq(frame->payload[2], 0xbe);
  ck_assert_uint_eq(frame->payload[3], 0xef);
}
END_TEST

START_TEST(test_h2_frame_parse_data_with_extra_buffer)
{
  uint8_t buffer[] = {
    0, 0, 0x4, FRAME_TYPE_DATA, FLAG_END_STREAM, 0, 0, 0, 1, 0xde, 0xad, 0xbe, 0xef,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
  };
  size_t buffer_position = 0;
  size_t buffer_length = sizeof(buffer) / sizeof(uint8_t);

  h2_frame_t * ret = h2_frame_parse(&parser, buffer, buffer_length, &buffer_position);
  ck_assert(ret != NULL);

  ck_assert_uint_eq(buffer_position, 9 + 4);
  ck_assert_uint_eq(num_frames_parsed, 1);
  h2_frame_data_t * frame = (h2_frame_data_t *) last_frames[0];
  ck_assert_uint_eq(frame->length, 4);
  ck_assert_uint_eq(frame->type, FRAME_TYPE_DATA);
  ck_assert_uint_eq(frame->flags, FLAG_END_STREAM);
  ck_assert_uint_eq(frame->stream_id, 1);
  ck_assert_uint_eq(frame->payload_length, 4);
  ck_assert_uint_eq(frame->payload[0], 0xde);
  ck_assert_uint_eq(frame->payload[1], 0xad);
  ck_assert_uint_eq(frame->payload[2], 0xbe);
  ck_assert_uint_eq(frame->payload[3], 0xef);
}
END_TEST

START_TEST(test_h2_frame_parse_data_with_padding)
{
  uint8_t buffer[] = {
    0, 0, 0x9, FRAME_TYPE_DATA, FLAG_PADDED | FLAG_END_STREAM, 0, 0, 0, 1, 0x04, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00
  };
  size_t buffer_position = 0;
  size_t buffer_length = sizeof(buffer) / sizeof(uint8_t);

  h2_frame_t * ret = h2_frame_parse(&parser, buffer, buffer_length, &buffer_position);
  ck_assert(ret != NULL);

  ck_assert_uint_eq(buffer_position, buffer_length);
  ck_assert_uint_eq(num_frames_parsed, 1);
  h2_frame_data_t * frame = (h2_frame_data_t *) last_frames[0];
  ck_assert_uint_eq(frame->length, 9);
  ck_assert_uint_eq(frame->type, FRAME_TYPE_DATA);
  ck_assert_uint_eq(frame->flags, FLAG_PADDED | FLAG_END_STREAM);
  ck_assert_uint_eq(frame->stream_id, 1);
  ck_assert_uint_eq(frame->payload_length, 4);
  ck_assert_uint_eq(frame->payload[0], 0xde);
  ck_assert_uint_eq(frame->payload[1], 0xad);
  ck_assert_uint_eq(frame->payload[2], 0xbe);
  ck_assert_uint_eq(frame->payload[3], 0xef);
}
END_TEST

START_TEST(test_h2_frame_parse_data_with_1_padding)
{
  uint8_t buffer[] = {
    0, 0, 0x5, FRAME_TYPE_DATA, FLAG_PADDED | FLAG_END_STREAM, 0, 0, 0, 1, 0x00, 0xde, 0xad, 0xbe, 0xef
  };
  size_t buffer_position = 0;
  size_t buffer_length = sizeof(buffer) / sizeof(uint8_t);

  h2_frame_t * ret = h2_frame_parse(&parser, buffer, buffer_length, &buffer_position);
  ck_assert(ret != NULL);

  ck_assert_uint_eq(buffer_position, buffer_length);
  ck_assert_uint_eq(num_frames_parsed, 1);
  h2_frame_data_t * frame = (h2_frame_data_t *) last_frames[0];
  ck_assert_uint_eq(frame->length, 5);
  ck_assert_uint_eq(frame->type, FRAME_TYPE_DATA);
  ck_assert_uint_eq(frame->flags, FLAG_PADDED | FLAG_END_STREAM);
  ck_assert_uint_eq(frame->stream_id, 1);
  ck_assert_uint_eq(frame->payload_length, 4);
  ck_assert_uint_eq(frame->payload[0], 0xde);
  ck_assert_uint_eq(frame->payload[1], 0xad);
  ck_assert_uint_eq(frame->payload[2], 0xbe);
  ck_assert_uint_eq(frame->payload[3], 0xef);
}
END_TEST

START_TEST(test_h2_frame_parse_data_with_all_padding)
{
  uint8_t buffer[] = {
    0, 0, 0x5, FRAME_TYPE_DATA, FLAG_PADDED | FLAG_END_STREAM, 0, 0, 0, 1, 0x04, 0, 0, 0, 0
  };
  size_t buffer_position = 0;
  size_t buffer_length = sizeof(buffer) / sizeof(uint8_t);

  h2_frame_t * ret = h2_frame_parse(&parser, buffer, buffer_length, &buffer_position);
  ck_assert(ret != NULL);

  ck_assert_uint_eq(buffer_position, buffer_length);
  ck_assert_uint_eq(num_frames_parsed, 1);
  h2_frame_data_t * frame = (h2_frame_data_t *) last_frames[0];
  ck_assert_uint_eq(frame->length, 5);
  ck_assert_uint_eq(frame->type, FRAME_TYPE_DATA);
  ck_assert_uint_eq(frame->flags, FLAG_PADDED | FLAG_END_STREAM);
  ck_assert_uint_eq(frame->stream_id, 1);
  ck_assert_uint_eq(frame->payload_length, 0);
}
END_TEST

START_TEST(test_h2_frame_parse_data_with_max_padding)
{
  uint8_t buffer[4 + 1 + 255 + 9] = {
    0, ((4 + 1 + 255) >> 8) & 0xff, (4 + 1 + 255) & 0xff, FRAME_TYPE_DATA, FLAG_PADDED | FLAG_END_STREAM, 0, 0, 0, 1, 0xff, 0xde, 0xad, 0xbe, 0xef, // + a lot of padding
  };
  size_t buffer_position = 0;
  size_t buffer_length = sizeof(buffer) / sizeof(uint8_t);

  h2_frame_t * ret = h2_frame_parse(&parser, buffer, buffer_length, &buffer_position);
  ck_assert(ret != NULL);

  ck_assert_uint_eq(buffer_position, buffer_length);
  ck_assert_uint_eq(num_frames_parsed, 1);
  h2_frame_data_t * frame = (h2_frame_data_t *) last_frames[0];
  ck_assert_uint_eq(frame->length, 4 + 1 + 255);
  ck_assert_uint_eq(frame->type, FRAME_TYPE_DATA);
  ck_assert_uint_eq(frame->flags, FLAG_PADDED | FLAG_END_STREAM);
  ck_assert_uint_eq(frame->stream_id, 1);
  ck_assert_uint_eq(frame->payload_length, 4);
  ck_assert_uint_eq(frame->payload[0], 0xde);
  ck_assert_uint_eq(frame->payload[1], 0xad);
  ck_assert_uint_eq(frame->payload[2], 0xbe);
  ck_assert_uint_eq(frame->payload[3], 0xef);
}
END_TEST

START_TEST(test_h2_frame_parse_data_with_too_much_padding)
{
  uint8_t buffer[] = {
    0, 0, 0x5, FRAME_TYPE_DATA, FLAG_PADDED | FLAG_END_STREAM, 0, 0, 0, 1, 0x06, 0xde, 0xad, 0xbe, 0xef
  };
  size_t buffer_position = 0;
  size_t buffer_length = sizeof(buffer) / sizeof(uint8_t);

  h2_frame_t * ret = h2_frame_parse(&parser, buffer, buffer_length, &buffer_position);
  ck_assert(ret == NULL);

  // buffer position might be set to the middle of the frame, don't worry about it since
  // it will throw a protocol error anyway
  ck_assert_uint_eq(num_frames_parsed, 0);

  ck_assert_uint_eq(num_errors, 1);
  caught_error_t * ce = caught_errors[0];
  ck_assert_uint_eq(ce->error_code, H2_ERROR_PROTOCOL_ERROR);
  ck_assert_str_eq(ce->error_string,
      "Padding length is too large in comparison to frame length: 6 (0x6) >= 5 (0x5)");
}
END_TEST

START_TEST(test_h2_frame_parse_data_with_too_much_padding_by_1)
{
  uint8_t buffer[] = {
    0, 0, 0x5, FRAME_TYPE_DATA, FLAG_PADDED | FLAG_END_STREAM, 0, 0, 0, 1, 0x05, 0xde, 0xad, 0xbe, 0xef
  };
  size_t buffer_position = 0;
  size_t buffer_length = sizeof(buffer) / sizeof(uint8_t);

  h2_frame_t * ret = h2_frame_parse(&parser, buffer, buffer_length, &buffer_position);
  ck_assert(ret == NULL);

  // buffer position might be set to the middle of the frame, don't worry about it since
  // it will throw a protocol error anyway
  ck_assert_uint_eq(num_frames_parsed, 0);

  ck_assert_uint_eq(num_errors, 1);
  caught_error_t * ce = caught_errors[0];
  ck_assert_uint_eq(ce->error_code, H2_ERROR_PROTOCOL_ERROR);
  ck_assert_str_eq(ce->error_string,
      "Padding length is too large in comparison to frame length: 5 (0x5) >= 5 (0x5)");
}
END_TEST

START_TEST(test_h2_frame_parse_data_with_no_stream_id)
{
  uint8_t buffer[] = {
    0, 0, 4, FRAME_TYPE_DATA, FLAG_END_STREAM, 0, 0, 0, 0, 0xde, 0xad, 0xbe, 0xef
  };
  size_t buffer_position = 0;
  size_t buffer_length = sizeof(buffer) / sizeof(uint8_t);

  h2_frame_t * ret = h2_frame_parse(&parser, buffer, buffer_length, &buffer_position);
  ck_assert(ret == NULL);

  ck_assert_uint_eq(buffer_position, 0);
  ck_assert_uint_eq(num_frames_parsed, 0);

  ck_assert_uint_eq(num_errors, 1);
  caught_error_t * ce = caught_errors[0];
  ck_assert_uint_eq(ce->error_code, H2_ERROR_PROTOCOL_ERROR);
  ck_assert_str_eq(ce->error_string, "Stream ID must be set for frame type DATA (0x0)");
}
END_TEST

START_TEST(test_h2_frame_parse_headers)
{
  uint8_t buffer[] = {
    0, 0, 0x4, FRAME_TYPE_HEADERS, FLAG_END_HEADERS, 0, 0, 0, 1, 0xde, 0xad, 0xbe, 0xef
  };
  size_t buffer_position = 0;
  size_t buffer_length = sizeof(buffer) / sizeof(uint8_t);

  h2_frame_t * ret = h2_frame_parse(&parser, buffer, buffer_length, &buffer_position);
  ck_assert(ret != NULL);

  ck_assert_uint_eq(buffer_position, 9 + 4);
  ck_assert_uint_eq(num_frames_parsed, 1);
  h2_frame_headers_t * frame = (h2_frame_headers_t*) last_frames[0];
  ck_assert_uint_eq(frame->length, 4);
  ck_assert_uint_eq(frame->type, FRAME_TYPE_HEADERS);
  ck_assert_uint_eq(frame->flags, FLAG_END_HEADERS);
  ck_assert_uint_eq(frame->stream_id, 1);
  ck_assert_uint_eq(frame->header_block_fragment_length, 4);
  ck_assert_uint_eq(frame->header_block_fragment[0], 0xde);
  ck_assert_uint_eq(frame->header_block_fragment[1], 0xad);
  ck_assert_uint_eq(frame->header_block_fragment[2], 0xbe);
  ck_assert_uint_eq(frame->header_block_fragment[3], 0xef);
}
END_TEST

START_TEST(test_h2_frame_parse_headers_plus_data)
{
  uint8_t buffer[] = {
    0, 0, 0x4, FRAME_TYPE_HEADERS, FLAG_END_HEADERS, 0, 0, 0, 1, 0xde, 0xad, 0xbe, 0xef,
    0, 0, 0x4, FRAME_TYPE_DATA, FLAG_END_STREAM, 0, 0, 0, 1, 0xde, 0xad, 0xbe, 0xef,
  };
  size_t buffer_position = 0;
  size_t buffer_length = sizeof(buffer) / sizeof(uint8_t);

  h2_frame_t * ret = h2_frame_parse(&parser, buffer, buffer_length, &buffer_position);
  ck_assert(ret != NULL);

  ck_assert_uint_eq(buffer_position, 9 + 4);
  ck_assert_uint_eq(num_frames_parsed, 1);
  h2_frame_headers_t * frame = (h2_frame_headers_t*) last_frames[0];
  ck_assert_uint_eq(frame->length, 4);
  ck_assert_uint_eq(frame->type, FRAME_TYPE_HEADERS);
  ck_assert_uint_eq(frame->flags, FLAG_END_HEADERS);
  ck_assert_uint_eq(frame->stream_id, 1);
  ck_assert_uint_eq(frame->header_block_fragment_length, 4);
  ck_assert_uint_eq(frame->header_block_fragment[0], 0xde);
  ck_assert_uint_eq(frame->header_block_fragment[1], 0xad);
  ck_assert_uint_eq(frame->header_block_fragment[2], 0xbe);
  ck_assert_uint_eq(frame->header_block_fragment[3], 0xef);

  h2_frame_t * ret2 = h2_frame_parse(&parser, buffer, buffer_length, &buffer_position);
  ck_assert(ret2 != NULL);

  ck_assert_uint_eq(buffer_position, 9 + 4 + 9 + 4);
  ck_assert_uint_eq(num_frames_parsed, 2);
  h2_frame_data_t * data_frame = (h2_frame_data_t *) last_frames[1];
  ck_assert_uint_eq(data_frame->length, 4);
  ck_assert_uint_eq(data_frame->type, FRAME_TYPE_DATA);
  ck_assert_uint_eq(data_frame->flags, FLAG_END_STREAM);
  ck_assert_uint_eq(data_frame->stream_id, 1);
  ck_assert_uint_eq(data_frame->payload_length, 4);
  ck_assert_uint_eq(data_frame->payload[0], 0xde);
  ck_assert_uint_eq(data_frame->payload[1], 0xad);
  ck_assert_uint_eq(data_frame->payload[2], 0xbe);
  ck_assert_uint_eq(data_frame->payload[3], 0xef);
}
END_TEST

START_TEST(test_h2_frame_parse_headers_plus_frame_header_of_next_frame)
{
  uint8_t buffer[] = {
    0, 0, 0x4, FRAME_TYPE_HEADERS, FLAG_END_HEADERS, 0, 0, 0, 1, 0xde, 0xad, 0xbe, 0xef,
    0, 0, 0x4, FRAME_TYPE_DATA, FLAG_END_STREAM, 0, 0, 0, 1,
  };
  size_t buffer_position = 0;
  size_t buffer_length = sizeof(buffer) / sizeof(uint8_t);

  h2_frame_t * ret = h2_frame_parse(&parser, buffer, buffer_length, &buffer_position);
  ck_assert(ret != NULL);

  ck_assert_uint_eq(buffer_position, 9 + 4);
  ck_assert_uint_eq(num_frames_parsed, 1);
  h2_frame_headers_t * frame = (h2_frame_headers_t*) last_frames[0];
  ck_assert_uint_eq(frame->length, 4);
  ck_assert_uint_eq(frame->type, FRAME_TYPE_HEADERS);
  ck_assert_uint_eq(frame->flags, FLAG_END_HEADERS);
  ck_assert_uint_eq(frame->stream_id, 1);
  ck_assert_uint_eq(frame->header_block_fragment_length, 4);
  ck_assert_uint_eq(frame->header_block_fragment[0], 0xde);
  ck_assert_uint_eq(frame->header_block_fragment[1], 0xad);
  ck_assert_uint_eq(frame->header_block_fragment[2], 0xbe);
  ck_assert_uint_eq(frame->header_block_fragment[3], 0xef);

  h2_frame_t * ret2 = h2_frame_parse(&parser, buffer, buffer_length, &buffer_position);
  ck_assert(ret2 == NULL);

  ck_assert_uint_eq(buffer_position, 9 + 4);
  ck_assert_uint_eq(num_frames_parsed, 1);
}
END_TEST

START_TEST(test_h2_frame_parse_headers_plus_frame_header_and_then_some)
{
  uint8_t buffer[] = {
    0, 0, 0x4, FRAME_TYPE_HEADERS, FLAG_END_HEADERS, 0, 0, 0, 1, 0xde, 0xad, 0xbe, 0xef,
    0, 0, 0x4, FRAME_TYPE_DATA, FLAG_END_STREAM, 0, 0, 0, 1, 0xde, 0xad,
  };
  size_t buffer_position = 0;
  size_t buffer_length = sizeof(buffer) / sizeof(uint8_t);

  h2_frame_t * ret = h2_frame_parse(&parser, buffer, buffer_length, &buffer_position);
  ck_assert(ret != NULL);

  ck_assert_uint_eq(buffer_position, 9 + 4);
  ck_assert_uint_eq(num_frames_parsed, 1);
  h2_frame_headers_t * frame = (h2_frame_headers_t*) last_frames[0];
  ck_assert_uint_eq(frame->length, 4);
  ck_assert_uint_eq(frame->type, FRAME_TYPE_HEADERS);
  ck_assert_uint_eq(frame->flags, FLAG_END_HEADERS);
  ck_assert_uint_eq(frame->stream_id, 1);
  ck_assert_uint_eq(frame->header_block_fragment_length, 4);
  ck_assert_uint_eq(frame->header_block_fragment[0], 0xde);
  ck_assert_uint_eq(frame->header_block_fragment[1], 0xad);
  ck_assert_uint_eq(frame->header_block_fragment[2], 0xbe);
  ck_assert_uint_eq(frame->header_block_fragment[3], 0xef);

  h2_frame_t * ret2 = h2_frame_parse(&parser, buffer, buffer_length, &buffer_position);
  ck_assert(ret2 == NULL);

  ck_assert_uint_eq(buffer_position, 9 + 4);
  ck_assert_uint_eq(num_frames_parsed, 1);
}
END_TEST

START_TEST(test_h2_frame_parse_headers_with_padding)
{
  uint8_t buffer[] = {
    0, 0, 0x9, FRAME_TYPE_HEADERS, FLAG_PADDED | FLAG_END_STREAM, 0, 0, 0, 1, 0x04, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00
  };
  size_t buffer_position = 0;
  size_t buffer_length = sizeof(buffer) / sizeof(uint8_t);

  h2_frame_t * ret = h2_frame_parse(&parser, buffer, buffer_length, &buffer_position);
  ck_assert(ret != NULL);

  ck_assert_uint_eq(buffer_position, buffer_length);
  ck_assert_uint_eq(num_frames_parsed, 1);
  h2_frame_headers_t * frame = (h2_frame_headers_t *) last_frames[0];
  ck_assert_uint_eq(frame->length, 9);
  ck_assert_uint_eq(frame->type, FRAME_TYPE_HEADERS);
  ck_assert_uint_eq(frame->flags, FLAG_PADDED | FLAG_END_STREAM);
  ck_assert_uint_eq(frame->stream_id, 1);
  ck_assert_uint_eq(frame->priority_stream_dependency, 0);
  ck_assert_uint_eq(frame->priority_exclusive, 0);
  ck_assert_uint_eq(frame->priority_weight, 15); // default is 16, frame reports wire value (value - 1)
  ck_assert_uint_eq(frame->header_block_fragment_length, 4);
  ck_assert_uint_eq(frame->header_block_fragment[0], 0xde);
  ck_assert_uint_eq(frame->header_block_fragment[1], 0xad);
  ck_assert_uint_eq(frame->header_block_fragment[2], 0xbe);
  ck_assert_uint_eq(frame->header_block_fragment[3], 0xef);
}
END_TEST

START_TEST(test_h2_frame_parse_headers_with_1_padding)
{
  uint8_t buffer[] = {
    0, 0, 0x5, FRAME_TYPE_HEADERS, FLAG_PADDED | FLAG_END_STREAM, 0, 0, 0, 1, 0x00, 0xde, 0xad, 0xbe, 0xef
  };
  size_t buffer_position = 0;
  size_t buffer_length = sizeof(buffer) / sizeof(uint8_t);

  h2_frame_t * ret = h2_frame_parse(&parser, buffer, buffer_length, &buffer_position);
  ck_assert(ret != NULL);

  ck_assert_uint_eq(buffer_position, buffer_length);
  ck_assert_uint_eq(num_frames_parsed, 1);
  h2_frame_headers_t * frame = (h2_frame_headers_t *) last_frames[0];
  ck_assert_uint_eq(frame->length, 5);
  ck_assert_uint_eq(frame->type, FRAME_TYPE_HEADERS);
  ck_assert_uint_eq(frame->flags, FLAG_PADDED | FLAG_END_STREAM);
  ck_assert_uint_eq(frame->stream_id, 1);
  ck_assert_uint_eq(frame->header_block_fragment_length, 4);
  ck_assert_uint_eq(frame->header_block_fragment[0], 0xde);
  ck_assert_uint_eq(frame->header_block_fragment[1], 0xad);
  ck_assert_uint_eq(frame->header_block_fragment[2], 0xbe);
  ck_assert_uint_eq(frame->header_block_fragment[3], 0xef);
}
END_TEST

START_TEST(test_h2_frame_parse_headers_with_all_padding)
{
  uint8_t buffer[] = {
    0, 0, 0x5, FRAME_TYPE_HEADERS, FLAG_PADDED | FLAG_END_STREAM, 0, 0, 0, 1, 0x04, 0, 0, 0, 0
  };
  size_t buffer_position = 0;
  size_t buffer_length = sizeof(buffer) / sizeof(uint8_t);

  h2_frame_t * ret = h2_frame_parse(&parser, buffer, buffer_length, &buffer_position);
  ck_assert(ret != NULL);

  ck_assert_uint_eq(buffer_position, buffer_length);
  ck_assert_uint_eq(num_frames_parsed, 1);
  h2_frame_headers_t * frame = (h2_frame_headers_t *) last_frames[0];
  ck_assert_uint_eq(frame->length, 5);
  ck_assert_uint_eq(frame->type, FRAME_TYPE_HEADERS);
  ck_assert_uint_eq(frame->flags, FLAG_PADDED | FLAG_END_STREAM);
  ck_assert_uint_eq(frame->stream_id, 1);
  ck_assert_uint_eq(frame->header_block_fragment_length, 0);
}
END_TEST

START_TEST(test_h2_frame_parse_headers_with_max_padding)
{
  uint8_t buffer[4 + 1 + 255 + 9] = {
    0, ((4 + 1 + 255) >> 8) & 0xff, (4 + 1 + 255) & 0xff, FRAME_TYPE_HEADERS, FLAG_PADDED | FLAG_END_STREAM, 0, 0, 0, 1, 0xff, 0xde, 0xad, 0xbe, 0xef, // + a lot of padding
  };
  size_t buffer_position = 0;
  size_t buffer_length = sizeof(buffer) / sizeof(uint8_t);

  h2_frame_t * ret = h2_frame_parse(&parser, buffer, buffer_length, &buffer_position);
  ck_assert(ret != NULL);

  ck_assert_uint_eq(buffer_position, buffer_length);
  ck_assert_uint_eq(num_frames_parsed, 1);
  h2_frame_headers_t * frame = (h2_frame_headers_t *) last_frames[0];
  ck_assert_uint_eq(frame->length, 4 + 1 + 255);
  ck_assert_uint_eq(frame->type, FRAME_TYPE_HEADERS);
  ck_assert_uint_eq(frame->flags, FLAG_PADDED | FLAG_END_STREAM);
  ck_assert_uint_eq(frame->stream_id, 1);
  ck_assert_uint_eq(frame->header_block_fragment_length, 4);
  ck_assert_uint_eq(frame->header_block_fragment[0], 0xde);
  ck_assert_uint_eq(frame->header_block_fragment[1], 0xad);
  ck_assert_uint_eq(frame->header_block_fragment[2], 0xbe);
  ck_assert_uint_eq(frame->header_block_fragment[3], 0xef);
}
END_TEST

START_TEST(test_h2_frame_parse_headers_with_too_much_padding)
{
  uint8_t buffer[] = {
    0, 0, 0x5, FRAME_TYPE_HEADERS, FLAG_PADDED | FLAG_END_STREAM, 0, 0, 0, 1, 0x06, 0xde, 0xad, 0xbe, 0xef
  };
  size_t buffer_position = 0;
  size_t buffer_length = sizeof(buffer) / sizeof(uint8_t);

  h2_frame_t * ret = h2_frame_parse(&parser, buffer, buffer_length, &buffer_position);
  ck_assert(ret == NULL);

  // buffer position might be set to the middle of the frame, don't worry about it since
  // it will throw a protocol error anyway
  ck_assert_uint_eq(num_frames_parsed, 0);

  ck_assert_uint_eq(num_errors, 1);
  caught_error_t * ce = caught_errors[0];
  ck_assert_uint_eq(ce->error_code, H2_ERROR_PROTOCOL_ERROR);
  ck_assert_str_eq(ce->error_string,
      "Padding length is too large in comparison to frame length: 6 (0x6) >= 5 (0x5)");
}
END_TEST

START_TEST(test_h2_frame_parse_headers_with_too_much_padding_by_1)
{
  uint8_t buffer[] = {
    0, 0, 0x5, FRAME_TYPE_HEADERS, FLAG_PADDED | FLAG_END_STREAM, 0, 0, 0, 1, 0x05, 0xde, 0xad, 0xbe, 0xef
  };
  size_t buffer_position = 0;
  size_t buffer_length = sizeof(buffer) / sizeof(uint8_t);

  h2_frame_t * ret = h2_frame_parse(&parser, buffer, buffer_length, &buffer_position);
  ck_assert(ret == NULL);

  // buffer position might be set to the middle of the frame, don't worry about it since
  // it will throw a protocol error anyway
  ck_assert_uint_eq(num_frames_parsed, 0);

  ck_assert_uint_eq(num_errors, 1);
  caught_error_t * ce = caught_errors[0];
  ck_assert_uint_eq(ce->error_code, H2_ERROR_PROTOCOL_ERROR);
  ck_assert_str_eq(ce->error_string,
      "Padding length is too large in comparison to frame length: 5 (0x5) >= 5 (0x5)");
}
END_TEST

START_TEST(test_h2_frame_parse_headers_with_priority)
{
  uint8_t buffer[] = {
    0, 0, 0x9, FRAME_TYPE_HEADERS, FLAG_PRIORITY | FLAG_END_STREAM, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0xde, 0xad, 0xbe, 0xef
  };
  size_t buffer_position = 0;
  size_t buffer_length = sizeof(buffer) / sizeof(uint8_t);

  h2_frame_t * ret = h2_frame_parse(&parser, buffer, buffer_length, &buffer_position);
  ck_assert(ret != NULL);

  ck_assert_uint_eq(buffer_position, buffer_length);
  ck_assert_uint_eq(num_frames_parsed, 1);
  h2_frame_headers_t * frame = (h2_frame_headers_t *) last_frames[0];
  ck_assert_uint_eq(frame->length, 9);
  ck_assert_uint_eq(frame->type, FRAME_TYPE_HEADERS);
  ck_assert_uint_eq(frame->flags, FLAG_PRIORITY | FLAG_END_STREAM);
  ck_assert_uint_eq(frame->stream_id, 1);
  ck_assert_uint_eq(frame->priority_exclusive, 0);
  ck_assert_uint_eq(frame->priority_stream_dependency, 1);
  ck_assert_uint_eq(frame->priority_weight, 1);
  ck_assert_uint_eq(frame->header_block_fragment_length, 4);
  ck_assert_uint_eq(frame->header_block_fragment[0], 0xde);
  ck_assert_uint_eq(frame->header_block_fragment[1], 0xad);
  ck_assert_uint_eq(frame->header_block_fragment[2], 0xbe);
  ck_assert_uint_eq(frame->header_block_fragment[3], 0xef);
}
END_TEST

START_TEST(test_h2_frame_parse_headers_with_priority_stream_exclusive)
{
  uint8_t buffer[] = {
    0, 0, 0x9, FRAME_TYPE_HEADERS, FLAG_PRIORITY | FLAG_END_STREAM, 0, 0, 0, 1, 0x80, 0, 0, 1, 1, 0xde, 0xad, 0xbe, 0xef
  };
  size_t buffer_position = 0;
  size_t buffer_length = sizeof(buffer) / sizeof(uint8_t);

  h2_frame_t * ret = h2_frame_parse(&parser, buffer, buffer_length, &buffer_position);
  ck_assert(ret != NULL);

  ck_assert_uint_eq(buffer_position, buffer_length);
  ck_assert_uint_eq(num_frames_parsed, 1);
  h2_frame_headers_t * frame = (h2_frame_headers_t *) last_frames[0];
  ck_assert_uint_eq(frame->length, 9);
  ck_assert_uint_eq(frame->type, FRAME_TYPE_HEADERS);
  ck_assert_uint_eq(frame->flags, FLAG_PRIORITY | FLAG_END_STREAM);
  ck_assert_uint_eq(frame->stream_id, 1);
  ck_assert_uint_eq(frame->priority_exclusive, 1);
  ck_assert_uint_eq(frame->priority_stream_dependency, 1);
  ck_assert_uint_eq(frame->priority_weight, 1);
  ck_assert_uint_eq(frame->header_block_fragment_length, 4);
  ck_assert_uint_eq(frame->header_block_fragment[0], 0xde);
  ck_assert_uint_eq(frame->header_block_fragment[1], 0xad);
  ck_assert_uint_eq(frame->header_block_fragment[2], 0xbe);
  ck_assert_uint_eq(frame->header_block_fragment[3], 0xef);
}
END_TEST

START_TEST(test_h2_frame_parse_headers_with_priority_and_padding)
{
  uint8_t buffer[] = {
    0, 0, 14, FRAME_TYPE_HEADERS, FLAG_PRIORITY | FLAG_PADDED | FLAG_END_STREAM, 0, 0, 0, 1, 4, 0, 0, 0, 1, 1, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00
  };
  size_t buffer_position = 0;
  size_t buffer_length = sizeof(buffer) / sizeof(uint8_t);

  h2_frame_t * ret = h2_frame_parse(&parser, buffer, buffer_length, &buffer_position);
  ck_assert(ret != NULL);

  ck_assert_uint_eq(buffer_position, buffer_length);
  ck_assert_uint_eq(num_frames_parsed, 1);
  h2_frame_headers_t * frame = (h2_frame_headers_t *) last_frames[0];
  ck_assert_uint_eq(frame->length, 14);
  ck_assert_uint_eq(frame->type, FRAME_TYPE_HEADERS);
  ck_assert_uint_eq(frame->flags, FLAG_PADDED | FLAG_PRIORITY | FLAG_END_STREAM);
  ck_assert_uint_eq(frame->stream_id, 1);
  ck_assert_uint_eq(frame->priority_exclusive, 0);
  ck_assert_uint_eq(frame->priority_stream_dependency, 1);
  ck_assert_uint_eq(frame->priority_weight, 1);
  ck_assert_uint_eq(frame->header_block_fragment_length, 4);
  ck_assert_uint_eq(frame->header_block_fragment[0], 0xde);
  ck_assert_uint_eq(frame->header_block_fragment[1], 0xad);
  ck_assert_uint_eq(frame->header_block_fragment[2], 0xbe);
  ck_assert_uint_eq(frame->header_block_fragment[3], 0xef);
}
END_TEST

START_TEST(test_h2_frame_parse_headers_with_no_stream_id)
{
  uint8_t buffer[] = {
    0, 0, 4, FRAME_TYPE_HEADERS, FLAG_END_HEADERS, 0, 0, 0, 0, 0xde, 0xad, 0xbe, 0xef
  };
  size_t buffer_position = 0;
  size_t buffer_length = sizeof(buffer) / sizeof(uint8_t);

  h2_frame_t * ret = h2_frame_parse(&parser, buffer, buffer_length, &buffer_position);
  ck_assert(ret == NULL);

  ck_assert_uint_eq(buffer_position, 0);
  ck_assert_uint_eq(num_frames_parsed, 0);

  ck_assert_uint_eq(num_errors, 1);
  caught_error_t * ce = caught_errors[0];
  ck_assert_uint_eq(ce->error_code, H2_ERROR_PROTOCOL_ERROR);
  ck_assert_str_eq(ce->error_string, "Stream ID must be set for frame type HEADERS (0x1)");
}
END_TEST

START_TEST(test_h2_frame_parse_priority)
{
  uint8_t buffer[] = {
    0, 0, 0x5, FRAME_TYPE_PRIORITY, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1
  };
  size_t buffer_position = 0;
  size_t buffer_length = sizeof(buffer) / sizeof(uint8_t);

  h2_frame_t * ret = h2_frame_parse(&parser, buffer, buffer_length, &buffer_position);
  ck_assert(ret != NULL);

  ck_assert_uint_eq(buffer_position, buffer_length);
  ck_assert_uint_eq(num_frames_parsed, 1);
  h2_frame_priority_t * frame = (h2_frame_priority_t *) last_frames[0];
  ck_assert_uint_eq(frame->length, 5);
  ck_assert_uint_eq(frame->type, FRAME_TYPE_PRIORITY);
  ck_assert_uint_eq(frame->flags, 0);
  ck_assert_uint_eq(frame->stream_id, 1);
  ck_assert_uint_eq(frame->priority_exclusive, 0);
  ck_assert_uint_eq(frame->priority_stream_dependency, 1);
  ck_assert_uint_eq(frame->priority_weight, 1);
}
END_TEST

START_TEST(test_h2_frame_parse_priority_with_high_weight)
{
  uint8_t buffer[] = {
    0, 0, 0x5, FRAME_TYPE_PRIORITY, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0xff
  };
  size_t buffer_position = 0;
  size_t buffer_length = sizeof(buffer) / sizeof(uint8_t);

  h2_frame_t * ret = h2_frame_parse(&parser, buffer, buffer_length, &buffer_position);
  ck_assert(ret != NULL);

  ck_assert_uint_eq(buffer_position, buffer_length);
  ck_assert_uint_eq(num_frames_parsed, 1);
  h2_frame_priority_t * frame = (h2_frame_priority_t *) last_frames[0];
  ck_assert_uint_eq(frame->length, 5);
  ck_assert_uint_eq(frame->type, FRAME_TYPE_PRIORITY);
  ck_assert_uint_eq(frame->flags, 0);
  ck_assert_uint_eq(frame->stream_id, 1);
  ck_assert_uint_eq(frame->priority_exclusive, 0);
  ck_assert_uint_eq(frame->priority_stream_dependency, 1);
  ck_assert_uint_eq(frame->priority_weight, 0xff);
}
END_TEST

START_TEST(test_h2_frame_parse_priority_with_high_dependency)
{
  uint8_t buffer[] = {
    0, 0, 0x5, FRAME_TYPE_PRIORITY, 0, 0, 0, 0, 1, 0x7f, 0xff, 0xff, 0xff, 15
  };
  size_t buffer_position = 0;
  size_t buffer_length = sizeof(buffer) / sizeof(uint8_t);

  h2_frame_t * ret = h2_frame_parse(&parser, buffer, buffer_length, &buffer_position);
  ck_assert(ret != NULL);

  ck_assert_uint_eq(buffer_position, buffer_length);
  ck_assert_uint_eq(num_frames_parsed, 1);
  h2_frame_priority_t * frame = (h2_frame_priority_t *) last_frames[0];
  ck_assert_uint_eq(frame->length, 5);
  ck_assert_uint_eq(frame->type, FRAME_TYPE_PRIORITY);
  ck_assert_uint_eq(frame->flags, 0);
  ck_assert_uint_eq(frame->stream_id, 1);
  ck_assert_uint_eq(frame->priority_exclusive, 0);
  ck_assert_uint_eq(frame->priority_stream_dependency, 0x7fffffff);
  ck_assert_uint_eq(frame->priority_weight, 15);
}
END_TEST

START_TEST(test_h2_frame_parse_priority_with_stream_exclusive)
{
  uint8_t buffer[] = {
    0, 0, 0x5, FRAME_TYPE_PRIORITY, 0, 0, 0, 0, 1, 0x80, 0, 0, 0, 15
  };
  size_t buffer_position = 0;
  size_t buffer_length = sizeof(buffer) / sizeof(uint8_t);

  h2_frame_t * ret = h2_frame_parse(&parser, buffer, buffer_length, &buffer_position);
  ck_assert(ret != NULL);

  ck_assert_uint_eq(buffer_position, buffer_length);
  ck_assert_uint_eq(num_frames_parsed, 1);
  h2_frame_priority_t * frame = (h2_frame_priority_t *) last_frames[0];
  ck_assert_uint_eq(frame->length, 5);
  ck_assert_uint_eq(frame->type, FRAME_TYPE_PRIORITY);
  ck_assert_uint_eq(frame->flags, 0);
  ck_assert_uint_eq(frame->stream_id, 1);
  ck_assert_uint_eq(frame->priority_exclusive, true);
  ck_assert_uint_eq(frame->priority_stream_dependency, 0);
  ck_assert_uint_eq(frame->priority_weight, 15);
}
END_TEST

START_TEST(test_h2_frame_parse_priority_with_no_stream_id)
{
  uint8_t buffer[] = {
    0, 0, 0x5, FRAME_TYPE_PRIORITY, 0, 0, 0, 0, 0, 0x80, 0, 0, 0, 15
  };
  size_t buffer_position = 0;
  size_t buffer_length = sizeof(buffer) / sizeof(uint8_t);

  h2_frame_t * ret = h2_frame_parse(&parser, buffer, buffer_length, &buffer_position);
  ck_assert(ret == NULL);

  ck_assert_uint_eq(buffer_position, 0);
  ck_assert_uint_eq(num_frames_parsed, 0);

  ck_assert_uint_eq(num_errors, 1);
  caught_error_t * ce = caught_errors[0];
  ck_assert_uint_eq(ce->error_code, H2_ERROR_PROTOCOL_ERROR);
  ck_assert_str_eq(ce->error_string, "Stream ID must be set for frame type PRIORITY (0x2)");
}
END_TEST

START_TEST(test_h2_frame_parse_rst_stream)
{
  uint8_t buffer[] = {
    0, 0, 0x4, FRAME_TYPE_RST_STREAM, 0, 0, 0, 0, 1, 0, 0, 0, H2_ERROR_INTERNAL_ERROR
  };
  size_t buffer_position = 0;
  size_t buffer_length = sizeof(buffer) / sizeof(uint8_t);

  h2_frame_t * ret = h2_frame_parse(&parser, buffer, buffer_length, &buffer_position);
  ck_assert(ret != NULL);

  ck_assert_uint_eq(buffer_position, buffer_length);
  ck_assert_uint_eq(num_frames_parsed, 1);
  h2_frame_rst_stream_t * frame = (h2_frame_rst_stream_t *) last_frames[0];
  ck_assert_uint_eq(frame->length, 4);
  ck_assert_uint_eq(frame->type, FRAME_TYPE_RST_STREAM);
  ck_assert_uint_eq(frame->flags, 0);
  ck_assert_uint_eq(frame->stream_id, 1);
  ck_assert_uint_eq(frame->error_code, H2_ERROR_INTERNAL_ERROR);
}
END_TEST

START_TEST(test_h2_frame_parse_rst_stream_with_invalid_stream_id)
{
  uint8_t buffer[] = {
    0, 0, 0x4, FRAME_TYPE_RST_STREAM, 0, 0, 0, 0, 0, 0, 0, 0, H2_ERROR_INTERNAL_ERROR
  };
  size_t buffer_position = 0;
  size_t buffer_length = sizeof(buffer) / sizeof(uint8_t);

  h2_frame_t * ret = h2_frame_parse(&parser, buffer, buffer_length, &buffer_position);
  ck_assert(ret == NULL);

  ck_assert_uint_eq(num_frames_parsed, 0);
  ck_assert_uint_eq(num_errors, 1);
  caught_error_t * ce = caught_errors[0];
  ck_assert_uint_eq(ce->error_code, H2_ERROR_PROTOCOL_ERROR);
  ck_assert_str_eq(ce->error_string, "Stream ID must be set for frame type RST_STREAM (0x3)");
}
END_TEST

START_TEST(test_h2_frame_parse_settings_ack)
{
  uint8_t buffer[] = {
    0, 0, 0, FRAME_TYPE_SETTINGS, FLAG_ACK, 0, 0, 0, 0
  };
  size_t buffer_position = 0;
  size_t buffer_length = sizeof(buffer) / sizeof(uint8_t);

  h2_frame_t * ret = h2_frame_parse(&parser, buffer, buffer_length, &buffer_position);
  ck_assert(ret != NULL);

  ck_assert_uint_eq(buffer_position, buffer_length);
  ck_assert_uint_eq(num_frames_parsed, 1);
  h2_frame_settings_t * frame = (h2_frame_settings_t *) last_frames[0];
  ck_assert_uint_eq(frame->length, 0);
  ck_assert_uint_eq(frame->type, FRAME_TYPE_SETTINGS);
  ck_assert_uint_eq(frame->flags, FLAG_ACK);
  ck_assert_uint_eq(frame->stream_id, 0);
  ck_assert_uint_eq(frame->num_settings, 0);
}
END_TEST

START_TEST(test_h2_frame_parse_settings_ack_with_invalid_length)
{
  uint8_t buffer[] = {
    0, 0, 5, FRAME_TYPE_SETTINGS, FLAG_ACK, 0, 0, 0, 0, SETTINGS_ENABLE_PUSH, 0, 0, 0, 0
  };
  size_t buffer_position = 0;
  size_t buffer_length = sizeof(buffer) / sizeof(uint8_t);

  h2_frame_t * ret = h2_frame_parse(&parser, buffer, buffer_length, &buffer_position);
  ck_assert(ret == NULL);

  ck_assert_uint_eq(num_frames_parsed, 0);
  ck_assert_uint_eq(num_errors, 1);
  caught_error_t * ce = caught_errors[0];
  ck_assert_uint_eq(ce->error_code, H2_ERROR_FRAME_SIZE_ERROR);
  ck_assert_str_eq(ce->error_string, "SETTINGS (0x4) ACK frame must have 0 length but was: 5 (0x5)");
}
END_TEST

START_TEST(test_h2_frame_parse_settings_with_payload)
{
  uint8_t buffer[] = {
    0, 0, 6, FRAME_TYPE_SETTINGS, 0, 0, 0, 0, 0, 0, SETTINGS_ENABLE_PUSH, 0, 0, 0, 0
  };
  size_t buffer_position = 0;
  size_t buffer_length = sizeof(buffer) / sizeof(uint8_t);

  h2_frame_t * ret = h2_frame_parse(&parser, buffer, buffer_length, &buffer_position);
  ck_assert(ret != NULL);

  ck_assert_uint_eq(buffer_position, buffer_length);
  ck_assert_uint_eq(num_frames_parsed, 1);
  h2_frame_settings_t * frame = (h2_frame_settings_t *) last_frames[0];
  ck_assert_uint_eq(frame->length, 6);
  ck_assert_uint_eq(frame->type, FRAME_TYPE_SETTINGS);
  ck_assert_uint_eq(frame->flags, 0);
  ck_assert_uint_eq(frame->stream_id, 0);
  ck_assert_uint_eq(frame->num_settings, 1);
  ck_assert_uint_eq(frame->settings[0].id, SETTINGS_ENABLE_PUSH);
  ck_assert_uint_eq(frame->settings[0].value, 0);
}
END_TEST

START_TEST(test_h2_frame_parse_settings_with_invalid_frame_length)
{
  uint8_t buffer[] = {
    0, 0, 5, FRAME_TYPE_SETTINGS, 0, 0, 0, 0, 0, 0, SETTINGS_ENABLE_PUSH, 0, 0, 0
  };
  size_t buffer_position = 0;
  size_t buffer_length = sizeof(buffer) / sizeof(uint8_t);

  h2_frame_t * ret = h2_frame_parse(&parser, buffer, buffer_length, &buffer_position);
  ck_assert(ret == NULL);

  ck_assert_uint_eq(num_frames_parsed, 0);
  ck_assert_uint_eq(num_errors, 1);
  caught_error_t * ce = caught_errors[0];
  ck_assert_uint_eq(ce->error_code, H2_ERROR_FRAME_SIZE_ERROR);
  ck_assert_str_eq(ce->error_string, "SETTINGS (0x4) frame length must be a multiple of 6 but was: 5 (0x5)");
}
END_TEST

START_TEST(test_h2_frame_parse_settings_with_too_many_settings)
{
  uint8_t buffer[] = {
    0, 0, 6 * 7, FRAME_TYPE_SETTINGS, 0, 0, 0, 0, 0,
    0, SETTINGS_HEADER_TABLE_SIZE, 0, 0, 0, 0,
    0, SETTINGS_ENABLE_PUSH, 0, 0, 0, 0,
    0, SETTINGS_MAX_CONCURRENT_STREAMS, 0, 0, 0, 0,
    0, SETTINGS_INITIAL_WINDOW_SIZE, 0, 0, 0, 0,
    0, SETTINGS_MAX_FRAME_SIZE, 0, 0, 0, 0,
    0, SETTINGS_MAX_HEADER_LIST_SIZE, 0, 0, 0, 0,
    0, 100, 0, 0, 0, 0
  };
  size_t buffer_position = 0;
  size_t buffer_length = sizeof(buffer) / sizeof(uint8_t);

  h2_frame_t * ret = h2_frame_parse(&parser, buffer, buffer_length, &buffer_position);
  ck_assert(ret == NULL);

  ck_assert_uint_eq(num_frames_parsed, 0);
  ck_assert_uint_eq(num_errors, 1);
  caught_error_t * ce = caught_errors[0];
  ck_assert_uint_eq(ce->error_code, H2_ERROR_INTERNAL_ERROR);
  ck_assert_str_eq(ce->error_string, "Up to 6 settings per frame are supported");
}
END_TEST

START_TEST(test_h2_frame_parse_settings_with_bad_push_enabled_value)
{
  uint8_t buffer[] = {
    0, 0, 6 * 1, FRAME_TYPE_SETTINGS, 0, 0, 0, 0, 0,
    0, SETTINGS_ENABLE_PUSH, 0, 0, 0, 2
  };
  size_t buffer_position = 0;
  size_t buffer_length = sizeof(buffer) / sizeof(uint8_t);

  h2_frame_t * ret = h2_frame_parse(&parser, buffer, buffer_length, &buffer_position);
  ck_assert(ret == NULL);

  ck_assert_uint_eq(num_frames_parsed, 0);
  ck_assert_uint_eq(num_errors, 1);
  caught_error_t * ce = caught_errors[0];
  ck_assert_uint_eq(ce->error_code, H2_ERROR_PROTOCOL_ERROR);
  ck_assert_str_eq(ce->error_string, "SETTINGS_ENABLE_PUSH value must be 0 or 1 but was: 2 (0x2)");
}
END_TEST

START_TEST(test_h2_frame_parse_settings_with_bad_initial_window_size)
{
  uint8_t buffer[] = {
    0, 0, 6 * 1, FRAME_TYPE_SETTINGS, 0, 0, 0, 0, 0,
    0, SETTINGS_INITIAL_WINDOW_SIZE, 0xff, 0xff, 0xff, 0xff
  };
  size_t buffer_position = 0;
  size_t buffer_length = sizeof(buffer) / sizeof(uint8_t);

  h2_frame_t * ret = h2_frame_parse(&parser, buffer, buffer_length, &buffer_position);
  ck_assert(ret == NULL);

  ck_assert_uint_eq(num_frames_parsed, 0);
  ck_assert_uint_eq(num_errors, 1);
  caught_error_t * ce = caught_errors[0];
  ck_assert_uint_eq(ce->error_code, H2_ERROR_PROTOCOL_ERROR);
  ck_assert_str_eq(ce->error_string,
      "SETTINGS_INITIAL_WINDOW_SIZE value must not be greater than 0x7fffffff "
      "but was: 4294967295 (0xffffffff)");
}
END_TEST

START_TEST(test_h2_frame_parse_settings_with_low_max_frame_size)
{
  uint8_t buffer[] = {
    0, 0, 6 * 1, FRAME_TYPE_SETTINGS, 0, 0, 0, 0, 0,
    0, SETTINGS_MAX_FRAME_SIZE, 0, 0, 0x20, 0
  };
  size_t buffer_position = 0;
  size_t buffer_length = sizeof(buffer) / sizeof(uint8_t);

  h2_frame_t * ret = h2_frame_parse(&parser, buffer, buffer_length, &buffer_position);
  ck_assert(ret == NULL);

  ck_assert_uint_eq(num_frames_parsed, 0);
  ck_assert_uint_eq(num_errors, 1);
  caught_error_t * ce = caught_errors[0];
  ck_assert_uint_eq(ce->error_code, H2_ERROR_PROTOCOL_ERROR);
  ck_assert_str_eq(ce->error_string,
      "SETTINGS_MAX_FRAME_SIZE value must be between 0x4000 and 0xffffff (inclusive) "
      "but was: 8192 (0x2000)");
}
END_TEST

START_TEST(test_h2_frame_parse_settings_with_high_max_frame_size)
{
  uint8_t buffer[] = {
    0, 0, 6 * 1, FRAME_TYPE_SETTINGS, 0, 0, 0, 0, 0,
    0, SETTINGS_MAX_FRAME_SIZE, 0xf0, 0, 0, 0
  };
  size_t buffer_position = 0;
  size_t buffer_length = sizeof(buffer) / sizeof(uint8_t);

  h2_frame_t * ret = h2_frame_parse(&parser, buffer, buffer_length, &buffer_position);
  ck_assert(ret == NULL);

  ck_assert_uint_eq(num_frames_parsed, 0);
  ck_assert_uint_eq(num_errors, 1);
  caught_error_t * ce = caught_errors[0];
  ck_assert_uint_eq(ce->error_code, H2_ERROR_PROTOCOL_ERROR);
  ck_assert_str_eq(ce->error_string,
      "SETTINGS_MAX_FRAME_SIZE value must be between 0x4000 and 0xffffff (inclusive) "
      "but was: 4026531840 (0xf0000000)");
}
END_TEST

START_TEST(test_h2_frame_parse_settings_with_unknown_setting_id)
{
  uint8_t buffer[] = {
    0, 0, 6, FRAME_TYPE_SETTINGS, 0, 0, 0, 0, 0, 0, 100, 0, 0, 0, 0
  };
  size_t buffer_position = 0;
  size_t buffer_length = sizeof(buffer) / sizeof(uint8_t);

  h2_frame_t * ret = h2_frame_parse(&parser, buffer, buffer_length, &buffer_position);
  ck_assert(ret != NULL);

  ck_assert_uint_eq(buffer_position, buffer_length);
  ck_assert_uint_eq(num_frames_parsed, 1);
  h2_frame_settings_t * frame = (h2_frame_settings_t *) last_frames[0];
  ck_assert_uint_eq(frame->length, 6);
  ck_assert_uint_eq(frame->type, FRAME_TYPE_SETTINGS);
  ck_assert_uint_eq(frame->flags, 0);
  ck_assert_uint_eq(frame->stream_id, 0);
  ck_assert_uint_eq(frame->num_settings, 1);
  ck_assert_uint_eq(frame->settings[0].id, 100);
  ck_assert_uint_eq(frame->settings[0].value, 0);
}
END_TEST

START_TEST(test_h2_frame_parse_settings_with_multiple_settings)
{
  uint8_t buffer[] = {
    0, 0, 12, FRAME_TYPE_SETTINGS, 0, 0, 0, 0, 0,
    0, SETTINGS_MAX_CONCURRENT_STREAMS, 0, 0, 0, 100,
    0, SETTINGS_MAX_FRAME_SIZE, 0, 0, 0x40, 0x00
  };
  size_t buffer_position = 0;
  size_t buffer_length = sizeof(buffer) / sizeof(uint8_t);

  h2_frame_t * ret = h2_frame_parse(&parser, buffer, buffer_length, &buffer_position);
  ck_assert(ret != NULL);

  ck_assert_uint_eq(buffer_position, buffer_length);
  ck_assert_uint_eq(num_frames_parsed, 1);
  h2_frame_settings_t * frame = (h2_frame_settings_t *) last_frames[0];
  ck_assert_uint_eq(frame->length, 12);
  ck_assert_uint_eq(frame->type, FRAME_TYPE_SETTINGS);
  ck_assert_uint_eq(frame->flags, 0);
  ck_assert_uint_eq(frame->stream_id, 0);
  ck_assert_uint_eq(frame->num_settings, 2);
  ck_assert_uint_eq(frame->settings[0].id, SETTINGS_MAX_CONCURRENT_STREAMS);
  ck_assert_uint_eq(frame->settings[0].value, 100);
  ck_assert_uint_eq(frame->settings[1].id, SETTINGS_MAX_FRAME_SIZE);
  ck_assert_uint_eq(frame->settings[1].value, 0x4000);
}
END_TEST

Suite * hpack_suite()
{
  Suite * s = suite_create("h2_frame");

  TCase * tc = tcase_create("h2_frame");
  tcase_add_checked_fixture(tc, setup, teardown);

  tcase_add_test(tc, test_h2_frame_emit_data_empty);
  tcase_add_test(tc, test_h2_frame_emit_data_with_payload);
  tcase_add_test(tc, test_h2_frame_emit_data_with_large_payload);
  tcase_add_test(tc, test_h2_frame_emit_data_twice);

  tcase_add_test(tc, test_h2_frame_emit_headers_empty);
  tcase_add_test(tc, test_h2_frame_emit_headers_end_stream);
  tcase_add_test(tc, test_h2_frame_emit_headers_with_payload);

  tcase_add_test(tc, test_h2_frame_emit_rst_stream);

  tcase_add_test(tc, test_h2_frame_emit_settings_ack);

  tcase_add_test(tc, test_h2_frame_emit_push_promise_empty);
  tcase_add_test(tc, test_h2_frame_emit_push_promise_end_stream);
  tcase_add_test(tc, test_h2_frame_emit_push_promise_with_payload);

  tcase_add_test(tc, test_h2_frame_emit_ping_ack);

  tcase_add_test(tc, test_h2_frame_emit_goaway);
  tcase_add_test(tc, test_h2_frame_emit_goaway_with_debug_data);

  tcase_add_test(tc, test_h2_frame_emit_window_update_for_connection);
  tcase_add_test(tc, test_h2_frame_emit_window_update_for_stream);

  tcase_add_test(tc, test_h2_frame_emit_continuation);

  tcase_add_test(tc, test_h2_frame_parse_invalid_frame_type);

  tcase_add_test(tc, test_h2_frame_parse_data);
  tcase_add_test(tc, test_h2_frame_parse_data_with_extra_buffer);
  tcase_add_test(tc, test_h2_frame_parse_data_with_padding);
  tcase_add_test(tc, test_h2_frame_parse_data_with_1_padding);
  tcase_add_test(tc, test_h2_frame_parse_data_with_max_padding);
  tcase_add_test(tc, test_h2_frame_parse_data_with_too_much_padding);
  tcase_add_test(tc, test_h2_frame_parse_data_with_too_much_padding_by_1);
  tcase_add_test(tc, test_h2_frame_parse_data_with_all_padding);
  tcase_add_test(tc, test_h2_frame_parse_data_with_no_stream_id);

  tcase_add_test(tc, test_h2_frame_parse_headers);
  tcase_add_test(tc, test_h2_frame_parse_headers_plus_data);
  tcase_add_test(tc, test_h2_frame_parse_headers_plus_frame_header_of_next_frame);
  tcase_add_test(tc, test_h2_frame_parse_headers_plus_frame_header_and_then_some);

  tcase_add_test(tc, test_h2_frame_parse_headers_with_padding);
  tcase_add_test(tc, test_h2_frame_parse_headers_with_1_padding);
  tcase_add_test(tc, test_h2_frame_parse_headers_with_max_padding);
  tcase_add_test(tc, test_h2_frame_parse_headers_with_too_much_padding);
  tcase_add_test(tc, test_h2_frame_parse_headers_with_too_much_padding_by_1);
  tcase_add_test(tc, test_h2_frame_parse_headers_with_all_padding);

  tcase_add_test(tc, test_h2_frame_parse_headers_with_priority);
  tcase_add_test(tc, test_h2_frame_parse_headers_with_priority_stream_exclusive);

  tcase_add_test(tc, test_h2_frame_parse_headers_with_priority_and_padding);

  tcase_add_test(tc, test_h2_frame_parse_headers_with_no_stream_id);

  tcase_add_test(tc, test_h2_frame_parse_priority);
  tcase_add_test(tc, test_h2_frame_parse_priority_with_high_weight);
  tcase_add_test(tc, test_h2_frame_parse_priority_with_high_dependency);
  tcase_add_test(tc, test_h2_frame_parse_priority_with_stream_exclusive);
  tcase_add_test(tc, test_h2_frame_parse_priority_with_no_stream_id);

  tcase_add_test(tc, test_h2_frame_parse_rst_stream);
  tcase_add_test(tc, test_h2_frame_parse_rst_stream_with_invalid_stream_id);

  tcase_add_test(tc, test_h2_frame_parse_settings_ack);
  tcase_add_test(tc, test_h2_frame_parse_settings_ack_with_invalid_length);
  tcase_add_test(tc, test_h2_frame_parse_settings_with_payload);
  tcase_add_test(tc, test_h2_frame_parse_settings_with_multiple_settings);
  tcase_add_test(tc, test_h2_frame_parse_settings_with_unknown_setting_id);
  tcase_add_test(tc, test_h2_frame_parse_settings_with_too_many_settings);
  tcase_add_test(tc, test_h2_frame_parse_settings_with_bad_push_enabled_value);
  tcase_add_test(tc, test_h2_frame_parse_settings_with_bad_initial_window_size);
  tcase_add_test(tc, test_h2_frame_parse_settings_with_low_max_frame_size);
  tcase_add_test(tc, test_h2_frame_parse_settings_with_high_max_frame_size);
  tcase_add_test(tc, test_h2_frame_parse_settings_with_invalid_frame_length);

  suite_add_tcase(s, tc);

  return s;
}

int main()
{
  Suite * s = hpack_suite();
  SRunner * sr = srunner_create(s);
  srunner_run_all(sr, CK_NORMAL);
  int number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
