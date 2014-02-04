#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "http.h"
#include "util.h"

#define FRAME_HEADER_SIZE 8 // octets
#define DEFAULT_STREAM_PRIORITY 0x40000000 // 2^30

const char* HTTP_CONNECTION_HEADER = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const size_t HTTP_CONNECTION_HEADER_LENGTH = 24;

http_parser_t* http_parser_init(void* data, write_cb writer, close_cb closer) {
  http_parser_t* parser = malloc(sizeof(http_parser_t));

  parser->data = data;
  parser->writer = writer;
  parser->closer = closer;

  parser->received_connection_header = false;
  parser->received_settings = false;
  parser->current_stream_id = 2;

  parser->buffer = NULL;
  parser->buffer_length = 0;
  parser->buffer_position = 0;

  parser->header_table_size = DEFAULT_HEADER_TABLE_SIZE;
  parser->enable_push = DEFAULT_ENABLE_PUSH;
  parser->max_concurrent_streams = DEFAULT_MAX_CONNCURRENT_STREAMS;
  parser->initial_window_size = DEFAULT_INITIAL_WINDOW_SIZE;

  parser->streams = calloc(sizeof(http_stream_t*), 1024);

  return parser;
}

void http_parser_free(http_parser_t* parser) {
  free(parser);
}

void http_emit_frame(http_parser_t* parser, http_frame_t* frame) {
  fprintf(stderr, "http_emit_frame: \n");
  parser->writer(parser->data, "xxx\n", 4);
}

void http_emit_goaway(http_parser_t* parser, int error_code) {
  http_emit_frame(parser, NULL);
}

/**
 * Returns true if the first part of data is the http connection
 * header string
 */
bool http_parser_recognize_connection_header(http_parser_t* parser) {
  if (parser->buffer_length >= HTTP_CONNECTION_HEADER_LENGTH) {
    parser->buffer_position = HTTP_CONNECTION_HEADER_LENGTH;
    return strncmp(parser->buffer, HTTP_CONNECTION_HEADER,
        HTTP_CONNECTION_HEADER_LENGTH) == 0;
  }
  return false;
}

inline uint16_t get_bits16(char* buf, size_t offset, size_t num_bytes, uint16_t mask) {
  char* curr = buf + offset;
  uint16_t val = 0;
  for (; curr < buf + offset + num_bytes; curr++) {
    val = (val << 8) | *curr;
  }
  return val & mask;
}

inline uint32_t get_bits32(char* buf, size_t offset, size_t num_bytes, uint32_t mask) {
  char* curr = buf + offset;
  uint32_t val = 0;
  for (; curr < buf + offset + num_bytes; curr++) {
    val = (val << 8) | *curr;
  }
  return val & mask;
}

void http_setting_set(http_parser_t* parser, uint8_t id, uint32_t value) {
  fprintf(stderr, "Setting: %d: %d\n", id, value);
  switch (id) {
    case SETTINGS_HEADER_TABLE_SIZE:
      fprintf(stderr, "Got table size: %d\n", value);
      parser->header_table_size = value;
      break;
    case SETTINGS_ENABLE_PUSH:
      fprintf(stderr, "Enable push? %d\n", value);
      parser->enable_push = value;
      break;
    case SETTINGS_MAX_CONCURRENT_STREAMS:
      fprintf(stderr, "Max concurrent streams: %d\n", value);
      parser->max_concurrent_streams = value;
      break;
    case SETTINGS_INITIAL_WINDOW_SIZE:
      fprintf(stderr, "Initial window size: %d\n", value);
      parser->initial_window_size = value;
      break;
    default:
      // TODO emit PROTOCOL_ERROR
      fprintf(stderr, "Invalid setting: %d\n", id);
      abort();
  }
}

http_stream_t* http_stream_get(http_parser_t* parser, uint32_t stream_id) {
  // TODO - use a better data structure than an array
  http_stream_t* stream = parser->streams[stream_id];
  if (stream_id >= 1024) {
    fprintf(stderr, "Unsupported stream identifier (too high): %d\n", stream_id);
    abort();
  }

  if (stream == NULL) {
    //fprintf(stderr, "Unknown stream identifier: %d\n", stream_id);
  }

  return stream;
}

http_stream_t* http_stream_init(http_parser_t* parser, uint32_t stream_id) {
  http_stream_t* stream = http_stream_get(parser, stream_id);
  if (stream != NULL) {
    // got a HEADERS frame for an existing stream
    // TODO emit protocol error
    fprintf(stderr, "Got a headers frame for an existing stream\n");
    abort();
  }
  stream = malloc(sizeof(http_stream_t));
  parser->streams[stream_id] = stream;

  stream->id = stream_id;
  stream->state = STREAM_STATE_IDLE;
  stream->header_fragments = NULL;
  stream->headers = NULL;
  stream->headers_length = 0;
  stream->priority = DEFAULT_STREAM_PRIORITY;

  return stream;
}

void http_stream_add_header_fragment(http_stream_t* stream, char* buffer, size_t length) {
  http_header_fragment_t* fragment = malloc(sizeof(http_header_fragment_t));
  fragment->buffer = malloc(length);
  memcpy(fragment->buffer, buffer, length);
  fragment->length = length;
  fragment->next = NULL;

  http_header_fragment_t* current = stream->header_fragments;
  for (; current && current->next; current = current->next);
  if (current == NULL) {
    stream->header_fragments = fragment;
  } else {
    current->next = fragment;
  }
}

void http_parse_header_fragments(http_parser_t* parser, http_stream_t* stream) {
  size_t headers_length = 0;
  http_header_fragment_t* current = stream->header_fragments;
  for (; current; current = current->next) {
    fprintf(stderr, "Counting header fragment lengths: %ld\n", current->length);
    headers_length += current->length;
  }
  char* headers = malloc(headers_length + 1);
  char* header_appender = headers;
  current = stream->header_fragments;
  while (current) {
    fprintf(stderr, "Appending header fragment: %s (%ld)\n", current->buffer, current->length);
    memcpy(header_appender, current->buffer, current->length);
    header_appender += current->length;
    http_header_fragment_t* prev = current;
    current = current->next;
    free(prev->buffer);
    free(prev);
  }
  *header_appender = '\0';
  fprintf(stderr, "Got headers: %s (%ld)\n", headers, headers_length);
  stream->headers = headers;
  stream->headers_length = headers_length;
  stream->state = STREAM_STATE_OPEN;
}

void http_parse_frame_headers(http_parser_t* parser, http_frame_headers_t* frame) {
  // TODO - start request parsing!
  char* pos = parser->buffer + parser->buffer_position;
  size_t header_block_fragment_size = frame->length;
  http_stream_t* stream = http_stream_init(parser, frame->stream_id);
  if (frame->priority) {
    stream->priority = get_bits32(pos, 4, 4, 0x7FFFFFFF);
    pos += 4;
    parser->buffer_position += 4;
    header_block_fragment_size -= 4;
  }
  http_stream_add_header_fragment(stream, pos, header_block_fragment_size);
  if (frame->end_headers) {
    // parse the headers
    http_parse_header_fragments(parser, stream);
  }
}

void http_parse_frame_settings(http_parser_t* parser, http_frame_settings_t* frame) {
  if (frame->stream_id != 0) {
    // TODO emit PROTOCOL_ERROR
    fprintf(stderr, "Invalid stream identifier for settings frame\n");
    abort();
  }
  if (frame->ack && frame->length != 0) {
    // TODO emit PROTOCOL_ERROR - FRAME_SIZE_ERROR
    fprintf(stderr, "Invalid frame size (non-zero) for ACK settings frame\n");
    abort();
  }
  if (frame->ack) {
    // TODO mark the settings frame we sent as acknowledged
    fprintf(stderr, "Received settings ACK\n");
    abort();
  } else {
    char* pos = parser->buffer + parser->buffer_position;
    size_t setting_size = 8;
    size_t num_settings = frame->length / setting_size;
    fprintf(stderr, "Found #%ld settings\n", num_settings);
    size_t i;
    for (i = 0; i < num_settings; i++) {
      char* curr_setting = pos + (i * setting_size);
      uint32_t setting_id = get_bits32(curr_setting, 1, 3, 0x0FFF);
      uint32_t setting_value = get_bits32(curr_setting, 4, 4, 0xFFFF);
      http_setting_set(parser, setting_id, setting_value);
    }
    parser->received_settings = true;
    fprintf(stderr, "Settings: %ld, %d, %ld, %ld\n", parser->header_table_size, parser->enable_push,
        parser->max_concurrent_streams, parser->initial_window_size);
    // TODO emit settings ACK frame
  }
}

http_frame_t* http_frame_init(uint16_t length, char type, char flags, uint32_t stream_id) {
  http_frame_t* frame;
  switch(type) {
    /*
    case FRAME_TYPE_DATA:
      parse_frame_data(parser);
    */
    case FRAME_TYPE_HEADERS:
    {
      http_frame_headers_t *headers_frame = malloc(sizeof(http_frame_headers_t));
      headers_frame->end_stream = flags & 0x1;
      // flag 0x2 is reserved
      headers_frame->end_headers = flags & 0x4;
      headers_frame->priority = flags & 0x8;
      frame = (http_frame_t*) headers_frame;
      break;
    }
    /*
    case FRAME_TYPE_PRIORITY:
      parse_frame_priority(parser);
    case FRAME_TYPE_RST_STREAM:
      parse_frame_reset_stream(parser);
    */
    case FRAME_TYPE_SETTINGS:
    {
      http_frame_settings_t *settings_frame = malloc(sizeof(http_frame_settings_t));
      settings_frame->ack = flags & 0x1;
      frame = (http_frame_t*) settings_frame;
      break;
    }
    /*
    case FRAME_TYPE_PUSH_PROMISE:
      parse_frame_push_promise(parser);
    case FRAME_TYPE_PING:
      parse_frame_ping(parser);
    case FRAME_TYPE_GOAWAY:
      parse_frame_goaway(parser);
    case FRAME_TYPE_WINDOW_UPDATE:
      parse_frame_window_update(parser);
    case FRAME_TYPE_CONTINUATION:
      parse_frame_continuation(parser);
    */
    default:
      fprintf(stderr, "Invalid frame type: %d\n", type);
  }
  frame->type = type;
  frame->length = length;
  frame->stream_id = stream_id;
  return frame;
}

bool http_parser_add_from_buffer(http_parser_t* parser) {
  // is there enough in the buffer to read a frame header?
  if (parser->buffer_position + FRAME_HEADER_SIZE > parser->buffer_length) {
    // TODO off-by-one?
    fprintf(stderr, "Not enough in buffer to read frame header\n");
    return false;
  }

  char* pos = parser->buffer + parser->buffer_position;

  // get 14 bits of first 2 bytes
  uint16_t frame_length = get_bits16(pos, 0, 2, 0x3FFF);
  char frame_type = pos[2];
  char frame_flags = pos[3];
  // get 31 bits
  uint32_t stream_id = get_bits32(pos, 4, 4, 0x7FFFFFFF);

  http_frame_t* frame = http_frame_init(frame_length, frame_type, frame_flags, stream_id);
  fprintf(stderr, "length: %d, type: %d, id: %d\n", frame->length, frame->type, frame->stream_id);

  parser->buffer_position += FRAME_HEADER_SIZE;

  // is there enough in the buffer to read the frame payload?
  if (parser->buffer_position + frame->length <= parser->buffer_length) {
    // TODO off-by-one?
    if (!parser->received_settings && frame->type != FRAME_TYPE_SETTINGS) {
      // TODO emit protocol error?
      fprintf(stderr, "Expected settings frame as first frame type\n");
      abort();
    } else {
      switch(frame->type) {
        /*
        case FRAME_TYPE_DATA:
          parse_frame_data(parser);
        */
        case FRAME_TYPE_HEADERS:
          http_parse_frame_headers(parser, (http_frame_headers_t*) frame);
          break;
        /*
        case FRAME_TYPE_PRIORITY:
          parse_frame_priority(parser);
        case FRAME_TYPE_RST_STREAM:
          parse_frame_reset_stream(parser);
        */
        case FRAME_TYPE_SETTINGS:
          http_parse_frame_settings(parser, (http_frame_settings_t*) frame);
          break;
        /*
        case FRAME_TYPE_PUSH_PROMISE:
          parse_frame_push_promise(parser);
        case FRAME_TYPE_PING:
          parse_frame_ping(parser);
        case FRAME_TYPE_GOAWAY:
          parse_frame_goaway(parser);
        case FRAME_TYPE_WINDOW_UPDATE:
          parse_frame_window_update(parser);
        case FRAME_TYPE_CONTINUATION:
          parse_frame_continuation(parser);
        */
        default:
          fprintf(stderr, "Invalid frame type: %d\n", frame->type);
      }
    }

    parser->buffer_position += frame->length;
    return true;
  } else {
    fprintf(stderr, "Not enough in buffer to read frame payload\n");
    abort();
  }
  return false;
}

void http_parser_read(http_parser_t* parser, char* buffer, size_t len) {
  fprintf(stderr, "Reading from buffer: %ld\n", len);
  parser->buffer = buffer;
  parser->buffer_length = len;
  parser->buffer_position = 0;
  if (!parser->received_connection_header) {
    if (http_parser_recognize_connection_header(parser)) {
      parser->received_connection_header = true;
      fprintf(stderr, "Found HTTP2 connection\n");
      parser->writer(parser->data, "Init\n", 5);
    } else {
      fprintf(stderr, "Found non-HTTP2 connection, closing connection\n");
      parser->closer(parser->data);
      return;
    }
  }
  while (http_parser_add_from_buffer(parser));
  fprintf(stderr, "What next?\n");
}

