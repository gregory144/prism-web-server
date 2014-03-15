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

http_parser_t* http_parser_init(void* data, request_cb request_handler, write_cb writer, close_cb closer) {
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

  parser->streams = calloc(sizeof(http_stream_t*), 4096);

  parser->request_listener = request_handler;

  parser->encoding_context = hpack_context_init(DEFAULT_HEADER_TABLE_SIZE);
  parser->decoding_context = hpack_context_init(parser->header_table_size);

  return parser;
}

void http_stream_close(http_parser_t* parser, http_stream_t* stream) {
  hpack_headers_free(stream->headers);
  parser->streams[stream->id] = NULL;
  free(stream);
}

void http_parser_free(http_parser_t* parser) {
  int i;
  for (i = 0; i < 4096; i++) {
    http_stream_t* stream = parser->streams[i];
    if (stream) {
      http_stream_close(parser, stream);
    }
  }
  free(parser->streams);
  hpack_context_free(parser->encoding_context);
  hpack_context_free(parser->decoding_context);
  free(parser);
}

void http_frame_header_write(uint8_t* buf, uint16_t length, uint8_t type, uint8_t flags, uint32_t stream_id) {
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

void http_emit_headers(http_parser_t* parser, http_stream_t* stream, http_headers_t* headers) {
  // TODO split large headers into multiple frames
  size_t headers_length = 0;
  uint8_t* hpack_buf = NULL;
  if (headers != NULL) {
    hpack_encode_result_t* encoded = hpack_encode(parser->encoding_context, headers);
    hpack_buf = encoded->buf;
    headers_length = encoded->buf_length;
    free(encoded);
  }
  size_t buf_length = FRAME_HEADER_SIZE + headers_length;
  uint8_t* buf = malloc(buf_length);
  uint8_t flags = 0;
  bool end_stream = false;
  bool end_headers = true;
  bool priority = false;
  if (end_stream) flags |= HEADERS_FLAG_END_STREAM;
  if (end_headers) flags |= HEADERS_FLAG_END_HEADERS;
  if (priority) flags |= HEADERS_FLAG_PRIORITY;
  http_frame_header_write(buf, headers_length, FRAME_TYPE_HEADERS, flags, stream->id);

  if (hpack_buf) {
    size_t pos = FRAME_HEADER_SIZE;
    memcpy(buf + pos, hpack_buf, headers_length);
    free(hpack_buf);
  }

  log_debug("Writing headers frame: stream %d, %ld octets\n", stream->id, buf_length);
  parser->writer(parser->data, buf, buf_length);
}

void http_emit_data(http_parser_t* parser, http_stream_t* stream, uint8_t* text, size_t text_length) {
  // TODO split large text into multiple frames
  // TODO support adding padding?
  size_t buf_length = FRAME_HEADER_SIZE + text_length;
  uint8_t* buf = malloc(buf_length);
  uint8_t flags = 0;
  bool end_stream = true;
  if (end_stream) flags |= DATA_FLAG_END_STREAM;
  http_frame_header_write(buf, text_length, FRAME_TYPE_DATA, flags, stream->id);
  size_t pos = FRAME_HEADER_SIZE;
  memcpy(buf + pos, text, text_length);
  log_debug("Writing data frame: stream %d, %ld octets\n", stream->id, buf_length);
  parser->writer(parser->data, buf, buf_length);
}

void http_emit_settings_ack(http_parser_t* parser) {
  size_t buf_length = FRAME_HEADER_SIZE;
  uint8_t* buf = malloc(buf_length);
  uint8_t flags = 0;
  bool ack = true;
  if (ack) flags |= SETTINGS_FLAG_ACK;
  http_frame_header_write(buf, 0, FRAME_TYPE_SETTINGS, flags, 0);
  log_debug("Writing settings ack frame\n");
  parser->writer(parser->data, buf, buf_length);
}

/**
 * Returns true if the first part of data is the http connection
 * header string
 */
bool http_parser_recognize_connection_header(http_parser_t* parser) {
  if (parser->buffer_length >= HTTP_CONNECTION_HEADER_LENGTH) {
    parser->buffer_position = HTTP_CONNECTION_HEADER_LENGTH;
    return memcmp(parser->buffer, HTTP_CONNECTION_HEADER,
        HTTP_CONNECTION_HEADER_LENGTH) == 0;
  }
  return false;
}

void http_setting_set(http_parser_t* parser, uint8_t id, uint32_t value) {
  log_debug("Setting: %d: %d\n", id, value);
  switch (id) {
    case SETTINGS_HEADER_TABLE_SIZE:
      log_debug("Got table size: %d\n", value);
      parser->header_table_size = value;
      hpack_header_table_adjust_size(parser->decoding_context, value);
      break;
    case SETTINGS_ENABLE_PUSH:
      log_debug("Enable push? %d\n", value);
      parser->enable_push = value;
      break;
    case SETTINGS_MAX_CONCURRENT_STREAMS:
      log_debug("Max concurrent streams: %d\n", value);
      parser->max_concurrent_streams = value;
      break;
    case SETTINGS_INITIAL_WINDOW_SIZE:
      log_debug("Initial window size: %d\n", value);
      parser->initial_window_size = value;
      break;
    default:
      // TODO emit PROTOCOL_ERROR
      log_error("Invalid setting: %d\n", id);
      abort();
  }
}

http_stream_t* http_stream_get(http_parser_t* parser, uint32_t stream_id) {
  // TODO - use a better data structure than an array
  if (stream_id >= 4096) {
    log_error("Unsupported stream identifier (too high): %d\n", stream_id);
    abort();
  }

  http_stream_t* stream = parser->streams[stream_id];

  if (stream == NULL) {
    log_error("Unknown stream identifier: %d\n", stream_id);
  }

  return stream;
}

http_stream_t* http_stream_init(http_parser_t* parser, uint32_t stream_id) {
  http_stream_t* stream = http_stream_get(parser, stream_id);
  if (stream != NULL) {
    // got a HEADERS frame for an existing stream
    // TODO emit protocol error
    log_error("Got a headers frame for an existing stream\n");
    abort();
  }
  stream = malloc(sizeof(http_stream_t));
  parser->streams[stream_id] = stream;

  stream->id = stream_id;
  stream->state = STREAM_STATE_IDLE;
  stream->header_fragments = NULL;
  stream->headers = NULL;
  stream->priority = DEFAULT_STREAM_PRIORITY;

  return stream;
}

void http_trigger_request(http_parser_t* parser, http_stream_t* stream) {
  if (!parser->request_listener) {
    log_error("No request listener set up\n");
    abort();
  }

  http_request_t* request = malloc(sizeof(http_request_t));
  request->headers = stream->headers;
  request->params = NULL;
  request->parser = (_http_parser_t)parser;
  request->stream = (_http_stream_t)stream;

  http_response_t* response = malloc(sizeof(http_response_t));
  response->request = request;
  response->headers = NULL;

  parser->request_listener(request, response);
}

void http_stream_add_header_fragment(http_stream_t* stream, uint8_t* buffer, size_t length) {
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
    log_debug("Counting header fragment lengths: %ld\n", current->length);
    headers_length += current->length;
  }
  uint8_t* headers = malloc(headers_length + 1);
  uint8_t* header_appender = headers;
  current = stream->header_fragments;
  while (current) {
    log_debug("Appending header fragment: %s (%ld)\n", current->buffer, current->length);
    memcpy(header_appender, current->buffer, current->length);
    header_appender += current->length;
    http_header_fragment_t* prev = current;
    current = current->next;
    free(prev->buffer);
    free(prev);
  }
  *header_appender = '\0';
  log_debug("Got headers: %s (%ld), decoding\n", headers, headers_length);
  stream->headers = hpack_decode(parser->decoding_context, headers, headers_length);
  stream->state = STREAM_STATE_OPEN;

  free(headers);

  http_trigger_request(parser, stream);
}

void http_parse_frame_headers(http_parser_t* parser, http_frame_headers_t* frame) {
  uint8_t* pos = parser->buffer + parser->buffer_position;
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
    log_debug("Parsing headers\n");
    http_parse_header_fragments(parser, stream);
  }
}

void http_parse_frame_settings(http_parser_t* parser, http_frame_settings_t* frame) {
  if (frame->stream_id != 0) {
    // TODO emit PROTOCOL_ERROR
    log_error("Invalid stream identifier for settings frame\n");
    abort();
  }
  if (frame->ack && frame->length != 0) {
    // TODO emit PROTOCOL_ERROR - FRAME_SIZE_ERROR
    log_error("Invalid frame size (non-zero) for ACK settings frame\n");
    abort();
  }
  if (frame->ack) {
    // TODO mark the settings frame we sent as acknowledged
    log_debug("Received settings ACK\n");
    abort();
  } else {
    uint8_t* pos = parser->buffer + parser->buffer_position;
    size_t setting_size = 8;
    size_t num_settings = frame->length / setting_size;
    log_debug("Found #%ld settings\n", num_settings);
    size_t i;
    for (i = 0; i < num_settings; i++) {
      uint8_t* curr_setting = pos + (i * setting_size);
      uint32_t setting_id = get_bits32(curr_setting, 0, 1, 0x0FF);
      uint32_t setting_value = curr_setting[1];
      http_setting_set(parser, setting_id, setting_value);
    }
    parser->received_settings = true;
    log_debug("Settings: %ld, %d, %ld, %ld\n", parser->header_table_size, parser->enable_push,
        parser->max_concurrent_streams, parser->initial_window_size);

    http_emit_settings_ack(parser);
  }
}

void http_parse_frame_goaway(http_parser_t* parser, http_frame_goaway_t* frame) {
  if (frame->stream_id != 0) {
    // TODO emit PROTOCOL_ERROR
    log_error("Invalid stream identifier for goaway frame\n");
    abort();
  }
  uint8_t* buf = parser->buffer + parser->buffer_position;
  frame->last_stream_id = get_bits32(buf, 0, 4, 0x7FFFFFFF);
  frame->error_code = get_bits32(buf, 4, 4, 0xFFFFFFFF);
  size_t debug_data_length = (frame->length - 8);
  frame->debug_data = malloc(sizeof(char) * (debug_data_length + 1));
  memcpy(frame->debug_data, buf + 8, debug_data_length);
  frame->debug_data[debug_data_length] = '\0';

  log_debug("Received goaway, last stream: %d, error code: %d, debug_data: %s\n", frame->last_stream_id, frame->error_code, frame->debug_data);

  free(frame->debug_data);
}

http_frame_t* http_frame_init(uint16_t length, char type, char flags, uint32_t stream_id) {
  http_frame_t* frame;
  switch(type) {
    case FRAME_TYPE_DATA:
    {
      http_frame_data_t *data_frame = malloc(sizeof(http_frame_data_t));
      data_frame->end_stream = flags & DATA_FLAG_END_STREAM;
      // flag 0x2 is reserved
      frame = (http_frame_t*) data_frame;
      break;
    }
    case FRAME_TYPE_HEADERS:
    {
      http_frame_headers_t *headers_frame = malloc(sizeof(http_frame_headers_t));
      headers_frame->end_stream = flags & HEADERS_FLAG_END_STREAM;
      // flag 0x2 is reserved
      headers_frame->end_headers = flags & HEADERS_FLAG_END_HEADERS;
      headers_frame->priority = flags & HEADERS_FLAG_PRIORITY;
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
    */
    case FRAME_TYPE_GOAWAY:
    {
      http_frame_goaway_t *goaway_frame = malloc(sizeof(http_frame_goaway_t));
      frame = (http_frame_t*) goaway_frame;
      break;
    }
    /*
    case FRAME_TYPE_WINDOW_UPDATE:
      parse_frame_window_update(parser);
    case FRAME_TYPE_CONTINUATION:
      parse_frame_continuation(parser);
    */
    default:
      log_fatal("Invalid frame type: %d\n", type);
      abort();
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
    log_error("Not enough in buffer to read frame header\n");
    return false;
  }

  uint8_t* pos = parser->buffer + parser->buffer_position;

  // get 14 bits of first 2 bytes
  uint16_t frame_length = get_bits16(pos, 0, 2, 0x3FFF);
  uint8_t frame_type = pos[2];
  uint8_t frame_flags = pos[3];
  // get 31 bits
  uint32_t stream_id = get_bits32(pos, 4, 4, 0x7FFFFFFF);
  log_debug("stream id: %x %x %x %x\n", pos[4], pos[5], pos[6], pos[7]);

  http_frame_t* frame = http_frame_init(frame_length, frame_type, frame_flags, stream_id);
  log_debug("length: %d, type: %d, id: %d\n", frame->length, frame->type, frame->stream_id);

  parser->buffer_position += FRAME_HEADER_SIZE;

  // is there enough in the buffer to read the frame payload?
  if (parser->buffer_position + frame->length <= parser->buffer_length) {
    // TODO off-by-one?
    if (!parser->received_settings && frame->type != FRAME_TYPE_SETTINGS) {
      // TODO emit protocol error?
      log_error("Expected settings frame as first frame type\n");
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
        */
        case FRAME_TYPE_GOAWAY:
          http_parse_frame_goaway(parser, (http_frame_goaway_t*) frame);
          break;
        /*
        case FRAME_TYPE_WINDOW_UPDATE:
          parse_frame_window_update(parser);
        case FRAME_TYPE_CONTINUATION:
          parse_frame_continuation(parser);
        */
        default:
          log_error("Invalid frame type: %d\n", frame->type);
      }
    }

    parser->buffer_position += frame->length;
    free(frame);
    return true;
  } else {
    log_error("Not enough in buffer to read frame payload\n");
    abort();
  }
  return false;
}

void http_parser_read(http_parser_t* parser, uint8_t* buffer, size_t len) {
  log_debug("Reading from buffer: %ld\n", len);
  parser->buffer = buffer;
  parser->buffer_length = len;
  parser->buffer_position = 0;
  if (!parser->received_connection_header) {
    if (http_parser_recognize_connection_header(parser)) {
      parser->received_connection_header = true;
      log_debug("Found HTTP2 connection\n");
    } else {
      log_debug("Found non-HTTP2 connection, closing connection\n");
      parser->closer(parser->data);
      return;
    }
  }
  while (http_parser_add_from_buffer(parser));
  log_debug("What next?\n");
}

void http_response_write(http_response_t* response, char* text, size_t text_length) {
  http_parser_t* parser = (http_parser_t*)response->request->parser;
  http_stream_t* stream = (http_stream_t*)response->request->stream;

  // emit headers frame
  http_emit_headers(parser, stream, response->headers);

  // emit data frame
  http_emit_data(parser, stream, (uint8_t*)text, text_length);

  http_response_free(response);
}

