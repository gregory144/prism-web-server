#ifndef HTTP_HTTP_H
#define HTTP_HTTP_H

#include <stdbool.h>

#include "../hpack/hpack.h"

#include "request.h"
#include "response.h"
#include "hash_table.h"
#include "gzip.h"

#define PUSH_ENABLED false

/**
 * Frame types
 */
enum frame_type_e {
  FRAME_TYPE_DATA,
  FRAME_TYPE_HEADERS,
  FRAME_TYPE_PRIORITY,
  FRAME_TYPE_RST_STREAM,
  FRAME_TYPE_SETTINGS,
  FRAME_TYPE_PUSH_PROMISE,
  FRAME_TYPE_PING,
  FRAME_TYPE_GOAWAY,
  FRAME_TYPE_WINDOW_UPDATE,
  FRAME_TYPE_CONTINUATION,
  FRAME_TYPE_ALTSVC,
  FRAME_TYPE_BLOCKED
};

#define FRAME_TYPE_MIN FRAME_TYPE_DATA
#define FRAME_TYPE_MAX FRAME_TYPE_BLOCKED

/**
 * Stream states
 */
enum stream_state_e {
  STREAM_STATE_IDLE,
  STREAM_STATE_RESERVED_LOCAL,
  STREAM_STATE_RESERVED_REMOTE,
  STREAM_STATE_OPEN,
  STREAM_STATE_HALF_CLOSED_LOCAL,
  STREAM_STATE_HALF_CLOSED_REMOTE,
  STREAM_STATE_CLOSED
};

/**
 * Connection setting identifiers
 */
enum settings_e {
  SETTINGS_HEADER_TABLE_SIZE = 1,
  SETTINGS_ENABLE_PUSH,
  SETTINGS_MAX_CONCURRENT_STREAMS,
  SETTINGS_INITIAL_WINDOW_SIZE,
  SETTINGS_COMPRESS_DATA
};

/**
 * Default setting values
 */
#define DEFAULT_HEADER_TABLE_SIZE 4096
#define DEFAULT_ENABLE_PUSH 1
#define DEFAULT_MAX_CONNCURRENT_STREAMS 100
#define DEFAULT_INITIAL_WINDOW_SIZE 65535
#define DEFAULT_COMPRESS_DATA 0

/**
 * Frame flags
 */

// shared
#define FLAG_ACK 0x1
#define FLAG_END_STREAM 0x1
#define FLAG_END_SEGMENT 0x2
#define FLAG_END_HEADERS 0x4
#define FLAG_PAD_LOW 0x8
#define FLAG_PAD_HIGH 0x10

// headers
#define FLAG_PRIORITY 0x20


// data
#define FLAG_COMPRESSED 0x20

/**
 * HTTP errors
 */
enum h2_error_code_e {

  /**
   * The associated condition is not as a result of an error. For example, a
   * GOAWAY might include this code to indicate graceful shutdown of a connection.
   */
  HTTP_ERROR_NO_ERROR,

  /**
   * The endpoint detected an unspecific protocol error. This error is for use
   * when a more specific error code is not available.
   */
  HTTP_ERROR_PROTOCOL_ERROR,

  /**
   * The endpoint encountered an unexpected internal error.
   */
  HTTP_ERROR_INTERNAL_ERROR,

  /**
   * The endpoint detected that its peer violated the flow control protocol.
   */
  HTTP_ERROR_FLOW_CONTROL_ERROR,

  /**
   * The endpoint sent a SETTINGS frame, but did not receive a response in a
   * timely manner. See Settings Synchronization (Section 6.5.3).
   */
  HTTP_ERROR_SETTINGS_TIMEOUT,

  /**
   * The endpoint received a frame after a stream was half closed.
   */
  HTTP_ERROR_STREAM_CLOSED,

  /**
   * The endpoint received a frame that was larger than the maximum size
   * that it supports.
   */
  HTTP_ERROR_FRAME_SIZE_ERROR,

  /**
   * The endpoint refuses the stream prior to performing any application
   * processing, see Section 8.1.4 for details.
   */
  HTTP_ERROR_REFUSED_STREAM,

  /**
   * Used by the endpoint to indicate that the stream is no longer needed.
   */
  HTTP_ERROR_CANCEL,

  /**
   * The endpoint is unable to maintain the compression context for the
   * connection.
   */
  HTTP_ERROR_COMPRESSION_ERROR,

  /**
   * The connection established in response to a CONNECT request (Section 8.3)
   * was reset or abnormally closed.
   */
  HTTP_ERROR_CONNECT_ERROR,

  /**
   * The endpoint detected that its peer is exhibiting a behavior over a given
   * amount of time that has caused it to refuse to process further frames.
   */
  HTTP_ERROR_ENHANCE_YOUR_CALM,

  /**
   * The underlying transport has properties that do not meet the minimum
   * requirements imposed by this document (see Section 9.2) or the endpoint.
   */
  HTTP_ERROR_INADEQUATE_SECURITY

};


#define HTTP_FRAME_FIELDS               \
  /* Length in octets of the frame */   \
  /* 14 bits                       */   \
  uint16_t length;                      \
                                        \
  /* Frame type                    */   \
  /* 8 bits                        */   \
  enum frame_type_e type;               \
                                        \
  /* Frame flags                   */   \
  uint8_t flags;                        \
                                        \
  /* Stream identifier             */   \
  /* 31 bits                       */   \
  uint32_t stream_id;


typedef struct {

  HTTP_FRAME_FIELDS

} http_frame_t;

typedef struct {

  HTTP_FRAME_FIELDS

} http_frame_settings_t;

typedef struct {

  HTTP_FRAME_FIELDS

} http_frame_priority_t;

typedef struct {

  HTTP_FRAME_FIELDS

} http_frame_blocked_t;

typedef struct {

  HTTP_FRAME_FIELDS

  uint32_t error_code;

} http_frame_rst_stream_t;

typedef struct {

  HTTP_FRAME_FIELDS

} http_frame_push_promise_t;

typedef struct {

  HTTP_FRAME_FIELDS

} http_frame_ping_t;

typedef struct {

  HTTP_FRAME_FIELDS

  uint32_t last_stream_id;
  uint32_t error_code;

  uint8_t * debug_data;

} http_frame_goaway_t;

typedef struct {

  HTTP_FRAME_FIELDS

  uint32_t increment;

} http_frame_window_update_t;

typedef struct http_header_fragment_s {

  uint8_t * buffer;
  size_t length;
  struct http_header_fragment_s * next;

} http_header_fragment_t;

typedef struct {

  HTTP_FRAME_FIELDS

  size_t header_block_fragment_size;
  uint8_t * header_block_fragment;

} http_frame_headers_t;

typedef struct {

  HTTP_FRAME_FIELDS

} http_frame_continuation_t;

typedef struct {

  HTTP_FRAME_FIELDS

} http_frame_data_t;

typedef struct http_queued_frame_s {
  struct http_queued_frame_s * next;

  uint8_t * buf;
  size_t buf_length;

  /**
   * The buf may be part of a larger buffer
   * that needs to be free'd.
   * If the buffer should be free'd after the data
   * is sent, this is the point to the full buffer.
   */
  void * buf_begin;

  bool compressed;
  bool continuation;
  bool end_stream;

} http_queued_frame_t;

typedef struct http_stream_t {

  /**
   * Stream identifier
   */
  uint32_t id;

  /**
   * The current state of the stream, one of:
   *
   * idle
   * reserved (local)
   * reserved (remote)
   * open
   * half closed (local)
   * half closed (remote)
   * closed
   *
   */
  enum stream_state_e state;

  bool closing;

  uint32_t priority;

  long outgoing_window_size;
  long incoming_window_size;

  bool can_send_blocked_frame;

  http_header_fragment_t * header_fragments;

  http_queued_frame_t * queued_data_frames;

  multimap_t * headers;

  http_request_t * request;
  http_response_t * response;

  /*
   * If this is a pushed stream, what stream originally
   * opened this
   */
  uint32_t associated_stream_id;

  uint32_t priority_dependency;
  uint8_t priority_weight;
  bool priority_exclusive;

} http_stream_t;

typedef void (*request_cb)(http_request_t * request, http_response_t * response);

typedef void (*data_cb)(http_request_t * request, http_response_t * response, uint8_t * buf, size_t len, bool last,
                        bool free_buf);

typedef bool (*write_cb)(void * data, uint8_t * buf, size_t len);

typedef void (*close_cb)(void * data);

/**
 * Stores state for a client.
 */
typedef struct {
  void * data;
  write_cb writer;
  close_cb closer;
  request_cb request_handler;
  data_cb data_handler;

  /**
   * connection state
   */
  bool received_connection_preface;
  bool received_settings;
  // the next stream id that can be used to start a pushed stream
  size_t current_stream_id;
  // the last stream id that has started processing
  size_t last_stream_id;
  long outgoing_window_size;
  long incoming_window_size;
  // is the connection waiting to be gracefully closed?
  bool closing;
  bool can_send_blocked_frame;

  // the number of streams that are currently opened
  // that the server has initiated
  size_t outgoing_concurrent_streams;
  // the number of streams that are currently opened
  // that the client has initiated
  size_t incoming_concurrent_streams;

  /**
   * what's currently being read
   */
  uint8_t * buffer;
  size_t buffer_length;
  size_t buffer_position;

  binary_buffer_t * write_buffer;

  /**
   * Connection settings
   */
  size_t header_table_size;
  bool enable_push;
  size_t max_concurrent_streams;
  size_t initial_window_size;
  bool enable_compress_data;

  hash_table_t * streams;

  hpack_context_t * encoding_context;
  hpack_context_t * decoding_context;

  gzip_context_t * gzip_context;
} http_connection_t;

http_connection_t * http_connection_init(void * const data, const request_cb request_handler,
    const data_cb data_handler, const write_cb writer, const close_cb closer);

void http_connection_free(http_connection_t * const connection);

void http_connection_read(http_connection_t * const connection, uint8_t * const buffer, const size_t len);

bool http_response_write(http_response_t * const response, uint8_t * data, const size_t data_length, bool last);

bool http_response_write_data(http_response_t * const response, uint8_t * data, const size_t data_length, bool last);

http_request_t * http_push_init(http_request_t * const request);

bool http_push_promise(http_request_t * const request);

http_response_t * http_push_response_get(http_request_t * const request);

#endif
