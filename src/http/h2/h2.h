#ifndef H2_H
#define H2_H

#include <stdbool.h>

#include "plugin_callbacks.h"

#include "hash_table.h"
#include "hpack/hpack.h"

#include "http/request.h"
#include "http/response.h"

#include "h2_setting.h"
#include "h2_frame.h"

#define PUSH_ENABLED true

typedef bool (*h2_write_cb)(void * data, uint8_t * buf, size_t len);

typedef void (*h2_close_cb)(void * data);

typedef http_request_t * (*h2_request_init_cb)(void * data, void * user_data, header_list_t * headers);

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
 * Default setting values
 */
#define DEFAULT_HEADER_TABLE_SIZE 4096
#define DEFAULT_ENABLE_PUSH 1
#define DEFAULT_MAX_CONNCURRENT_STREAMS 100
#define DEFAULT_INITIAL_WINDOW_SIZE 65535
#define DEFAULT_MAX_FRAME_SIZE 16384 // 2^14
#define DEFAULT_MAX_HEADER_LIST_SIZE 0 // unlimited

/**
 * HTTP 2 errors
 */
enum h2_error_code_e {

  /**
   * The associated condition is not as a result of an error. For example, a
   * GOAWAY might include this code to indicate graceful shutdown of a connection.
   */
  H2_ERROR_NO_ERROR,

  /**
   * The endpoint detected an unspecific protocol error. This error is for use
   * when a more specific error code is not available.
   */
  H2_ERROR_PROTOCOL_ERROR,

  /**
   * The endpoint encountered an unexpected internal error.
   */
  H2_ERROR_INTERNAL_ERROR,

  /**
   * The endpoint detected that its peer violated the flow control protocol.
   */
  H2_ERROR_FLOW_CONTROL_ERROR,

  /**
   * The endpoint sent a SETTINGS frame, but did not receive a response in a
   * timely manner. See Settings Synchronization (Section 6.5.3).
   */
  H2_ERROR_SETTINGS_TIMEOUT,

  /**
   * The endpoint received a frame after a stream was half closed.
   */
  H2_ERROR_STREAM_CLOSED,

  /**
   * The endpoint received a frame that was larger than the maximum size
   * that it supports.
   */
  H2_ERROR_FRAME_SIZE_ERROR,

  /**
   * The endpoint refuses the stream prior to performing any application
   * processing, see Section 8.1.4 for details.
   */
  H2_ERROR_REFUSED_STREAM,

  /**
   * Used by the endpoint to indicate that the stream is no longer needed.
   */
  H2_ERROR_CANCEL,

  /**
   * The endpoint is unable to maintain the compression context for the
   * connection.
   */
  H2_ERROR_COMPRESSION_ERROR,

  /**
   * The connection established in response to a CONNECT request (Section 8.3)
   * was reset or abnormally closed.
   */
  H2_ERROR_CONNECT_ERROR,

  /**
   * The endpoint detected that its peer is exhibiting a behavior over a given
   * amount of time that has caused it to refuse to process further frames.
   */
  H2_ERROR_ENHANCE_YOUR_CALM,

  /**
   * The underlying transport has properties that do not meet the minimum
   * requirements imposed by this document (see Section 9.2) or the endpoint.
   */
  H2_ERROR_INADEQUATE_SECURITY

};

typedef struct h2_header_fragment_s {

  uint8_t * buffer;
  size_t length;
  struct h2_header_fragment_s * next;

} h2_header_fragment_t;

typedef struct h2_queued_frame_s {
  struct h2_queued_frame_s * next;

  uint8_t * buf;
  size_t buf_length;

  /**
   * The buf may be part of a larger buffer
   * that needs to be free'd.
   * If the buffer should be free'd after the data
   * is sent, this is the point to the full buffer.
   */
  void * buf_begin;

  bool continuation;
  bool end_stream;

} h2_queued_frame_t;

struct h2_t;

typedef struct {

  struct h2_t * h2;

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

  h2_header_fragment_t * header_fragments;

  h2_queued_frame_t * queued_data_frames;

  header_list_t * headers;

  http_request_t * request;
  http_response_t * response;

  /*
   * If this is a pushed stream, what stream originally
   * opened this
   */
  uint32_t associated_stream_id;

  uint32_t priority_stream_dependency;
  uint8_t priority_weight;
  bool priority_exclusive;

} h2_stream_t;

typedef struct h2_t {

  void * data;

  log_context_t * log;

  h2_write_cb writer;
  h2_close_cb closer;
  struct plugin_invoker_t * plugin_invoker;
  h2_request_init_cb request_init;

  /**
   * TLS settings
   */
  const char * tls_version;
  const char * cipher;
  int cipher_key_size_in_bits;

  /**
   * connection state
   */
  bool verified_tls_settings;
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
  bool closed;

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
  bool reading_from_client;

  binary_buffer_t write_buffer;

  /**
   * Connection settings
   */
  size_t header_table_size;
  bool enable_push;
  size_t max_concurrent_streams;
  size_t initial_window_size;
  size_t max_frame_size;
  size_t max_header_list_size;

  hash_table_t * streams;

  hpack_context_t * encoding_context;
  hpack_context_t * decoding_context;

} h2_t;

bool h2_detect_connection(uint8_t * buffer, size_t len);

h2_t * h2_init(void * const data, log_context_t * log, log_context_t * hpack_log, const char * tls_version,
               const char * cipher, int cipher_key_size_in_bits, struct plugin_invoker_t * plugin_invoker,
               const h2_write_cb writer, const h2_close_cb closer, const h2_request_init_cb request_init);

bool h2_settings_apply(h2_t * const h2, char * base64);

bool h2_request_begin(h2_t * const h2, header_list_t * headers, uint8_t * buf, size_t buf_length);

void h2_free(h2_t * const h2);

bool h2_write(const h2_t * const h2, uint8_t * const buf, size_t buf_length);

void h2_read(h2_t * const h2, uint8_t * const buffer, const size_t len);

void h2_eof(h2_t * const h2);

void h2_finished_writes(h2_t * const h2);

bool h2_flush(const h2_t * const h2, size_t new_length);

bool h2_emit_error_and_close(h2_t * const h2, uint32_t stream_id,
                                 enum h2_error_code_e error_code, char * format, ...);

bool h2_response_write(h2_stream_t * stream, http_response_t * const response, uint8_t * data, const size_t data_length,
                       bool last);

bool h2_response_write_data(h2_stream_t * stream, http_response_t * const response, uint8_t * data,
                            const size_t data_length, bool last);

http_request_t * h2_push_init(h2_stream_t * stream, http_request_t * const request);

bool h2_push_promise(h2_stream_t * stream, http_request_t * const request);

http_response_t * h2_push_response_get(h2_stream_t * stream, http_request_t * const request);

/* streams */

h2_stream_t * h2_stream_get(h2_t * const h2, const uint32_t stream_id);

bool h2_stream_closed(h2_t * const h2, const uint32_t stream_id);

#endif
