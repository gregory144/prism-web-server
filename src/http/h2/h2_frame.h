#ifndef H2_FRAME_H
#define H2_FRAME_H

#include <stdbool.h>

#include "hash_table.h"
#include "hpack/hpack.h"

#include "http/request.h"
#include "http/response.h"

#include "h2_setting.h"

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
  FRAME_TYPE_CONTINUATION
};

#define FRAME_HEADER_SIZE 9 // octets
#define SETTING_ID_SIZE 2
#define SETTING_VALUE_SIZE 4
#define SETTING_SIZE (SETTING_ID_SIZE + SETTING_VALUE_SIZE)

#define PING_OPAQUE_DATA_LENGTH 8

#define FRAME_TYPE_MIN FRAME_TYPE_DATA
#define FRAME_TYPE_MAX FRAME_TYPE_CONTINUATION

/**
 * Frame flags
 */

// shared
#define FLAG_ACK 0x1
#define FLAG_END_STREAM 0x1
#define FLAG_END_SEGMENT 0x2
#define FLAG_END_HEADERS 0x4
#define FLAG_PADDED 0x8

#define FRAME_FLAG(frame, mask) \
  h2_frame_flag_get((h2_frame_t *) frame, mask)

// headers
#define FLAG_PRIORITY 0x20

#define H2_FRAME_FIELDS                 \
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

  H2_FRAME_FIELDS

} h2_frame_t;

typedef struct {

  H2_FRAME_FIELDS

  size_t num_settings;

  h2_setting_t settings[6];

} h2_frame_settings_t;

typedef struct {

  H2_FRAME_FIELDS

  bool priority_exclusive;
  uint32_t priority_stream_dependency;
  // This is a value from 0 - 255.
  // The priority weight is usually refered to as a value
  // from 1 - 256. We may need to add 1 to this value when using it.
  uint8_t priority_weight;

} h2_frame_priority_t;

typedef struct {

  H2_FRAME_FIELDS

  uint32_t error_code;

} h2_frame_rst_stream_t;

typedef struct {

  H2_FRAME_FIELDS

  /**
   * See the note about padding lengths in the definition of h2_frame_data_t
   */
  size_t padding_length;

  uint32_t promised_stream_id;

  uint8_t * header_block_fragment;
  uint16_t header_block_fragment_length;

} h2_frame_push_promise_t;

typedef struct {

  H2_FRAME_FIELDS

  uint8_t * opaque_data;

} h2_frame_ping_t;

typedef struct {

  H2_FRAME_FIELDS

  uint32_t last_stream_id;
  uint32_t error_code;

  uint8_t * debug_data;
  size_t debug_data_length;

} h2_frame_goaway_t;

typedef struct {

  H2_FRAME_FIELDS

  uint32_t increment;

} h2_frame_window_update_t;

typedef struct {

  H2_FRAME_FIELDS

  uint8_t * header_block_fragment;
  uint16_t header_block_fragment_length;

} h2_frame_continuation_t;

typedef struct {

  H2_FRAME_FIELDS

  /**
   * There are 2 potential values that this could represent:
   * 1. The value transmitted over the wire in the padding length field
   * 2. The "actual" amount of padding in this frame, which is:
   *    transmitted value + 1
   *
   * Since the padding length field takes up one byte itself, there is
   * always an extra octet of padding.
   *
   * This value represents the transmitted value.
   *
   */
  uint8_t padding_length;

  uint8_t * payload;
  uint16_t payload_length;

} h2_frame_data_t;

typedef struct {

  H2_FRAME_FIELDS

  /**
   * See the note about padding lengths in the definition of h2_frame_data_t
   */
  size_t padding_length;

  bool priority_exclusive;
  uint32_t priority_stream_dependency;
  // This is a value from 0 - 255.
  // The priority weight is usually refered to as a value
  // from 1 - 256. We may need to add 1 to this value when using it.
  uint8_t priority_weight;

  uint8_t * header_block_fragment;
  uint16_t header_block_fragment_length;

} h2_frame_headers_t;

struct h2_t;

h2_frame_t * h2_frame_init(const struct h2_t * const h2, const uint32_t length, const uint8_t type,
                                  const uint8_t flags, const uint32_t stream_id);

void h2_frame_free(h2_frame_t * frame);

bool h2_frame_flag_get(const h2_frame_t * const frame, int mask);

bool h2_frame_emit(const struct h2_t * const h2, h2_frame_t * frame);

bool h2_frame_is_valid_frame_type(enum frame_type_e frame_type);

bool h2_frame_is_valid(struct h2_t * const h2, h2_frame_t * frame);

bool h2_frame_parse_data(struct h2_t * const h2, h2_frame_data_t * const frame);

bool h2_frame_parse_headers(struct h2_t * const h2, h2_frame_headers_t * const frame);

bool h2_frame_parse_settings(struct h2_t * const h2, h2_frame_settings_t * const frame);

bool h2_frame_parse_ping(struct h2_t * const h2, h2_frame_ping_t * const frame);

bool h2_frame_parse_window_update(struct h2_t * const h2, h2_frame_window_update_t * const frame);

bool h2_frame_parse_rst_stream(struct h2_t * const h2, h2_frame_rst_stream_t * const frame);

bool h2_frame_parse_priority(struct h2_t * const h2, h2_frame_priority_t * const frame);

bool h2_frame_parse_goaway(struct h2_t * const h2, h2_frame_goaway_t * const frame);

bool h2_frame_parse_continuation(struct h2_t * const h2, h2_frame_continuation_t * const frame);

bool h2_parse_settings_payload(struct h2_t * const h2, uint8_t * buffer, size_t buffer_length,
    size_t * num_settings, h2_setting_t * settings);

#endif
