#ifndef H2_SETTING_H
#define H2_SETTING_H

/**
 * Connection setting identifiers
 */
enum settings_e {
  SETTINGS_HEADER_TABLE_SIZE = 1,
  SETTINGS_ENABLE_PUSH,
  SETTINGS_MAX_CONCURRENT_STREAMS,
  SETTINGS_INITIAL_WINDOW_SIZE,
  SETTINGS_MAX_FRAME_SIZE,
  SETTINGS_MAX_HEADER_LIST_SIZE
};

typedef struct {

  enum settings_e id;
  uint32_t value;

} h2_setting_t;

#endif
