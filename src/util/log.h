#ifndef HTTP_LOG_H
#define HTTP_LOG_H

#include <stdbool.h>
#include <stdio.h>

enum log_level_e {
  LOG_OFF,
  LOG_TRACE,
  LOG_DEBUG,
  LOG_INFO,
  LOG_WARN,
  LOG_ERROR,
  LOG_FATAL
};

typedef struct {
  char * name;
  bool enabled;
  enum log_level_e min_level;
  FILE * fp;
} log_context_t;

log_context_t * log_context_init(log_context_t * cxt, char * name, FILE * fp, int min_level, bool enabled);

bool log_enabled(log_context_t * cxt);

bool log_level_enabled(log_context_t * cxt, enum log_level_e level);

void log_append(log_context_t * cxt, enum log_level_e level, char * format, ...);

void log_buffer(log_context_t * cxt, enum log_level_e level, uint8_t * buffer, size_t length);

enum log_level_e log_level_from_string(char * s);

#endif
