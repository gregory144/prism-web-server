#ifndef HTTP_LOG_H
#define HTTP_LOG_H

#include <stdbool.h>
#include <stdio.h>

enum log_level_e {
  LOG_FATAL,
  LOG_ERROR,
  LOG_WARN,
  LOG_INFO,
  LOG_DEBUG,
  LOG_TRACE
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

#endif
