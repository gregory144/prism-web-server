#ifndef HTTP_LOG_H
#define HTTP_LOG_H

#include <stdbool.h>
#include <stdio.h>

#define LOG_BUFFER_LENGTH 4096
static char log_storage[LOG_BUFFER_LENGTH];
#define LOG_BUFFER (log_storage)

enum log_level_e {
  LOG_OFF,
  LOG_TRACE,
  LOG_DEBUG,
  LOG_INFO,
  LOG_WARN,
  LOG_ERROR,
  LOG_FATAL
};

struct log_context_t {
  char * name;
  bool enabled;
  enum log_level_e min_level;
  FILE * file;
  int pid;
};


struct log_context_t * log_context_init(struct log_context_t * cxt, char * name,
    FILE * file, int min_level, bool enabled);

bool log_enabled(struct log_context_t * cxt);

bool log_level_enabled(struct log_context_t * cxt, enum log_level_e level);

void log_append(struct log_context_t * cxt, enum log_level_e level, char * format, ...);

void log_buffer(struct log_context_t * cxt, enum log_level_e level, uint8_t * buffer, size_t length);

enum log_level_e log_level_from_string(const char * s);

#endif
