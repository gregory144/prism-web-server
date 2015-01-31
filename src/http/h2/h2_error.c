#include "h2_error.h"

static const char * const H2_ERRORS[] = {
  "NO_ERROR",
  "PROTOCOL_ERROR",
  "INTERNAL_ERROR",
  "FLOW_CONTROL_ERROR",
  "SETTINGS_TIMEOUT",
  "STREAM_CLOSED",
  "FRAME_SIZE_ERROR",
  "REFUSED_STREAM",
  "CANCEL",
  "COMPRESSION_ERROR",
  "CONNECT_ERROR",
  "ENHANCE_YOUR_CALM",
  "INADEQUATE_SECURITY",
  "HTTP_1_1_REQUIRED"
};

const char * h2_error_to_string(enum h2_error_code_e code) {
  return H2_ERRORS[code];
}

