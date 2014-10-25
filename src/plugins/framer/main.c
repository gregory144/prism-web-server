#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <inttypes.h>

#include <uv.h>

#include "server.h"
#include "plugin.h"

#include "log.h"
#include "util.h"
#include "http/http.h"
#include "http/h2/h2.h"
#include "http/request.h"

static void framer_plugin_start(plugin_t * plugin)
{
  log_append(plugin->log, LOG_INFO, "framer plugin started");
}

static void framer_plugin_stop(plugin_t * plugin)
{
  log_append(plugin->log, LOG_INFO, "framer plugin stopped");
}

char * frame_type_to_string(enum frame_type_e t)
{
  switch (t) {
    case FRAME_TYPE_DATA:
      return "DATA";
    case FRAME_TYPE_HEADERS:
      return "HEADERS";
    case FRAME_TYPE_PRIORITY:
      return "PRIORITY";
    case FRAME_TYPE_RST_STREAM:
      return "RST_STREAM";
    case FRAME_TYPE_SETTINGS:
      return "SETTINGS";
    case FRAME_TYPE_PUSH_PROMISE:
      return "PUSH_PROMISE";
    case FRAME_TYPE_PING:
      return "PING";
    case FRAME_TYPE_GOAWAY:
      return "GOAWAY";
    case FRAME_TYPE_WINDOW_UPDATE:
      return "WINDOW_UPDATE";
    case FRAME_TYPE_CONTINUATION:
      return "CONTINUATION";
  }
  return "UNKNOWN";

}

static void framer_plugin_preprocess_incoming_frame(plugin_t * plugin, client_t * client,
    h2_frame_t * frame)
{
  log_append(plugin->log, LOG_INFO, "RECEIVED FRAME %s [client: %" PRIu64 ", length: %" PRIu16
      ", stream id: %" PRIu32 "]",
      frame_type_to_string(frame->type), client->id, frame->length, frame->stream_id
  );
}

static bool framer_plugin_handler(plugin_t * plugin, client_t * client, enum plugin_callback_e cb, va_list args)
{
  switch (cb) {
    case PREPROCESS_INCOMING_FRAME:
    {
      h2_frame_t * frame = va_arg(args, h2_frame_t *);
      framer_plugin_preprocess_incoming_frame(plugin, client, frame);
      return false;
    }
    default:
      return false;
  }
}

void plugin_initialize(plugin_t * plugin, server_t * server)
{
  UNUSED(server);

  plugin->handlers->start = framer_plugin_start;
  plugin->handlers->stop = framer_plugin_stop;
  plugin->handlers->handle = framer_plugin_handler;
}

