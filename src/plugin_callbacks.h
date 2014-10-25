#ifndef HTTP_PLUGIN_CALLBACKS_H
#define HTTP_PLUGIN_CALLBACKS_H

enum plugin_callback_e {
  HANDLE_REQUEST,
  HANDLE_DATA,
  POST_CONSTRUCT_FRAME
};

struct plugin_invoker_t;

bool plugin_invoke(struct plugin_invoker_t * invoker, enum plugin_callback_e cb, ...);

#endif
