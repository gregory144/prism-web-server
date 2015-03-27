add_library(framer_plugin SHARED main.c)
if(APPLE)
  set_target_properties(framer_plugin PROPERTIES LINK_FLAGS "-undefined dynamic_lookup")
endif()
