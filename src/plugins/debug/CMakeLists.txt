add_library(debug_plugin SHARED main.c)
if(APPLE)
  set_target_properties(debug_plugin PROPERTIES LINK_FLAGS "-undefined dynamic_lookup")
endif()
