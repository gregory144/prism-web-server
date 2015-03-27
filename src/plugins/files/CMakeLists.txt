add_library(files_plugin SHARED main.c)
if(APPLE)
  set_target_properties(files_plugin PROPERTIES LINK_FLAGS "-undefined dynamic_lookup")
endif()
