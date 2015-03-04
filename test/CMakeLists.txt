if (RUBY_FOUND)
  add_test(NAME test_end_to_end COMMAND ${RUBY_EXECUTABLE} -I${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/harness.rb)
  set_tests_properties(test_end_to_end PROPERTIES DEPENDS prism files_plugin debug_plugin)
  set_tests_properties(test_end_to_end PROPERTIES ENVIRONMENT
    "PRISM_EXECUTABLE=$<TARGET_FILE:prism>;FILES_PLUGIN_LIB=$<TARGET_FILE:files_plugin>;DEBUG_PLUGIN_LIB=$<TARGET_FILE:debug_plugin>;FOUND_NGHTTP=${FOUND_NGHTTP}"
  )
endif (RUBY_FOUND)
