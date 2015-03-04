if (RUBY_FOUND)
  add_test(NAME test_h1_1 COMMAND ${RUBY_EXECUTABLE} -I${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/h1_1.rb)
  set_tests_properties(test_h1_1 PROPERTIES DEPENDS prism files_plugin debug_plugin)
  set_tests_properties(test_h1_1 PROPERTIES ENVIRONMENT
    "PRISM_EXECUTABLE=$<TARGET_FILE:prism>;FILES_PLUGIN_LIB=$<TARGET_FILE:files_plugin>;DEBUG_PLUGIN_LIB=$<TARGET_FILE:debug_plugin>;HAVE_NGHTTP=${HAVE_NGHTTP}"
  )
endif (RUBY_FOUND)
