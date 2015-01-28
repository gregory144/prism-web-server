add_library(http_hpack header_list.c circular_buffer.c hpack.c)
target_link_libraries(http_hpack http_util http_huffman ${CMAKE_THREAD_LIBS_INIT})

add_executable(check_hpack check_hpack.c)
target_link_libraries(check_hpack http_util http_huffman ${TEST_LIBS})
add_test(check_hpack ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/check_hpack)
