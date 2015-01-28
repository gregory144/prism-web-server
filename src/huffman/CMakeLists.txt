add_library(http_huffman huffman.c)
target_link_libraries(http_huffman http_util ${CMAKE_THREAD_LIBS_INIT})

add_executable(huffman main.c)
target_link_libraries(huffman http_util http_huffman ${CMAKE_THREAD_LIBS_INIT})

add_executable(check_huffman check_huffman.c)
target_link_libraries(check_huffman http_util ${TEST_LIBS})
add_test(check_huffman ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/check_huffman)
