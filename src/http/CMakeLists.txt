add_subdirectory(h1_1)
add_subdirectory(h2)

add_library(http request.c response.c http.c)
target_link_libraries(http http_util http_hpack http_huffman http_h1_1 http_h2)

add_executable(check_request check_request.c)
target_link_libraries(check_request http_util http_hpack ${TEST_LIBS})
add_test(check_request ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/check_request)
