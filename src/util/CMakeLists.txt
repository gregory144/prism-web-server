add_library(http_util log.c util.c base64url.c multimap.c binary_buffer.c hash_table.c blocking_queue.c atomic_int.c)
target_link_libraries(http_util ${CMAKE_THREAD_LIBS_INIT})

add_executable(check_util check_util.c)
target_link_libraries(check_util ${TEST_LIBS})
add_test(check_util ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/check_util)

add_executable(check_multimap check_multimap.c)
target_link_libraries(check_multimap ${TEST_LIBS})
add_test(check_multimap ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/check_multimap)

add_executable(check_binary_buffer check_binary_buffer.c)
target_link_libraries(check_binary_buffer ${TEST_LIBS})
add_test(check_binary_buffer ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/check_binary_buffer)

add_executable(check_hash_table check_hash_table.c)
target_link_libraries(check_hash_table ${TEST_LIBS})
add_test(check_hash_table ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/check_hash_table)

add_executable(check_priority_queue check_priority_queue.c)
target_link_libraries(check_priority_queue ${TEST_LIBS})
add_test(check_priority_queue ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/check_priority_queue)

add_executable(check_blocking_queue check_blocking_queue.c)
target_link_libraries(check_blocking_queue uv ${TEST_LIBS})
add_test(check_blocking_queue ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/check_blocking_queue)

add_executable(check_base64url binary_buffer.c util.c check_base64url.c)
target_link_libraries(check_base64url ${TEST_LIBS})
add_test(check_base64url ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/check_base64url)
