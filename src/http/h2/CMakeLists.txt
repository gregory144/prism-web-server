add_library(http_h2 h2_error.c h2_frame.c h2.c)
target_link_libraries(http_h2 http_hpack)

add_executable(check_h2_frame check_h2_frame.c)
target_link_libraries(check_h2_frame http_util http_huffman http_hpack uv ${TEST_LIBS})
add_test(check_h2_frame ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/check_h2_frame)

find_package(BISON)
find_package(FLEX)

include_directories(.)
BISON_TARGET(h2_test_cmd_parser h2_test_cmd_parser.y ${CMAKE_CURRENT_BINARY_DIR}/h2_test_cmd_parser.c)
FLEX_TARGET(h2_test_cmd_scanner h2_test_cmd_scanner.l ${CMAKE_CURRENT_BINARY_DIR}/h2_test_cmd_scanner.c
  COMPILE_FLAGS --header-file=${CMAKE_CURRENT_BINARY_DIR}/h2_test_cmd_scanner.h
  )
ADD_FLEX_BISON_DEPENDENCY(h2_test_cmd_scanner h2_test_cmd_parser)
include_directories(${CMAKE_CURRENT_BINARY_DIR})
add_library(http_h2_test_cmd h2_test_cmd.c ${BISON_h2_test_cmd_parser_OUTPUTS} ${FLEX_h2_test_cmd_scanner_OUTPUTS})
target_link_libraries(http_h2_test_cmd ${FLEX_LIBRARIES} ${BISON_LIBRARIES})

add_executable(check_h2 check_h2.c)
set_source_files_properties(check_h2.c PROPERTIES COMPILE_FLAGS -DH2_TEST_FILES_DIR=\\"${CMAKE_CURRENT_SOURCE_DIR}/tests\\")
target_link_libraries(check_h2 http_util http_hpack http http_h2_test_cmd uv ${FLEX_LIBRARIES} ${BISON_LIBRARIES} ${TEST_LIBS})
add_test(check_h2 ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/check_h2)
