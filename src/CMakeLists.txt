add_subdirectory(util)
add_subdirectory(huffman)
add_subdirectory(hpack)
add_subdirectory(http)
add_subdirectory(plugins)

set_source_files_properties(tags PROPERTIES GENERATED true)
add_custom_target(OUTPUT tags
  COMMAND ctags -R .
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

add_executable(prism server_config.c plugin.c tls.c worker.c client.c server.c daemon.c main.c tags)
target_link_libraries(prism http_util http_huffman http_hpack http http_h1_1 http_h2 uv ${OPENSSL_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} ${JEMALLOC_LIBRARIES})

