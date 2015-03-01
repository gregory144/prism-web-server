cmake_minimum_required(VERSION 2.8.9)
project(prism C)

# Point CMake at any custom modules we may ship
list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")
include(CheckFunctionExists)

set(PROJECT_NAME prism)
set(PROJECT_VERSION_MAJOR 0)
set(PROJECT_VERSION_MINOR 0)
set(PROJECT_VERSION_PATCH 2)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_GNU_SOURCE")
add_definitions(-std=c99)

include(CTest)
enable_testing()
find_program(CTEST_MEMORYCHECK_COMMAND valgrind)
set(CTEST_MEMORYCHECK_COMMAND_OPTIONS "--trace-children=yes --leak-check=full --track-origins=yes")
set(CTEST_MEMORYCHECK_SUPPRESSIONS_FILE "${PROJECT_SOURCE_DIR}/valgrind.supp")

include_directories(SYSTEM ${_INCLUDE_DIRS})

find_package(Check REQUIRED)
include_directories(${CHECK_INCLUDE_DIRS})
set(TEST_LIBS m pthread ${CHECK_LIBRARIES})

find_package(Threads REQUIRED)
find_package(LibUV REQUIRED)
include_directories(SYSTEM ${LIBUV_INCLUDE_DIRS})

find_package(OpenSSL REQUIRED)
include_directories(SYSTEM ${OPENSSL_INCLUDE_DIR})
list(APPEND CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
list(APPEND CMAKE_REQUIRED_LIBRARIES ${OPENSSL_LIBRARIES})
CHECK_SYMBOL_EXISTS(SSL_CTX_set_alpn_select_cb openssl/ssl.h HAVE_ALPN)
list(REMOVE_ITEM CMAKE_REQUIRED_LIBRARIES ${OPENSSL_LIBRARIES})
list(REMOVE_ITEM CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})

# using JeMalloc doesn't work with valgrind without extra configuration
# find_package(JeMalloc)

include_directories(${CMAKE_BINARY_DIR})
include_directories(src)
include_directories(src/util)

find_program(FOUND_GIT git)

if (FOUND_GIT)

  # Get the current working branch
  execute_process(
    COMMAND git rev-parse --abbrev-ref HEAD
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_BRANCH
    OUTPUT_STRIP_TRAILING_WHITESPACE
    )

  # Get the latest abbreviated commit hash of the working branch
  execute_process(
    COMMAND git log -1 --format=%h
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_COMMIT_HASH
    OUTPUT_STRIP_TRAILING_WHITESPACE
    )

endif(FOUND_GIT)

string(TIMESTAMP BUILD_TIMESTAMP UTC)

# configure a header file to pass some of the CMake settings
# to the source code
configure_file (
  "${PROJECT_SOURCE_DIR}/config.h.in"
  "${CMAKE_BINARY_DIR}/config.h"
  )

add_subdirectory(src)
add_subdirectory(docs)

