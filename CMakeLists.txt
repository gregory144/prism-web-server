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

# configure a header file to pass some of the CMake settings
# to the source code
configure_file (
  "${PROJECT_SOURCE_DIR}/config.h.in"
  "${CMAKE_BINARY_DIR}/config.h"
  )

enable_testing()

include_directories(SYSTEM ${_INCLUDE_DIRS})

find_package(Check REQUIRED)
include_directories(${CHECK_INCLUDE_DIRS})
set(TEST_LIBS m pthread ${CHECK_LIBRARIES})

find_package(Threads REQUIRED)
find_package(LibUV REQUIRED)
include_directories(SYSTEM ${LIBUV_INCLUDE_DIRS})

find_package(OpenSSL REQUIRED)
include_directories(SYSTEM ${OPENSSL_ROOT_DIR/include})
CHECK_FUNCTION_EXISTS(SSL_CTX_set_alpn_select_cb HAVE_ALPN)

include_directories(${CMAKE_BINARY_DIR})
include_directories(src)
include_directories(src/util)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_GNU_SOURCE")
add_definitions(-std=c99)

add_subdirectory(src)
add_subdirectory(docs)

