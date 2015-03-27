cmake_minimum_required(VERSION 2.8.7)
project(prism C)

# Point CMake at any custom modules we may ship
list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")
include(CheckSymbolExists)
include(CheckLibraryExists)

set(PROJECT_NAME prism)
set(PROJECT_VERSION_MAJOR 0)
set(PROJECT_VERSION_MINOR 0)
set(PROJECT_VERSION_PATCH 2)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set(MEMORYCHECK_COMMAND_OPTIONS "--tool=memcheck --trace-children=yes --leak-check=full --num-callers=50" CACHE STRING "")
set(MEMORYCHECK_SUPPRESSIONS_FILE ${PROJECT_SOURCE_DIR}/valgrind.supp CACHE STRING "")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_GNU_SOURCE")
add_definitions(-std=c99)

include_directories(SYSTEM ${_INCLUDE_DIRS})

check_library_exists(rt clock_gettime "time.h" HAVE_LIBRT)

find_package(Check REQUIRED)
include_directories(${CHECK_INCLUDE_DIRS})
set(TEST_LIBS m pthread ${CHECK_LIBRARIES})
if(HAVE_LIBRT)
  list(APPEND TEST_LIBS rt)
endif()
check_symbol_exists(ck_assert_uint_eq check.h HAVE_UINT_ASSERTS)

find_package(Threads REQUIRED)
find_package(LibUV REQUIRED)
include_directories(SYSTEM ${LIBUV_INCLUDE_DIRS})

find_package(OpenSSL REQUIRED)
include_directories(SYSTEM ${OPENSSL_INCLUDE_DIR})
list(APPEND CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
list(APPEND CMAKE_REQUIRED_LIBRARIES ${OPENSSL_LIBRARIES})
check_symbol_exists(SSL_CTX_set_alpn_select_cb openssl/ssl.h HAVE_ALPN)
list(REMOVE_ITEM CMAKE_REQUIRED_LIBRARIES ${OPENSSL_LIBRARIES})
list(REMOVE_ITEM CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})

find_package(Jansson)

# for end to end tests
find_package(Ruby)
find_program(FOUND_NGHTTP nghttp)

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

# this only works in cmake 2.8.11 and above
#string(TIMESTAMP BUILD_TIMESTAMP UTC)
# so use the primitive version
execute_process(COMMAND date -u +"%Y-%m-%dT%H:%M:%SZ" OUTPUT_VARIABLE BUILD_TIMESTAMP_RAW)
string(STRIP ${BUILD_TIMESTAMP_RAW} BUILD_TIMESTAMP)

include(CTest)
find_program(CTEST_MEMORYCHECK_COMMAND valgrind)

if(APPLE)
  set(CMAKE_MACOSX_RPATH ON)
  set(CMAKE_SKIP_BUILD_RPATH FALSE)
  set(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
  set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")
  set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
  list(FIND CMAKE_PLATFORM_IMPLICIT_LINK_DIRECTORIES "${CMAKE_INSTALL_PREFIX}/lib" isSystemDir)
  if("${isSystemDir}" STREQUAL "-1")
    set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")
  endif()
endif()

include(CTest)
find_program(CTEST_MEMORYCHECK_COMMAND valgrind)

# configure a header file to pass some of the CMake settings
# to the source code
configure_file (
  "${PROJECT_SOURCE_DIR}/config.h.in"
  "${CMAKE_BINARY_DIR}/config.h"
  )

add_subdirectory(src)
add_subdirectory(test)
add_subdirectory(docs)

