# Need 3.10 to support CXX_STANDARD=17
cmake_minimum_required(VERSION 3.10.0)
project(gtirb-stack-stamp)

include(CheckFunctionExists)
include(CheckCXXSourceCompiles)
include(CheckIncludeFile)

# ---------------------------------------------------------------------------
# Build options
# ---------------------------------------------------------------------------

option(GTIRB_STACK_STAMP_ENABLE_TESTS "Enable building and running unit tests." ON)

# This just sets the builtin BUILD_SHARED_LIBS, but if defaults to ON instead of
# OFF.
option(GTIRB_STACK_STAMP_BUILD_SHARED_LIBS "Build shared libraries." ON)
if(GTIRB_STACK_STAMP_BUILD_SHARED_LIBS)
  set(BUILD_SHARED_LIBS ON)
else()
  set(BUILD_SHARED_LIBS OFF)
endif()
if(UNIX AND NOT BUILD_SHARED_LIBS)
  # Find only static libraries
  set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
  add_compile_options(-static)
endif()

if(GTIRB_STACK_STAMP_ENABLE_TESTS)
enable_testing()
endif()

# ---------------------------------------------------------------------------
# Global settings
# ---------------------------------------------------------------------------

set_property(GLOBAL PROPERTY USE_FOLDERS ON)
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/src)
if(WIN32)
  set(CMAKE_DEBUG_POSTFIX
      "d"
      CACHE STRING "add a postfix, usually d on windows"
  )
endif()
set(CMAKE_RELEASE_POSTFIX
    ""
    CACHE STRING "add a postfix, usually empty on windows"
)
set(CMAKE_RELWITHDEBINFO_POSTFIX
    ""
    CACHE STRING "add a postfix, usually empty on windows"
)
set(CMAKE_MINSIZEREL_POSTFIX
    ""
    CACHE STRING "add a postfix, usually empty on windows"
)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Use C++17
set(CMAKE_CXX_STANDARD 17)
# Error if it's not available
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Specifically check for gcc-7 or later. gcc-5 is installed on many systems
# and will accept -std=c++17, but does not fully support the standard.
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "7.0.0")
    message(FATAL_ERROR "gcc 7 or later is required to build gtirb")
endif()
endif()

#
# Global Options (Compile / Link)
#
if((${CMAKE_CXX_COMPILER_ID} STREQUAL GNU) OR (${CMAKE_CXX_COMPILER_ID}
                                                     STREQUAL Clang))
  add_compile_options(-Wall -Wextra -Wpointer-arith -Wshadow -Werror)
  add_compile_options(-fPIC)
endif()

# ---------------------------------------------------------------------------
# Boost
# ---------------------------------------------------------------------------
set(BOOST_COMPONENTS filesystem program_options system)
find_package(Boost 1.67 REQUIRED COMPONENTS ${BOOST_COMPONENTS})

add_definitions(-DBOOST_MULTI_INDEX_DISABLE_SERIALIZATION)
add_definitions(-DBOOST_CONFIG_SUPPRESS_OUTDATED_MESSAGE)
add_definitions(-DBOOST_SYSTEM_NO_DEPRECATED)

# Boost versions 1.70.0+ may use Boost's provided CMake support rather than
# CMake's internal Boost support. The former uses "Boost::boost" and so on,
# while the latter uses "Boost_BOOST" and so on. This normalizes the two cases
# to use Boost_INCLUDE_DIRS and Boost_LIBRARIES.
if(TARGET Boost::headers)
  get_target_property(Boost_INCLUDE_DIRS Boost::headers
                      INTERFACE_INCLUDE_DIRECTORIES)
  foreach(BOOST_COMPONENT ${BOOST_COMPONENTS})
    list(APPEND Boost_LIBRARIES Boost::${BOOST_COMPONENT})
  endforeach()
endif()

include_directories(${Boost_INCLUDE_DIRS})

# ---------------------------------------------------------------------------
# Google Test Application
# ---------------------------------------------------------------------------
if(GTIRB_STACK_STAMP_ENABLE_TESTS)
  # Pull in Google Test
  # https://github.com/google/googletest/tree/master/googletest#incorporating-
  # into-an-existing-cmake-project

  # Download and unpack googletest at configure time
  configure_file(CMakeLists.googletest googletest-download/CMakeLists.txt)

  execute_process(
    COMMAND "${CMAKE_COMMAND}" -G "${CMAKE_GENERATOR}" .
    RESULT_VARIABLE result
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/googletest-download"
  )

  if(result)
    message(WARNING "CMake step for googletest failed: ${result}")
  endif()

  execute_process(
    COMMAND "${CMAKE_COMMAND}" --build .
    RESULT_VARIABLE result
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/googletest-download"
  )

  if(result)
    message(WARNING "Build step for googletest failed: ${result}")
  endif()

  # Prevent overriding the parent project's compiler/linker settings on Windows
  set(gtest_force_shared_crt
      ON
      CACHE BOOL "" FORCE
  )

  # Add googletest directly to our build. This defines the gtest and gtest_main
  # targets.
  add_subdirectory(
    "${CMAKE_BINARY_DIR}/googletest-src" "${CMAKE_BINARY_DIR}/googletest-build"
    EXCLUDE_FROM_ALL
  )

  include_directories("${gtest_SOURCE_DIR}/include")
endif()

# ---------------------------------------------------------------------------
# Capstone and Keystone
# ---------------------------------------------------------------------------
if(BUILD_SHARED_LIBS)
  find_library(CAPSTONE NAMES capstone)
  find_library(KEYSTONE NAMES keystone)
  if(${CMAKE_CXX_COMPILER_ID} STREQUAL MSVC)
    include_directories(SYSTEM ${CAPSTONE}/../include ${KEYSTONE}/../include)
  endif()
else()
  find_library(CAPSTONE NAMES libcapstone.a)
  find_library(KEYSTONE NAMES libkeystone.a)
  if(${CMAKE_CXX_COMPILER_ID} STREQUAL MSVC)
    include_directories(SYSTEM ${CAPSTONE}/../include ${KEYSTONE}/../include)
  endif()
endif()

# ---------------------------------------------------------------------------
# gtirb
# ---------------------------------------------------------------------------
find_package(gtirb REQUIRED)

# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------
add_subdirectory(src)

if(GTIRB_STACK_STAMP_ENABLE_TESTS)
  add_subdirectory(tests)
endif()
