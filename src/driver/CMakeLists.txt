SET(PROJECT_NAME gtirbstackstamp)

# Need 3.9 to support CXX_STANDARD=17 and protobuf
cmake_minimum_required(VERSION 3.9.0)

# Use C++17
set(CMAKE_CXX_STANDARD 17)
# Error if it's not available
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Specifically check for gcc-7 or later. gcc-5 is installed on many systems and
# will accept -std=c++17, but does not fully support the standard.
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "7.0.0")
    message(FATAL_ERROR "gcc 7 or later is required to build gtirb_merge")
  endif()
endif()

set(${PROJECT_NAME}_H
  Logger.h
)

set(${PROJECT_NAME}_SRC
  main.cpp
)

# Unix, but not Cygwin.
IF(UNIX AND NOT WIN32)
  SET(SYSLIBS
    dl
    pthread
  )
ELSE()
  SET(SYSLIBS
  )
endif()

# Find to warn the user...
find_program(DEBLOAT_FOUND_DDISASM ddisasm
  HINTS $ENV{PATH}
    DOC "ddisasm is required to be in your PATH for ${PROJECT_NAME} to execute.")
if(NOT DEBLOAT_FOUND_DDISASM)
    message(WARNING "ddisasm was not found in your PATH is required for ${PROJECT_NAME} to properly execute.")
endif()

# build libraries
add_executable(${PROJECT_NAME}
     ${${PROJECT_NAME}_H}
     ${${PROJECT_NAME}_SRC}
  )


# ---------------------------------------------------------------------------
# Boost
# ---------------------------------------------------------------------------
set(BOOST_COMPONENTS filesystem system program_options)
find_package(Boost 1.67 REQUIRED COMPONENTS ${BOOST_COMPONENTS})

add_compile_options(-DBOOST_CONFIG_SUPPRESS_OUTDATED_MESSAGE)
add_compile_options(-DBOOST_SYSTEM_NO_DEPRECATED)

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
# gtirb
# ---------------------------------------------------------------------------

find_package(gtirb REQUIRED)





#include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../src)

set_target_properties(${PROJECT_NAME} PROPERTIES FOLDER "debloat")

target_link_libraries(${PROJECT_NAME}
  ${SYSLIBS}
  gtirb
  ${Boost_LIBRARIES}
  ${LIBCPP_ABI}
)

if(NOT BUILD_SHARED_LIBS)
  target_link_libraries(${PROJECT_NAME} -static-libstdc++)
endif()
