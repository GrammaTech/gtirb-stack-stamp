SET(PROJECT_NAME gtirbstackstamp)

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

#include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../src)

set_target_properties(${PROJECT_NAME} PROPERTIES FOLDER "debloat")

target_link_libraries(${PROJECT_NAME}
  ${SYSLIBS}
  #gtirbToSwyxHints
  ${Boost_LIBRARIES}
  ${LIBCPP_ABI}
)

if(NOT BUILD_SHARED_LIBS)
  target_link_libraries(${PROJECT_NAME} -static-libstdc++)
endif()
