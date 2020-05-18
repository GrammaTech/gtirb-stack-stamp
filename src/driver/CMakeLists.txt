set(BINARY_NAME gtirb-stack-stamp)

add_executable(${BINARY_NAME} driver.cpp)

target_link_libraries(${BINARY_NAME} gtirb_stack_stamp)

if(NOT BUILD_SHARED_LIBS)
  target_link_libraries(${BINARY_NAME} -static-libstdc++)
endif()
