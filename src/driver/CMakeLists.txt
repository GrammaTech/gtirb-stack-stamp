set(BINARY_NAME gtirb-stack-stamp-driver)

add_executable(${BINARY_NAME} driver.cpp)

target_link_libraries(${BINARY_NAME} ${PROJECT_NAME})

set_target_properties(${BINARY_NAME} PROPERTIES OUTPUT_NAME ${PROJECT_NAME})
