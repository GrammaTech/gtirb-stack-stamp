set(PROJECT_NAME test-gtirb-stack-stamp)

include_directories(${GTEST_INCLUDE_DIRS})

add_compile_options(-DDEBUG)
add_compile_options(-fpermissive)
add_compile_options(-mtune=generic)
add_compile_options(-pthread)

add_executable(${PROJECT_NAME} test_stack_stamp.cpp)

target_link_libraries(
  ${PROJECT_NAME} gtest gtest_main gtirb_stack_stamp
)

add_test(NAME ${PROJECT_NAME} COMMAND $<TARGET_FILE:${PROJECT_NAME}>)
