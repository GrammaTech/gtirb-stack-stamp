set(PROJECT_NAME gtirb_stack_stamp)

if((${CMAKE_CXX_COMPILER_ID} STREQUAL GNU) OR (${CMAKE_CXX_COMPILER_ID}
                                                     STREQUAL Clang))
  add_compile_options(-mtune=generic)
  add_compile_options(-pthread)
endif()

# specify source files
file(GLOB ${PROJECT_NAME}_H ${CMAKE_SOURCE_DIR}/include/${PROJECT_NAME}/*.hpp)
file(GLOB ${PROJECT_NAME}_SRC *.cpp)

# specify libraries generated
add_library(${PROJECT_NAME} ${${PROJECT_NAME}_H} ${${PROJECT_NAME}_SRC})

# specify header direcotries
target_include_directories(
  ${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
)

# add dependencies
target_link_libraries(
  ${PROJECT_NAME}
  PUBLIC ${Boost_LIBRARIES}
         ${CAPSTONE}
         ${KEYSTONE}
         gtirb
)

# build driver
add_subdirectory(driver)
