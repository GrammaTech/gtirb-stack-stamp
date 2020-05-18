set(PROJECT_NAME gtirb_stack_stamp)

add_compile_options(-mtune=generic)
add_compile_options(-pthread)

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
if(UNIX AND NOT WIN32)
  set(SYSLIBS ${CMAKE_DL_LIBS})
else()
  set(SYSLIBS)
endif()

target_link_libraries(
  ${PROJECT_NAME}
  PUBLIC ${SYSLIBS}
         ${Boost_LIBRARIES}
         ${CAPSTONE}
         ${KEYSTONE}
)

# build driver
add_subdirectory(driver)
