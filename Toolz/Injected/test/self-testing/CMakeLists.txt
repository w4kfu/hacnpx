include_directories(${CMAKE_SOURCE_DIR}/src/include/)

set(FILES_TEST_SRC injected_test.cpp)

add_executable(injected_test ${FILES_TEST_SRC})

target_link_libraries(injected_test injected ${LINK_LIBS})