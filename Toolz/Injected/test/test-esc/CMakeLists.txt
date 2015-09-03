include_directories(${CMAKE_SOURCE_DIR}/src/include/)

set(FILES_TEST_SRC test-esc.cpp)

add_library(test-esc SHARED ${FILES_TEST_SRC})

target_link_libraries(test-esc injected ${LINK_LIBS})