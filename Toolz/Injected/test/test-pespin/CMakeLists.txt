include_directories(${CMAKE_SOURCE_DIR}/src/include/)

set(FILES_TEST_SRC test-pespin.cpp)

add_library(test-pespin SHARED ${FILES_TEST_SRC})

target_link_libraries(test-pespin injected ${LINK_LIBS})