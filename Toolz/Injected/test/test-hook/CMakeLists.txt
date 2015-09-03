include_directories(${CMAKE_SOURCE_DIR}/src/include/)

set(FILES_TEST_SRC test-hook.cpp)

add_library(test-hook SHARED ${FILES_TEST_SRC})

target_link_libraries(test-hook injected ${LINK_LIBS})