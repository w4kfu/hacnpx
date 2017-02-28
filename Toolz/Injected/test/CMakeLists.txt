include_directories(${CMAKE_SOURCE_DIR}/components/capstone-next/include/capstone/)

add_subdirectory(test-esc/)
add_subdirectory(test-hook/)
#add_subdirectory(test-mpress/)
add_subdirectory(test-pespin/)
add_subdirectory(self-testing/)