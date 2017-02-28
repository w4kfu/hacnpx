set(INJECTED_FILES_SRC
    breakpoint.cpp
    dbg.cpp
    disas.cpp
    dump.cpp
    hookstuff.cpp
    iatstuff.cpp
    injected.cpp
    modules.cpp
    memory.cpp
    pestuff.cpp
    utils.cpp)

include_directories(${CMAKE_SOURCE_DIR}/components/capstone-next/include/capstone/)
include_directories(${CMAKE_SOURCE_DIR}/src/include/)

add_library(injected ${INJECTED_FILES_SRC})