set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2")

file(GLOB_RECURSE SOURCE_CORE
        "src/*.h"
        "src/*.hpp"
        "src/*.c"
        "src/*.cpp")

set(COMPILE_DEFINITIONS)

################### MAIN ###################

add_library(bearssl STATIC ${SOURCE_CORE})
include_directories(${TARGET_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/inc)
include_directories(${TARGET_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/src)

target_include_directories(bearssl
  PRIVATE
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/inc>"
  PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/inc>")
