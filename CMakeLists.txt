cmake_minimum_required(VERSION 3.8)
project(co_api)
set(TARGET_NAME "${PROJECT_NAME}")
set(CMAKE_CXX_STANDARD 20)

# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2")

add_subdirectory(${PROJECT_SOURCE_DIR}/contrib)

include_directories(${TARGET_NAME} ${PROJECT_SOURCE_DIR}/include)
include_directories(${TARGET_NAME} ${PROJECT_SOURCE_DIR}/src)
include_directories(${TARGET_NAME} ${PROJECT_SOURCE_DIR}/.)

file(GLOB_RECURSE SOURCE_CORE
        "src/*.h"
        "src/*.hpp"
        "src/*.c"
        "src/*.cpp")

find_package(OpenSSL REQUIRED)
add_executable(${TARGET_NAME} ${SOURCE_CORE})
# specify which libraries to connect
if (UNIX)
  target_link_libraries(${TARGET_NAME} pthread)
endif()

target_link_libraries(${TARGET_NAME} co_async concurrencpp_library ${OPENSSL_LIBRARIES})
