set(co_async_ROOT_DIR "${PROJECT_SOURCE_DIR}/contrib/co_async")
if(NOT EXISTS "${co_async_ROOT_DIR}/CMakeLists.txt")
  message(FATAL_ERROR " submodule contrib/co_async is missing. To fix try run: \n git submodule update --init --recursive")
endif()

set(BUILD_SHARED_LIBS "FALSE")
add_subdirectory("${co_async_ROOT_DIR}" "${PROJECT_BINARY_DIR}/contrib/co_async")
add_library(co_async_library INTERFACE)

target_link_libraries(co_async_library INTERFACE
  co_async
)

get_target_property(co_async_INCLUDE_DIR co_async INTERFACE_INCLUDE_DIRECTORIES)
target_include_directories (co_async_library SYSTEM BEFORE INTERFACE ${co_async_INCLUDE_DIR})
