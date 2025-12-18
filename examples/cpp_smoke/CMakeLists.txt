cmake_minimum_required(VERSION 3.20)

project(omnisstream_ffi_cpp_smoke LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

get_filename_component(OMNISSTREAM_CORE_ROOT "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)

set(OMNISSTREAM_FFI_INCLUDE_DIR "${OMNISSTREAM_CORE_ROOT}/include")
set(OMNISSTREAM_FFI_LIB "${OMNISSTREAM_CORE_ROOT}/target/release/libomnisstream_ffi.a")

if(NOT EXISTS "${OMNISSTREAM_FFI_LIB}")
  message(FATAL_ERROR "Missing ${OMNISSTREAM_FFI_LIB}. Run: cargo build -p omnisstream_ffi --release")
endif()

add_executable(os_cpp_smoke main.cpp)
target_include_directories(os_cpp_smoke PRIVATE "${OMNISSTREAM_FFI_INCLUDE_DIR}")

find_package(Threads REQUIRED)
target_link_libraries(os_cpp_smoke PRIVATE "${OMNISSTREAM_FFI_LIB}" Threads::Threads dl m)

