# OmnisStream FFI: CMake

## Build the Rust static library

```sh
cargo build -p omnisstream_ffi --release
```

## Link from C/C++

```cmake
set(OMNISSTREAM_CORE_ROOT "/path/to/OmnisStream-Core")

set(OMNISSTREAM_FFI_INCLUDE_DIR "${OMNISSTREAM_CORE_ROOT}/include")
set(OMNISSTREAM_FFI_LIB "${OMNISSTREAM_CORE_ROOT}/target/release/libomnisstream_ffi.a")

add_executable(my_app main.cpp)
target_include_directories(my_app PRIVATE "${OMNISSTREAM_FFI_INCLUDE_DIR}")

find_package(Threads REQUIRED)
target_link_libraries(my_app PRIVATE "${OMNISSTREAM_FFI_LIB}" Threads::Threads dl m)
```

## Regenerate the header

```sh
cargo run -p omnisstream_ffi --features header-gen --bin omnisstream_ffi_header
```

