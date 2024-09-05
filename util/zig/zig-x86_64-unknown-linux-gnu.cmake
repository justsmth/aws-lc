set(CMAKE_ASM_COMPILER "${CMAKE_CURRENT_SOURCE_DIR}/util/zig/zig-cc.sh")
set(CMAKE_C_COMPILER "${CMAKE_CURRENT_SOURCE_DIR}/util/zig/zig-cc.sh")
set(CMAKE_CXX_COMPILER "${CMAKE_CURRENT_SOURCE_DIR}/util/zig/zig-c++.sh")

set(CMAKE_SYSTEM_NAME "Darwin")
set(CMAKE_SYSTEM_PROCESSOR "x86_64")
set(CMAKE_OSX_ARCHITECTURES "x86_64")

# See: https://github.com/ziglang/zig/issues/20493
set(CMAKE_SIZEOF_VOID_P 8)