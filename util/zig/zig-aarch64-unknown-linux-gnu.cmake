set(CMAKE_ASM_COMPILER "${CMAKE_CURRENT_SOURCE_DIR}/util/zig/zig-cc.sh")
set(CMAKE_C_COMPILER "${CMAKE_CURRENT_SOURCE_DIR}/util/zig/zig-cc.sh")
set(CMAKE_CXX_COMPILER "${CMAKE_CURRENT_SOURCE_DIR}/util/zig/zig-c++.sh")

set(CMAKE_SYSTEM_NAME "Linux")
set(CMAKE_SYSTEM_PROCESSOR "aarch64")

# See: https://github.com/ziglang/zig/issues/20493
set(CMAKE_SIZEOF_VOID_P 8)
# See: https://github.com/ziglang/zig/issues/10411
set(CMAKE_C_FLAGS "-D__ARM_NEON=1 -D__ARM_FEATURE_AES=1 -D__ARM_FEATURE_SHA2=1")
