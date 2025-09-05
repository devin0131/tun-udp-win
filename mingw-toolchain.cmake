# mingw-toolchain.cmake
# MinGW工具链配置文件，用于在Linux上交叉编译Windows可执行程序

# 指定目标系统为 Windows
set(CMAKE_SYSTEM_NAME Windows)

# 指定 C 和 C++ 编译器
set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)
set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)

# 指定资源编译器（用于处理 .rc 文件）
set(CMAKE_RC_COMPILER x86_64-w64-mingw32-windres)

# 设置 CMake 查找库的路径（可选）
# set(CMAKE_FIND_ROOT_PATH /usr/x86_64-w64-mingw32)

# 仅查找目标平台库
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# 设置pkg-config路径（如果需要）
# set(ENV{PKG_CONFIG_PATH} "/usr/x86_64-w64-mingw32/lib/pkgconfig")

# 设置默认的Windows SDK版本（如果需要）
# set(CMAKE_C_STANDARD_LIBRARIES "-lkernel32 -luser32 -lgdi32 -lwinspool -lshell32 -lole32 -loleaut32 -luuid -lcomdlg32 -ladvapi32")