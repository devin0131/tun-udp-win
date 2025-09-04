cmake_minimum_required(VERSION 3.10)
project(tun_udp_win)

# 设置默认构建类型
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# 选项：是否使用clang编译器
option(USE_CLANG "Use Clang compiler" OFF)

if(USE_CLANG)
    set(CMAKE_C_COMPILER clang)
    set(CMAKE_CXX_COMPILER clang++)
endif()

# 添加子目录
add_subdirectory(devin_cap)