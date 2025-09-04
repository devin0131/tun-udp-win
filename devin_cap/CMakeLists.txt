cmake_minimum_required(VERSION 3.10)
project(devin_cap)

# 设置C++标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 设置Windows子系统为控制台应用
if(WIN32)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /SUBSYSTEM:CONSOLE")
endif()

# 检查编译器类型并设置相应的标志
if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang" OR CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang")
    # Clang特定的编译选项
    add_compile_options(-Wall -Wextra -Wpedantic)
    # 对于Windows平台使用clang，可能需要特定的选项
    add_compile_options(-fms-compatibility)
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    # GCC特定的编译选项
    add_compile_options(-Wall -Wextra -Wpedantic)
elseif(MSVC)
    # MSVC特定的编译选项
    add_compile_options(/W3)
endif()

# 添加源文件
set(SOURCES
    devin_cap.cpp
)

# 添加头文件目录
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/ncap/Include
    ${CMAKE_CURRENT_SOURCE_DIR}/ncap/Include/pcap
    ${CMAKE_CURRENT_SOURCE_DIR}/wintun/include
)

# 创建可执行文件
add_executable(${PROJECT_NAME} ${SOURCES})

# 链接库目录
link_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/ncap/Lib
    ${CMAKE_CURRENT_SOURCE_DIR}/wintun/bin/amd64
)

# 链接库
target_link_libraries(${PROJECT_NAME}
    wpcap
    Packet
    ws2_32
    iphlpapi
)

# 设置预处理器定义
target_compile_definitions(${PROJECT_NAME} PRIVATE
    _CRT_SECURE_NO_WARNINGS
)

# 复制wintun.dll到输出目录
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
    "${CMAKE_CURRENT_SOURCE_DIR}/wintun/bin/amd64/wintun.dll"
    $<TARGET_FILE_DIR:${PROJECT_NAME}>
)