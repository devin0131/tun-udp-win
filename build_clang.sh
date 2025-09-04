#!/bin/bash

# 构建脚本 - 使用clang++直接编译

# 创建构建目录
mkdir -p build
cd build

# 使用CMake配置项目，指定使用clang编译器
cmake .. -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++

# 构建项目
cmake --build .

echo "构建完成！可执行文件位于 build/devin_cap/devin_cap.exe"
echo "确保 wintun.dll 也在同一目录下"