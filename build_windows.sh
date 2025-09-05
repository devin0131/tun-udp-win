#!/bin/bash
# Windows交叉编译脚本 (使用MinGW)

# 检查是否安装了MinGW工具链
if ! command -v x86_64-w64-mingw32-gcc &> /dev/null; then
    echo "错误: 未找到MinGW工具链 (x86_64-w64-mingw32-gcc)"
    echo "请安装MinGW-w64工具链:"
    echo "  Ubuntu/Debian: sudo apt-get install gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64"
    echo "  CentOS/RHEL: sudo yum install mingw64-gcc mingw64-gcc-c++"
    echo "  Fedora: sudo dnf install mingw64-gcc mingw64-gcc-c++"
    exit 1
fi

# 检查是否安装了CMake
if ! command -v cmake &> /dev/null; then
    echo "错误: 未找到CMake"
    echo "请安装CMake"
    exit 1
fi

# 创建构建目录
mkdir -p build/windows
cd build/windows

# 配置项目 (使用MinGW工具链)
cmake -DCMAKE_TOOLCHAIN_FILE=../../mingw-toolchain.cmake \
      -DCROSS_COMPILE_WINDOWS=ON \
      ../..

# 检查配置是否成功
if [ $? -ne 0 ]; then
    echo "CMake配置失败!"
    exit 1
fi

# 构建项目
make

# 检查构建是否成功
if [ $? -eq 0 ]; then
    echo "构建完成！Windows可执行文件位于 build/windows/devin_cap/devin_cap.exe"
    echo "注意: 还需要wintun.dll才能在Windows上运行"
else
    echo "构建失败!"
    exit 1
fi