#!/bin/bash
# 测试构建脚本

echo "=== tun-udp-win 构建测试 ==="

# 清理之前的构建
echo "清理之前的构建..."
rm -rf build/windows

# 运行构建脚本
echo "运行构建脚本..."
./build_windows.sh

# 检查构建结果
if [ -f "build/windows/devin_cap/devin_cap.exe" ]; then
    echo "✓ 构建成功!"
    echo "可执行文件大小: $(du -h build/windows/devin_cap/devin_cap.exe | cut -f1)"
    echo "wintun.dll大小: $(du -h build/windows/devin_cap/wintun.dll | cut -f1)"
    
    # 检查文件类型
    echo "文件类型信息:"
    file build/windows/devin_cap/devin_cap.exe
    
    echo "构建测试完成!"
else
    echo "✗ 构建失败!"
    exit 1
fi