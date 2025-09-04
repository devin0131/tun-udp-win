# PowerShell脚本 - 使用CMake和clang编译项目

# 创建构建目录
if (!(Test-Path -Path "build")) {
    New-Item -ItemType Directory -Path "build" | Out-Null
}
Set-Location -Path "build"

# 使用CMake配置项目，指定使用clang编译器
cmake .. -G "MinGW Makefiles" -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Release

# 检查CMake配置是否成功
if ($LASTEXITCODE -ne 0) {
    Write-Host "CMake配置失败"
    pause
    exit 1
}

# 构建项目
cmake --build .

# 检查构建是否成功
if ($LASTEXITCODE -ne 0) {
    Write-Host "构建失败"
    pause
    exit 1
}

Write-Host ""
Write-Host "构建完成！可执行文件位于 build/devin_cap/devin_cap.exe"
Write-Host "确保 wintun.dll 也在同一目录下"
Write-Host ""
pause