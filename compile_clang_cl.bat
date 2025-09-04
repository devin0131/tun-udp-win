@echo off
REM 使用Visual Studio的clang-cl编译脚本

REM 检查是否存在clang-cl
where clang-cl >nul 2>&1
if %errorlevel% neq 0 (
    echo clang-cl 未找到，请确保已安装Visual Studio并包含Clang工具
    pause
    exit /b 1
)

REM 创建输出目录
if not exist "output" mkdir output

REM 使用clang-cl编译
clang-cl /std:c++17 /Wall ^
  /I./devin_cap ^
  /I./devin_cap/ncap/Include ^
  /I./devin_cap/ncap/Include/pcap ^
  /I./devin_cap/wintun/include ^
  ./devin_cap/devin_cap.cpp ^
  /link ^
  /LIBPATH:./devin_cap/ncap/Lib ^
  /LIBPATH:./devin_cap/wintun/bin/amd64 ^
  wpcap.lib Packet.lib ws2_32.lib iphlpapi.lib ^
  /OUT:./output/devin_cap.exe

REM 复制wintun.dll到输出目录
copy ./devin_cap/wintun/bin/amd64/wintun.dll ./output/

echo.
echo 编译完成！可执行文件位于 output/devin_cap.exe
echo 确保 wintun.dll 也在 output 目录下
echo.
pause