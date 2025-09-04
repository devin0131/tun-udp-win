@echo off
REM 直接使用clang++编译脚本

REM 创建输出目录
if not exist "output" mkdir output

REM 使用clang++直接编译
clang++ -std=c++17 -Wall -Wextra ^
  -I./devin_cap ^
  -I./devin_cap/ncap/Include ^
  -I./devin_cap/ncap/Include/pcap ^
  -I./devin_cap/wintun/include ^
  -L./devin_cap/ncap/Lib ^
  -L./devin_cap/wintun/bin/amd64 ^
  ./devin_cap/devin_cap.cpp ^
  -lwpcap -lPacket -lws2_32 -liphlpapi ^
  -o ./output/devin_cap.exe

REM 复制wintun.dll到输出目录
copy ./devin_cap/wintun/bin/amd64/wintun.dll ./output/

echo.
echo 编译完成！可执行文件位于 output/devin_cap.exe
echo 确保 wintun.dll 也在 output 目录下
echo.
pause