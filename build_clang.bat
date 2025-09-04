@echo off
REM 构建脚本 - 使用clang++在Windows上编译

REM 创建构建目录
if not exist "build" mkdir build
cd build

REM 使用CMake配置项目，指定使用clang编译器
cmake .. -G "MinGW Makefiles" -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++

REM 构建项目
cmake --build .

echo.
echo 构建完成！可执行文件位于 build/devin_cap/devin_cap.exe
echo 确保 wintun.dll 也在同一目录下
echo.
pause