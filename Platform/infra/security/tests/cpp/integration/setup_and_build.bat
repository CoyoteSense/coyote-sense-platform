@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
if errorlevel 1 (
    echo Failed to set up Visual Studio environment
    exit /b 1
)
echo Visual Studio environment set up successfully
cl /EHsc real_oauth2_integration_test.cpp /link winhttp.lib
if errorlevel 1 (
    echo Build failed
    exit /b 1
)
echo Build completed successfully
real_oauth2_integration_test.exe
