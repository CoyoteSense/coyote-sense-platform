@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
if errorlevel 1 (
    echo Failed to set up Visual Studio environment
    exit /b 1
)
echo Visual Studio environment set up successfully

cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE="%VCPKG_ROOT%/scripts/buildsystems/vcpkg.cmake"
if errorlevel 1 (
    echo CMake configuration failed
    exit /b 1
)

cmake --build . --config Release
if errorlevel 1 (
    echo Build failed
    exit /b 1
)

echo Build completed successfully
ctest -C Release --output-on-failure
