if "%1" == "64" @goto :build64

mkdir cmake
cd cmake
cmake .. -G "Visual Studio 10"
msbuild ALL_BUILD.vcxproj /p:Configuration=Release
cd ..
@goto :end


:build64
mkdir cmake64
cd cmake64
cmake .. -G "Visual Studio 10 Win64"
msbuild ALL_BUILD.vcxproj /p:Configuration=Release
cd ..

:end