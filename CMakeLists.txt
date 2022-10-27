cmake_minimum_required(VERSION 3.11)

project(libpsi_cmake)

# 定义自己的cmake模块所在的路径
# set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake;"${CMAKE_SOURCE_DIR}")

# C++编译设置
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -no-pie -pthread -maes -msse2 -msse3 -msse4.1 -mpclmul -mavx -mavx2")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-ignored-attributes")

# Build mode
if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
   SET(CMAKE_BUILD_TYPE Release)
endif()

if(     NOT "${CMAKE_BUILD_TYPE}" STREQUAL "Release"
    AND NOT "${CMAKE_BUILD_TYPE}" STREQUAL "Debug" 
    AND NOT "${CMAKE_BUILD_TYPE}" STREQUAL "RelWithDebInfo" )
    message(FATAL_ERROR ": Unknown build type - \${CMAKE_BUILD_TYPE}=${CMAKE_BUILD_TYPE}.  Please use one of Debug, Release,or RelWithDebInfo. e.g. call\n\tcmake . -DCMAKE_BUILD_TYPE=Release\n" )        
endif()

# -D 参数设置
set(FETCH_AUTO ON CACHE BOOL)
set(ENABLE_ALL_PSI ON CACHE BOOL)

# 查找libPSI
list(APPEND CMAKE_PREFIX_PATH "${PROJECT_SOURCE_DIR}/extern/libPSI/out/build/linux")
list(APPEND CMAKE_PREFIX_PATH "${PROJECT_SOURCE_DIR}/extern/libPSI/out/install/linux/lib/cmake/libOTe")
find_package(libPSI QUIET)

if (libPSI_FOUND)
    message(STATUS "Found libPSI")
elseif (NOT libPSI_FOUND)
    message("libPSI was not found: add libPSI subdirectory")
    message("please install libPSI")
    if (NOT EXISTS "${PROJECT_SOURCE_DIR}/extern/libPSI/CMakeLists.txt")
        message("libPSI cmake was not found")
        find_package(Git REQUIRED)
        message("initialize Git submodule: extern/libPSI")
        execute_process(COMMAND git submodule update --init --recursive extern/libPSI
                WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}")
    endif ()
    message("added")
endif ()

# 创建子文件夹，并运行cmake
file(REMOVE ${PROJECT_SOURCE_DIR}/extern/libPSI/frontend/CMakeLists.txt)
file(TOUCH  ${PROJECT_SOURCE_DIR}/extern/libPSI/frontend/CMakeLists.txt)

add_subdirectory(extern/libPSI)

# 头文件路径设置
include_directories(${PROJECT_SOURCE_DIR}/extern/libPSI/out/install/linux
                    ${PROJECT_SOURCE_DIR}/extern/libPSI/out/build/linux/include)

add_executable(test test.cpp)

target_link_libraries(test PUBLIC libPSI)


