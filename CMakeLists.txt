cmake_minimum_required(VERSION 3.11)

project(libpsi_cmake)

# 定义自己的cmake模块所在的路径
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/cmake")

# Build mode
if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
   SET(CMAKE_BUILD_TYPE Release)
endif()

# 查找libPSI
find_package(libPSI QUIET)
if (libPSI_FOUND)
    message(STATUS "Found libPSI")
elseif (NOT libPSI_FOUND)
    message("libPSI was not found: add libPSI subdirectory")
    message("please install libPSI")
    # if (NOT EXISTS "${PROJECT_SOURCE_DIR}/extern/libPSI/CMakeLists.txt")
    #     message("libPSI cmake was not found")
    #     find_package(Git REQUIRED)
    #     message("initialize Git submodule: extern/libPSI")
    #     execute_process(COMMAND git submodule update --init --recursive extern/libPSI
    #             WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}")
    # endif ()
    # add_subdirectory(extern/libPSI)
    # message("added")
endif ()

include_directories(${PROJECT_SOURCE_DIR}/extern
                    ${PROJECT_SOURCE_DIR}/extern/libPSI
                    )

add_executable(test test.cpp)

target_link_libraries(test libPSI)
cmake_minimum_required(VERSION 3.11)

project(libpsi_cmake)

# 定义自己的cmake模块所在的路径
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/cmake")

add_definitions(-DSOLUTION_DIR='${CMAKE_SOURCE_DIR}')

# Build mode
if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
   SET(CMAKE_BUILD_TYPE Release)
endif()

# 查找libPSI
find_package(libPSI QUIET)
if (libPSI_FOUND)
    message(STATUS "Found libPSI")
elseif (NOT libPSI_FOUND)
    message("libPSI was not found: add libPSI subdirectory")
    if (NOT EXISTS "${PROJECT_SOURCE_DIR}/extern/libPSI/CMakeLists.txt")
        message("libPSI cmake was not found")
        find_package(Git REQUIRED)
        message("initialize Git submodule: extern/libPSI")
        execute_process(COMMAND git submodule update --init --recursive extern/libPSI
                WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}")
    endif ()
    add_subdirectory(extern/libPSI)
    message("added")
endif ()

include_directories(${PROJECT_SOURCE_DIR}/extern
                    ${PROJECT_SOURCE_DIR}/extern/libPSI
                    )

add_executable(test test.cpp)

target_link_libraries(test libPSI)
