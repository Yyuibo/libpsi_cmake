cmake_minimum_required(VERSION 3.11)

project(libpsi_cmake)

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

include_directories(${PROJECT_SOURCE_DIR}/extern)

add_executable(test test.cpp)

target_link_libraries(test libPSI)
