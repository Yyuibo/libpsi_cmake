cmake_minimum_required(VERSION 3.11)

project(libpsi_cmake)

find_package(libPSI REQUIRED)

add_executable(test test.cpp)