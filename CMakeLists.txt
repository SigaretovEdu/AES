cmake_minimum_required(VERSION 3.22.1)

project(AES)

set(CMAKE_BUILD_TYPE Debug)

add_executable(${PROJECT_NAME} src/AES.cpp)

SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ../)
