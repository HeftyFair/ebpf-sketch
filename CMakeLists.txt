cmake_minimum_required(VERSION 3.20)

project(test)



set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake")

find_package(LibBpf REQUIRED)

add_subdirectory(kernel)

add_subdirectory(user)