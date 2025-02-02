cmake_minimum_required(VERSION 3.29)
project(AES)

set(CMAKE_CXX_STANDARD 20)

add_executable(AES main.cpp
        aes128_helper/aes128_helper.cpp
        aes128_helper/aes128_helper.h
        encryption/steps.cpp
        encryption/steps.h
        encryption/keyGen.cpp
        encryption/keyGen.h
        encryption/algorithm.cpp
        encryption/algorithm.h
        fileManager/File.cpp
        fileManager/File.h
)
