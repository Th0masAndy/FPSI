cmake_minimum_required(VERSION 3.10)
project(FPSI)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_BUILD_TYPE Release)

set(CMAKE_PREFIX_PATH "${CMAKE_SOURCE_DIR}/thirdparty/out/install")
include_directories(include)
include_directories(${CMAKE_SOURCE_DIR}/thirdparty/out/install/include)

file(GLOB SOURCES src/*.cpp)

add_executable(fpsi ${SOURCES})

# secureJoin
target_include_directories(fpsi PRIVATE ${CMAKE_SOURCE_DIR}/thirdparty/out/install/include/secureJoin)

# Dependencies
find_package(cryptoTools REQUIRED)
find_package(libOTe REQUIRED)
find_package(volePSI REQUIRED)
find_package(fmt REQUIRED)

target_link_libraries(fpsi PRIVATE oc::cryptoTools oc::libOTe visa::volePSI fmt::fmt)
target_link_libraries(fpsi PRIVATE ${CMAKE_SOURCE_DIR}/thirdparty/out/install/lib/libsecureJoin.a)
target_link_libraries(fpsi PRIVATE ${CMAKE_SOURCE_DIR}/thirdparty/out/install/lib/libblake3.a)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/build)

if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|i.86")
    target_compile_options(fpsi PRIVATE -mpclmul -maes -msse2 -msse4.1)
endif()

add_definitions(-DNDEBUG)