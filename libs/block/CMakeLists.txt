#---------------------------------------------------------------------------#
# Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

cmake_minimum_required(VERSION 3.12.4)

cmake_policy(SET CMP0028 NEW)
cmake_policy(SET CMP0042 NEW)
cmake_policy(SET CMP0048 NEW)
cmake_policy(SET CMP0057 NEW)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake"
     "${CMAKE_CURRENT_LIST_DIR}/cmake/packages"
     "${CMAKE_CURRENT_LIST_DIR}/cmake/modules/share/modules/cmake")

include(CMConfig)
include(CMDeploy)
include(CMSetupVersion)

if(NOT CMAKE_WORKSPACE_NAME OR NOT ("${CMAKE_WORKSPACE_NAME}" STREQUAL "crypto3"))
    cm_workspace(crypto3)
endif()

cm_project(block WORKSPACE_NAME ${CMAKE_WORKSPACE_NAME} LANGUAGES C CXX)

include(TargetArchitecture)
include(TargetConfiguration)
include(PlatformConfiguration)

include(CheckSSE)
include(CheckAVX)

option(${CMAKE_UPPER_WORKSPACE_NAME}_${CURRENT_UPPER_PROJECT_NAME}_AES
       "Build with AES block encryption support" TRUE)
option(${CMAKE_UPPER_WORKSPACE_NAME}_${CURRENT_UPPER_PROJECT_NAME}_ARIA
       "Build with ARIA block encryption support" TRUE)
option(${CMAKE_UPPER_WORKSPACE_NAME}_${CURRENT_UPPER_PROJECT_NAME}_BLOWFISH
       "Build with Blowfish block encryption support" TRUE)
option(${CMAKE_UPPER_WORKSPACE_NAME}_${CURRENT_UPPER_PROJECT_NAME}_CAMELLIA
       "Build with Camellia block encryption support" TRUE)
option(${CMAKE_UPPER_WORKSPACE_NAME}_${CURRENT_UPPER_PROJECT_NAME}_CAST
       "Build with Cast block encryption support" TRUE)
option(${CMAKE_UPPER_WORKSPACE_NAME}_${CURRENT_UPPER_PROJECT_NAME}_DES
       "Build with DES block encryption support" TRUE)
option(${CMAKE_UPPER_WORKSPACE_NAME}_${CURRENT_UPPER_PROJECT_NAME}_GOST_28147_89
       "Build with GOST.28147.89 block encryption support" TRUE)
option(${CMAKE_UPPER_WORKSPACE_NAME}_${CURRENT_UPPER_PROJECT_NAME}_IDEA
       "Build with IDEA block encryption support" TRUE)
option(${CMAKE_UPPER_WORKSPACE_NAME}_${CURRENT_UPPER_PROJECT_NAME}_KASUMI
       "Build with Kasumi block encryption support" TRUE)
option(${CMAKE_UPPER_WORKSPACE_NAME}_${CURRENT_UPPER_PROJECT_NAME}_MD4
       "Build with MD4 block encryption support" TRUE)
option(${CMAKE_UPPER_WORKSPACE_NAME}_${CURRENT_UPPER_PROJECT_NAME}_MD5
       "Build with MD5 block encryption support" TRUE)
option(${CMAKE_UPPER_WORKSPACE_NAME}_${CURRENT_UPPER_PROJECT_NAME}_MISTY1
       "Build with Misty1 block encryption support" TRUE)
option(${CMAKE_UPPER_WORKSPACE_NAME}_${CURRENT_UPPER_PROJECT_NAME}_NOEKEON
       "Build with Noekeon block encryption support" TRUE)
option(${CMAKE_UPPER_WORKSPACE_NAME}_${CURRENT_UPPER_PROJECT_NAME}_NOEKEON_SIMD
       "Build with Noekeon block encryption through SMID instruction set support" TRUE)
option(${CMAKE_UPPER_WORKSPACE_NAME}_${CURRENT_UPPER_PROJECT_NAME}_SEED
       "Build with Seed block encryption support" TRUE)
option(${CMAKE_UPPER_WORKSPACE_NAME}_${CURRENT_UPPER_PROJECT_NAME}_SERPENT
       "Build with Serpent block encryption support" TRUE)
option(${CMAKE_UPPER_WORKSPACE_NAME}_${CURRENT_UPPER_PROJECT_NAME}_SHACAL2
       "Build with Shacal2 block encryption support" TRUE)
option(${CMAKE_UPPER_WORKSPACE_NAME}_${CURRENT_UPPER_PROJECT_NAME}_SM4
       "Build with SM4 block encryption support" TRUE)
option(${CMAKE_UPPER_WORKSPACE_NAME}_${CURRENT_UPPER_PROJECT_NAME}_TWOFISH
       "Build with Twofish block encryption support" TRUE)
option(${CMAKE_UPPER_WORKSPACE_NAME}_${CURRENT_UPPER_PROJECT_NAME}_THREEFISH
       "Build with Threefish block encryption support" TRUE)
option(${CMAKE_UPPER_WORKSPACE_NAME}_${CURRENT_UPPER_PROJECT_NAME}_XTEA
       "Build with XTEA block encryption support" TRUE)

set(BUILD_WITH_TARGET_ARCHITECTURE "" CACHE STRING "Target build architecture")

if(BUILD_WITH_TARGET_ARCHITECTURE)
    set(CMAKE_TARGET_ARCHITECTURE ${BUILD_WITH_TARGET_ARCHITECTURE})
else()
    target_architecture(CMAKE_TARGET_ARCHITECTURE)
endif()

define_target_architecture(${CMAKE_UPPER_WORKSPACE_NAME} ${CMAKE_TARGET_ARCHITECTURE})
define_target_endianness(${CMAKE_UPPER_WORKSPACE_NAME} ${CMAKE_TARGET_ARCHITECTURE})
define_target_platform_features(${CMAKE_UPPER_WORKSPACE_NAME})

check_sse()
check_avx()

set(BUILD_WITH_CONFIGURATION_FILE_DIR "${CMAKE_CURRENT_LIST_DIR}/cmake" CACHE STRING "Directory for build.hpp lookup")



if(${CMAKE_UPPER_WORKSPACE_NAME}_${CURRENT_UPPER_PROJECT_NAME}_AES)
    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_RIJNDAEL)

    if(${CMAKE_TARGET_ARCHITECTURE} STREQUAL "armv8" OR ${CMAKE_TARGET_ARCHITECTURE} STREQUAL "arm64")
        add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_RIJNDAEL_ARMV8)
    elseif(${CMAKE_TARGET_ARCHITECTURE} STREQUAL "ppc64")
        add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_RIJNDAEL_POWER8)
    endif()
endif()

if(${CMAKE_UPPER_WORKSPACE_NAME}_${CURRENT_UPPER_PROJECT_NAME}_ARIA)
    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_ARIA)
endif()

if(${CMAKE_UPPER_WORKSPACE_NAME}_${CURRENT_UPPER_PROJECT_NAME}_BLOWFISH)
    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_BLOWFISH)
endif()

if(${CMAKE_UPPER_WORKSPACE_NAME}_${CURRENT_UPPER_PROJECT_NAME}_CAMELLIA)
    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_CAMELLIA)
endif()

if(${CMAKE_UPPER_WORKSPACE_NAME}_${CURRENT_UPPER_PROJECT_NAME}_CAST128)
    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_CAST -D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_CAST_128
                    -D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_CAST_256)
endif()

if(${CMAKE_UPPER_WORKSPACE_NAME}_${CURRENT_UPPER_PROJECT_NAME}_DES)
    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_DES)
endif()

if(${CMAKE_UPPER_WORKSPACE_NAME}_${CURRENT_UPPER_PROJECT_NAME}_GOST_28147_89)
    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_GOST_28147_89)
endif()

if(${CMAKE_UPPER_WORKSPACE_NAME}_${CURRENT_UPPER_PROJECT_NAME}_IDEA)
    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_IDEA)
endif()

if(${CMAKE_UPPER_WORKSPACE_NAME}_${CURRENT_UPPER_PROJECT_NAME}_KASUMI)
    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_KASUMI)
endif()

if(${CMAKE_UPPER_WORKSPACE_NAME}_${CURRENT_UPPER_PROJECT_NAME}_MISTY1)
    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_MISTY1)
endif()

if(${CMAKE_UPPER_WORKSPACE_NAME}_${CURRENT_UPPER_PROJECT_NAME}_MD4)
    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_MD4)
endif()

if(${CMAKE_UPPER_WORKSPACE_NAME}_${CURRENT_UPPER_PROJECT_NAME}_MD5)
    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_MD5)
endif()

if(${CMAKE_UPPER_WORKSPACE_NAME}_${CURRENT_UPPER_PROJECT_NAME}_NOEKEON)
    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_NOEKEON)
endif()

if(${CMAKE_UPPER_WORKSPACE_NAME}_${CURRENT_UPPER_PROJECT_NAME}_SEED)
    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_SEED)
endif()

if(${CMAKE_UPPER_WORKSPACE_NAME}_${CURRENT_UPPER_PROJECT_NAME}_SERPENT)
    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_SERPENT)
endif()

if(${CMAKE_UPPER_WORKSPACE_NAME}_${CURRENT_UPPER_PROJECT_NAME}_SHACAL2)
    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_SHACAL2)
endif()

if(${CMAKE_UPPER_WORKSPACE_NAME}_${CURRENT_UPPER_PROJECT_NAME}_SM4)
    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_SM4)
endif()

if(${CMAKE_UPPER_WORKSPACE_NAME}_${CURRENT_UPPER_PROJECT_NAME}_THREEFISH)
    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_THREEFISH)
endif()

if(${CMAKE_UPPER_WORKSPACE_NAME}_${CURRENT_UPPER_PROJECT_NAME}_TWOFISH)
    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_TWOFISH)
endif()

if(${CMAKE_UPPER_WORKSPACE_NAME}_${CURRENT_UPPER_PROJECT_NAME}_XTEA)
    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_XTEA)
endif()

cm_setup_version(VERSION 0.1.0 PREFIX ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME})

add_library(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE)

set_target_properties(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PROPERTIES
                      EXPORT_NAME ${CURRENT_PROJECT_NAME})

if(${CMAKE_TARGET_ARCHITECTURE} STREQUAL "x86_64" OR ${CMAKE_TARGET_ARCHITECTURE} STREQUAL "x86")
    if(SSE2_FOUND)
        target_compile_definitions(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
                                   "${CMAKE_UPPER_WORKSPACE_NAME}_HAS_RIJNDAEL_NI")
        target_compile_options(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE "-maes;-mpclmul;-mssse3")
    elseif(SSSE3_FOUND)
        target_compile_definitions(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
                                   "${CMAKE_UPPER_WORKSPACE_NAME}_HAS_RIJNDAEL_SSSE3")
        target_compile_options(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE "-maes;-mpclmul;-mssse3")
    endif()
elseif(${CMAKE_TARGET_ARCHITECTURE} STREQUAL "armv8" OR ${CMAKE_TARGET_ARCHITECTURE} STREQUAL "arm64")
    target_compile_definitions(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
                               "${CMAKE_UPPER_WORKSPACE_NAME}_HAS_RIJNDAEL_ARMV8")
elseif(${CMAKE_TARGET_ARCHITECTURE} STREQUAL "ppc64")
    target_compile_definitions(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
                               "${CMAKE_UPPER_WORKSPACE_NAME}_HAS_RIJNDAEL_POWER8")
endif()

target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
                      Boost::container)

target_include_directories(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
                           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
                           $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>

                           ${Boost_INCLUDE_DIRS})

cm_deploy(TARGETS ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
          INCLUDE include
          NAMESPACE ${CMAKE_WORKSPACE_NAME}::)

include(CMTest)
cm_add_test_subdirectory(test)
