#---------------------------------------------------------------------------#
# Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

cmake_minimum_required(VERSION 2.8.12)

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

cm_project(hash WORKSPACE_NAME ${CMAKE_WORKSPACE_NAME} LANGUAGES C CXX)

macro(cm_find_package NAME)
    if(NOT "${NAME}" MATCHES "^${CMAKE_WORKSPACE_NAME}_.*$" AND NOT "${NAME}" STREQUAL CM)
        find_package(${ARGV})
    else()
        set(${ARGV0}_FOUND ON CACHE BOOL "")
    endif()
endmacro()

if(NOT Boost_FOUND)
    cm_find_package(Boost REQUIRED COMPONENTS container)
endif()

include(TargetArchitecture)
include(TargetConfiguration)
include(PlatformConfiguration)

include(CheckSSE)
include(CheckAVX)

option(BUILD_WITH_CCACHE "Build with ccache usage" TRUE)
option(BUILD_TESTS "Build unit tests" FALSE)

option(CRYPTO3_HASH_BLAKE2B "Build with Blake2 hash support" TRUE)
option(CRYPTO3_HASH_CHECKSUM_ADLER "Build with Adler checksum support" TRUE)
option(CRYPTO3_HASH_CHECKSUM_CRC "Build with CRC checksum support" TRUE)
option(CRYPTO3_HASH_CUBEHSAH "Build with Cubehash hash support" TRUE)
option(CRYPTO3_HASH_COMB4P "Build with Comb4p hash support" TRUE)
option(CRYPTO3_HASH_GOST_34_11 "Build with GOST.34.11 hash support" TRUE)
option(CRYPTO3_HASH_KECCAK "Build with Keccak hash support" TRUE)
option(CRYPTO3_HASH_MD4 "Build with MD4 hash support" TRUE)
option(CRYPTO3_HASH_MD5 "Build with MD5 hash support" TRUE)
option(CRYPTO3_HASH_RIPEMD "Build with Ripemd160 hash support" TRUE)
option(CRYPTO3_HASH_SHA1 "Build with SHA1 hash support" TRUE)
option(CRYPTO3_HASH_SHA2 "Build with SHA2 hash support" TRUE)
option(CRYPTO3_HASH_SHA3 "Build with SHA3 hash support" TRUE)
option(CRYPTO3_HASH_SKEIN "Build with Skein hash support" TRUE)
option(CRYPTO3_HASH_SHAKE "Build with Shake hash support" TRUE)
option(CRYPTO3_HASH_STREEBOG "Build with Streebog hash support" TRUE)
option(CRYPTO3_HASH_TIGER "Build with Tiger hash support" TRUE)
option(CRYPTO3_HASH_WHIRLPOOL "Build with Whirlpool hash support" TRUE)

set(BUILD_WITH_TARGET_ARCHITECTURE "" CACHE STRING "Target build architecture")

if(BUILD_WITH_TARGET_ARCHITECTURE)
    set(CMAKE_TARGET_ARCHITECTURE ${BUILD_WITH_TARGET_ARCHITECTURE})
else()
    target_architecture(CMAKE_TARGET_ARCHITECTURE)
endif()

check_sse()
check_avx()

list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
     include/nil/crypto3/hash/algorithm/hash.hpp

     include/nil/crypto3/hash/adaptor/hashed.hpp)

if(CRYPTO3_HASH_BLAKE2B)
    list(APPEND ${CURRENT_PROJECT_NAME}_BLAKE2B_HEADERS
         include/nil/crypto3/hash/blake2b.hpp

         include/nil/crypto3/hash/detail/blake2b/blake2b_policy.hpp
         include/nil/crypto3/hash/detail/blake2b/blake2b_functions.hpp)

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_BLAKE2B)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_BLAKE2B_HEADERS})
endif()

if(CRYPTO3_HASH_KECCAK)
    list(APPEND ${CURRENT_PROJECT_NAME}_KECCAK_HEADERS
         include/nil/crypto3/hash/keccak.hpp)

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_KECCAK)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_KECCAK_HEADERS})
endif()

if(CRYPTO3_HASH_MD4)
    list(APPEND ${CURRENT_PROJECT_NAME}_MD4_HEADERS
         include/nil/crypto3/hash/md4.hpp)

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_MD4)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_MD4_HEADERS})
endif()

if(CRYPTO3_HASH_MD5)
    list(APPEND ${CURRENT_PROJECT_NAME}_MD5_HEADERS
         include/nil/crypto3/hash/md5.hpp)

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_MD5)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_MD5_HEADERS})
endif()

if(CRYPTO3_HASH_RIPEMD)
    list(APPEND ${CURRENT_PROJECT_NAME}_RIPEMD_HEADERS
         include/nil/crypto3/hash/detail/ripemd/ripemd_functions.hpp
         include/nil/crypto3/hash/detail/ripemd/ripemd_policy.hpp
         include/nil/crypto3/hash/ripemd.hpp)

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_RIPEMD)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_RIPEMD_HEADERS})
endif()

if(CRYPTO3_HASH_SHA1)
    list(APPEND ${CURRENT_PROJECT_NAME}_SHA1_HEADERS
         include/nil/crypto3/hash/sha.hpp
         include/nil/crypto3/hash/sha1.hpp)

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_SHA1)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_SHA1_HEADERS})
endif()

if(CRYPTO3_HASH_SHA2)
    list(APPEND ${CURRENT_PROJECT_NAME}_SHA2_HEADERS
         include/nil/crypto3/hash/sha.hpp
         include/nil/crypto3/hash/sha2.hpp)

    list(APPEND ${CURRENT_PROJECT_NAME}_SHA2_SOURCES)

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_SHA2_32)
    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_SHA2_64)

    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_SHA2_HEADERS})
endif()

if(CRYPTO3_HASH_SHA3)
    list(APPEND ${CURRENT_PROJECT_NAME}_SHA3_HEADERS
         include/nil/crypto3/hash/sha3.hpp)

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_SHA3)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_SHA3_HEADERS})
endif()

if(CRYPTO3_HASH_TIGER)
    list(APPEND ${CURRENT_PROJECT_NAME}_TIGER_HEADERS
         include/nil/crypto3/hash/tiger.hpp)

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_TIGER)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_TIGER_HEADERS})
endif()

list(APPEND ${CURRENT_PROJECT_NAME}_HEADERS
     ${${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS})

cm_setup_version(VERSION 0.1.0 PREFIX ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME})

add_library(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE)
set_target_properties(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PROPERTIES
                      EXPORT_NAME ${CURRENT_PROJECT_NAME})

target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
                      ${CMAKE_WORKSPACE_NAME}::block

                      ${Boost_LIBRARIES})

target_include_directories(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
                           "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                           "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                           ${Boost_INCLUDE_DIR})

cm_deploy(TARGETS ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
          INCLUDE include
          NAMESPACE ${CMAKE_WORKSPACE_NAME}::)

if(BUILD_TESTS)
    add_subdirectory(test)
endif()
