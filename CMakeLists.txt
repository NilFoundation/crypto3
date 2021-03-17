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

macro(cm_find_package NAME)
    if(NOT "${NAME}" MATCHES "^${CMAKE_WORKSPACE_NAME}_.*$" AND NOT "${NAME}" STREQUAL CM)
        find_package(${ARGV})
    else()
        set(${ARGV0}_FOUND ON CACHE BOOL "")
    endif()
endmacro()

if(NOT Boost_FOUND OR NOT Boost_CONTAINER_FOUND)
    cm_find_package(Boost REQUIRED COMPONENTS container)
endif()

include(TargetArchitecture)
include(TargetConfiguration)
include(PlatformConfiguration)

include(CheckSSE)
include(CheckAVX)

cm_find_package(${CMAKE_WORKSPACE_NAME}_block)

option(BUILD_WITH_CCACHE "Build with ccache usage" TRUE)
option(BUILD_TESTS "Build unit tests" FALSE)

if(UNIX AND BUILD_WITH_CCACHE)
    find_program(CCACHE_FOUND ccache)
    if(CCACHE_FOUND)
        set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
        set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache)
    endif(CCACHE_FOUND)
endif()

option(CRYPTO3_BLOCK_AES "Build with AES block encryption support" TRUE)
option(CRYPTO3_BLOCK_ARIA "Build with ARIA block encryption support" TRUE)
option(CRYPTO3_BLOCK_BLOWFISH "Build with Blowfish block encryption support" TRUE)
option(CRYPTO3_BLOCK_CAMELLIA "Build with Camellia block encryption support" TRUE)
option(CRYPTO3_BLOCK_CAST "Build with Cast block encryption support" TRUE)
option(CRYPTO3_BLOCK_DES "Build with DES block encryption support" TRUE)
option(CRYPTO3_BLOCK_GOST_28147_89 "Build with GOST.28147.89 block encryption support" TRUE)
option(CRYPTO3_BLOCK_IDEA "Build with IDEA block encryption support" TRUE)
option(CRYPTO3_BLOCK_KASUMI "Build with Kasumi block encryption support" TRUE)
option(CRYPTO3_BLOCK_MD4 "Build with MD4 block encryption support" TRUE)
option(CRYPTO3_BLOCK_MD5 "Build with MD5 block encryption support" TRUE)
option(CRYPTO3_BLOCK_MISTY1 "Build with Misty1 block encryption support" TRUE)
option(CRYPTO3_BLOCK_NOEKEON "Build with Noekeon block encryption support" TRUE)
option(CRYPTO3_BLOCK_NOEKEON_SIMD "Build with Noekeon block encryption throught SMID instruction set support" TRUE)
option(CRYPTO3_BLOCK_SEED "Build with Seed block encryption support" TRUE)
option(CRYPTO3_BLOCK_SERPENT "Build with Serpent block encryption support" TRUE)
option(CRYPTO3_BLOCK_SHACAL2 "Build with Shacal2 block encryption support" TRUE)
option(CRYPTO3_BLOCK_SM4 "Build with SM4 block encryption support" TRUE)
option(CRYPTO3_BLOCK_TWOFISH "Build with Twofish block encryption support" TRUE)
option(CRYPTO3_BLOCK_THREEFISH "Build with Threefish block encryption support" TRUE)
option(CRYPTO3_BLOCK_XTEA "Build with XTEA block encryption support" TRUE)

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

if(NOT Boost_CONTAINER_FOUND OR NOT Boost_FOUND)
    cm_find_package(Boost COMPONENTS container)
endif()

set(BUILD_WITH_CONFIGURATION_FILE_DIR "${CMAKE_CURRENT_LIST_DIR}/cmake" CACHE STRING "Directory for build.hpp lookup")

list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
     include/nil/crypto3/block/algorithm/encrypt.hpp
     include/nil/crypto3/block/algorithm/decrypt.hpp
     include/nil/crypto3/block/algorithm/move.hpp
     include/nil/crypto3/block/algorithm/copy_n_if.hpp

     include/nil/crypto3/block/cipher.hpp
     include/nil/crypto3/block/cipher_state.hpp
     include/nil/crypto3/block/cipher_value.hpp

     include/nil/crypto3/block/detail/stream_endian.hpp
     include/nil/crypto3/block/detail/pack.hpp
     include/nil/crypto3/block/detail/digest.hpp

     include/nil/crypto3/block/detail/exploder.hpp
     include/nil/crypto3/block/detail/imploder.hpp
     include/nil/crypto3/block/detail/state_adder.hpp
     include/nil/crypto3/block/detail/unbounded_shift.hpp
     )

list(APPEND ${CURRENT_PROJECT_NAME}_UNGROUPED_SOURCES)

if(CRYPTO3_BLOCK_AES)
    list(APPEND ${CURRENT_PROJECT_NAME}_RIJNDAEL_HEADERS
         include/nil/crypto3/block/rijndael.hpp
         include/nil/crypto3/block/detail/rijndael/rijndael_functions.hpp
         include/nil/crypto3/block/detail/rijndael/rijndael_impl.hpp
         include/nil/crypto3/block/detail/rijndael/rijndael_policy.hpp
         )

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_RIJNDAEL)

    if(${CMAKE_TARGET_ARCHITECTURE} STREQUAL "x86_64" OR ${CMAKE_TARGET_ARCHITECTURE} STREQUAL "x86")
        if(SSE2_FOUND)
            list(APPEND ${CURRENT_PROJECT_NAME}_RIJNDAEL_HEADERS
                 include/nil/crypto3/block/detail/rijndael/rijndael_ni_impl.hpp
                 )

        elseif(SSSE3_FOUND)
            list(APPEND ${CURRENT_PROJECT_NAME}_RIJNDAEL_HEADERS
                 include/nil/crypto3/block/detail/rijndael/rijndael_ssse3_impl.hpp
                 )
        endif()
    elseif(${CMAKE_TARGET_ARCHITECTURE} STREQUAL "armv8")
        list(APPEND ${CURRENT_PROJECT_NAME}_RIJNDAEL_HEADERS
             include/nil/crypto3/block/detail/rijndael/rijndael_armv8_impl.hpp)
        add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_RIJNDAEL_ARMV8)
    elseif(${CMAKE_TARGET_ARCHITECTURE} STREQUAL "ppc64")
        add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_RIJNDAEL_POWER8)
        list(APPEND ${CURRENT_PROJECT_NAME}_RIJNDAEL_HEADERS
             include/nil/crypto3/block/detail/rijndael/rijndael_power8_impl.hpp)
    endif()

    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_RIJNDAEL_HEADERS}
         )
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_RIJNDAEL_SOURCES}
         )
endif()

if(CRYPTO3_BLOCK_ARIA)
    list(APPEND ${CURRENT_PROJECT_NAME}_ARIA_HEADERS
         include/nil/crypto3/block/aria.hpp
         include/nil/crypto3/block/detail/aria/aria_functions.hpp
         include/nil/crypto3/block/detail/aria/aria_policy.hpp
         )

    list(APPEND ${CURRENT_PROJECT_NAME}_ARIA_SOURCES

         )

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_ARIA)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_ARIA_HEADERS}
         )
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_ARIA_SOURCES}
         )
endif()

if(CRYPTO3_BLOCK_BLOWFISH)
    list(APPEND ${CURRENT_PROJECT_NAME}_BLOWFISH_HEADERS
         include/nil/crypto3/block/blowfish.hpp
         include/nil/crypto3/block/detail/blowfish/blowfish_functions.hpp
         include/nil/crypto3/block/detail/blowfish/blowfish_policy.hpp
         )


    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_BLOWFISH)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_BLOWFISH_HEADERS}
         )
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_BLOWFISH_SOURCES}
         )
endif()

if(CRYPTO3_BLOCK_CAMELLIA)
    list(APPEND ${CURRENT_PROJECT_NAME}_CAMELLIA_HEADERS
         include/nil/crypto3/block/camellia.hpp
         include/nil/crypto3/block/detail/camellia/camellia_functions.hpp
         include/nil/crypto3/block/detail/camellia/camellia_policy.hpp
         include/nil/crypto3/block/detail/camellia/basic_camellia_policy.hpp
         )

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_CAMELLIA)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_CAMELLIA_HEADERS}
         )
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_CAMELLIA_SOURCES}
         )
endif()

if(CRYPTO3_BLOCK_CAST128)
    list(APPEND ${CURRENT_PROJECT_NAME}_CAST_PUBLIC_HEADERS
         include/nil/crypto3/block/cast.hpp
         include/nil/crypto3/block/detail/cast/cast_functions.hpp
         include/nil/crypto3/block/detail/cast/basic_cast_policy.hpp
         include/nil/crypto3/block/detail/cast/cast_policy.hpp
         )

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_CAST -D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_CAST_128
                    -D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_CAST_256)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_CAST_PUBLIC_HEADERS}
         )
    list(APPEND ${CURRENT_PROJECT_NAME}_PRIVATE_HEADERS
         ${${CURRENT_PROJECT_NAME}_CAST_PRIVATE_HEADERS}
         )

    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_CAST_SOURCES}
         )
endif()

if(CRYPTO3_BLOCK_DES)
    list(APPEND ${CURRENT_PROJECT_NAME}_DES_HEADERS
         include/nil/crypto3/block/des.hpp
         include/nil/crypto3/block/detail/des/des_functions.hpp
         include/nil/crypto3/block/detail/des/basic_des_policy.hpp
         include/nil/crypto3/block/detail/des/des_policy.hpp
         )

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_DES)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_DES_HEADERS}
         )
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_DES_SOURCES}
         )
endif()

if(CRYPTO3_BLOCK_GOST_28147_89)
    list(APPEND ${CURRENT_PROJECT_NAME}_GOST_28147_89_HEADERS
         include/nil/crypto3/block/gost28147.hpp
         include/nil/crypto3/block/detail/gost_28147_89/gost_28147_89_functions.hpp
         include/nil/crypto3/block/detail/gost_28147_89/gost_28147_89_policy.hpp
         include/nil/crypto3/block/detail/gost_28147_89/gost_28147_89_parameters.hpp
         )

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_GOST_28147_89)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_GOST_28147_89_HEADERS}
         )
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_GOST_28147_89_SOURCES}
         )
endif()

if(CRYPTO3_BLOCK_IDEA)
    list(APPEND ${CURRENT_PROJECT_NAME}_IDEA_HEADERS
         include/nil/crypto3/block/idea.hpp
         include/nil/crypto3/block/detail/idea/idea_functions.hpp
         include/nil/crypto3/block/detail/idea/idea_policy.hpp
         )

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_IDEA)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_IDEA_HEADERS}
         )
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_IDEA_SOURCES}
         )
endif()

if(CRYPTO3_BLOCK_KASUMI)
    list(APPEND ${CURRENT_PROJECT_NAME}_KASUMI_HEADERS
         include/nil/crypto3/block/kasumi.hpp
         include/nil/crypto3/block/detail/kasumi/kasumi_functions.hpp
         include/nil/crypto3/block/detail/kasumi/kasumi_policy.hpp
         )

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_KASUMI)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_KASUMI_HEADERS}
         )
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_KASUMI_SOURCES}
         )
endif()

if(CRYPTO3_BLOCK_MISTY1)
    list(APPEND ${CURRENT_PROJECT_NAME}_MISTY1_HEADERS
         include/nil/crypto3/block/misty1.hpp
         include/nil/crypto3/block/detail/misty1/misty1_functions.hpp
         include/nil/crypto3/block/detail/misty1/misty1_policy.hpp
         )

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_MISTY1)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_MISTY1_HEADERS}
         )
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_MISTY1_SOURCES}
         )
endif()

if(CRYPTO3_BLOCK_MD4)
    list(APPEND ${CURRENT_PROJECT_NAME}_MD4_HEADERS
         include/nil/crypto3/block/md4.hpp
         )

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_MD4)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_MD4_HEADERS}
         )
endif()

if(CRYPTO3_BLOCK_MD5)
    list(APPEND ${CURRENT_PROJECT_NAME}_MD5_HEADERS
         include/nil/crypto3/block/md5.hpp
         )

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_MD5)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_MD5_HEADERS}
         )
endif()

if(CRYPTO3_BLOCK_NOEKEON)
    list(APPEND ${CURRENT_PROJECT_NAME}_NOEKEON_HEADERS
         include/nil/crypto3/block/noekeon.hpp
         include/nil/crypto3/block/detail/noekeon/noekeon_functions.hpp
         include/nil/crypto3/block/detail/noekeon/noekeon_policy.hpp
         )

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_NOEKEON)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_NOEKEON_HEADERS}
         )
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_NOEKEON_SOURCES}
         )
endif()

if(CRYPTO3_BLOCK_SEED)
    list(APPEND ${CURRENT_PROJECT_NAME}_SEED_HEADERS
         include/nil/crypto3/block/seed.hpp
         include/nil/crypto3/block/detail/seed/seed_functions.hpp
         include/nil/crypto3/block/detail/seed/seed_policy.hpp
         )

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_SEED)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_SEED_HEADERS}
         )
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_SEED_SOURCES}
         )
endif()

if(CRYPTO3_BLOCK_SERPENT)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_SERPENT_HEADERS
         include/nil/crypto3/block/serpent.hpp
         include/nil/crypto3/block/detail/serpent/serpent_policy.hpp
         include/nil/crypto3/block/detail/serpent/serpent_functions.hpp
         )

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_SERPENT)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_PUBLIC_SERPENT_HEADERS}
         )

    list(APPEND ${CURRENT_PROJECT_NAME}_PRIVATE_HEADERS
         ${${CURRENT_PROJECT_NAME}_PRIVATE_SERPENT_HEADERS})

    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_SERPENT_SOURCES})
endif()

if(CRYPTO3_BLOCK_SHACAL2)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_SHACAL2_HEADERS
         include/nil/crypto3/block/basic_shacal.hpp
         include/nil/crypto3/block/shacal.hpp
         include/nil/crypto3/block/shacal1.hpp
         include/nil/crypto3/block/shacal2.hpp
         include/nil/crypto3/block/detail/shacal/shacal_policy.hpp
         include/nil/crypto3/block/detail/shacal/shacal_functions.hpp
         include/nil/crypto3/block/detail/shacal/shacal1_policy.hpp
         include/nil/crypto3/block/detail/shacal/shacal2_policy.hpp)

    list(APPEND ${CURRENT_PROJECT_NAME}_SHACAL2_SOURCES)

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_SHACAL2)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_PUBLIC_SHACAL2_HEADERS})

    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_SHACAL2_SOURCES})
endif()

if(CRYPTO3_BLOCK_SM4)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_SM4_HEADERS
         include/nil/crypto3/block/detail/sm4/sm4_functions.hpp
         include/nil/crypto3/block/detail/sm4/sm4_policy.hpp
         include/nil/crypto3/block/sm4.hpp)

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_SM4)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_PUBLIC_SM4_HEADERS})

    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_SM4_SOURCES})
endif()

if(CRYPTO3_BLOCK_THREEFISH)
    list(APPEND ${CURRENT_PROJECT_NAME}_THREEFISH_HEADERS
         include/nil/crypto3/block/threefish.hpp
         include/nil/crypto3/block/detail/threefish/threefish_policy.hpp)

    list(APPEND ${CURRENT_PROJECT_NAME}_THREEFISH_SOURCES)

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_THREEFISH)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_THREEFISH_HEADERS})
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_THREEFISH_SOURCES})
endif()

if(CRYPTO3_BLOCK_TWOFISH)
    list(APPEND ${CURRENT_PROJECT_NAME}_TWOFISH_HEADERS
         include/nil/crypto3/block/twofish.hpp
         include/nil/crypto3/block/detail/twofish/basic_twofish_policy.hpp
         include/nil/crypto3/block/detail/twofish/twofish_policy.hpp
         include/nil/crypto3/block/detail/twofish/twofish_functions.hpp)

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_TWOFISH)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_TWOFISH_HEADERS})
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_TWOFISH_SOURCES})
endif()

if(CRYPTO3_BLOCK_XTEA)
    list(APPEND ${CURRENT_PROJECT_NAME}_XTEA_HEADERS
         include/nil/crypto3/block/xtea.hpp
         include/nil/crypto3/block/detail/xtea/xtea_functions.hpp
         include/nil/crypto3/block/detail/xtea/xtea_policy.hpp)

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_XTEA)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_XTEA_HEADERS})
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_XTEA_SOURCES})
endif()

list(APPEND ${CURRENT_PROJECT_NAME}_HEADERS
     ${${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS}
     ${${CURRENT_PROJECT_NAME}_PRIVATE_HEADERS})

list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
     ${${CURRENT_PROJECT_NAME}_UNGROUPED_SOURCES})

cm_setup_version(VERSION 0.1.0 PREFIX ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME})

add_library(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE)

set_target_properties(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PROPERTIES EXPORT_NAME ${CURRENT_PROJECT_NAME})

if(${CMAKE_TARGET_ARCHITECTURE} STREQUAL "x86_64" OR ${CMAKE_TARGET_ARCHITECTURE} STREQUAL "x86")
    if(SSE2_FOUND)
        target_compile_definitions(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE "${CMAKE_UPPER_WORKSPACE_NAME}_HAS_RIJNDAEL_NI")
        target_compile_options(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE "-maes;-mpclmul;-mssse3")
    elseif(SSSE3_FOUND)
        target_compile_definitions(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
                                   "${CMAKE_UPPER_WORKSPACE_NAME}_HAS_RIJNDAEL_SSSE3")
        target_compile_options(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE "-maes;-mpclmul;-mssse3")
    endif()
elseif(${CMAKE_TARGET_ARCHITECTURE} STREQUAL "armv8")
    target_compile_definitions(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE "${CMAKE_UPPER_WORKSPACE_NAME}_HAS_RIJNDAEL_ARMV8")
elseif(${CMAKE_TARGET_ARCHITECTURE} STREQUAL "ppc64")
    target_compile_definitions(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
                               "${CMAKE_UPPER_WORKSPACE_NAME}_HAS_RIJNDAEL_POWER8")
endif()

target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE

                      ${Boost_LIBRARIES})

target_include_directories(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
                           "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                           "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                           "${Boost_INCLUDE_DIRS}")

cm_deploy(TARGETS ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
          INCLUDE include
          NAMESPACE ${CMAKE_WORKSPACE_NAME}::)

if(BUILD_TESTS)
    add_subdirectory(test)
endif()
