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
cmake_policy(SET CMP0076 NEW)

list(APPEND CMAKE_MODULE_PATH
        "${CMAKE_CURRENT_LIST_DIR}/cmake"
        "${CMAKE_CURRENT_LIST_DIR}/cmake/packages"
        "${CMAKE_CURRENT_LIST_DIR}/cmake/modules/share/modules/cmake")

include(CMDeploy)
include(CMSetupVersion)
include(CMConfig)

if(NOT CMAKE_WORKSPACE_NAME OR NOT ("${CMAKE_WORKSPACE_NAME}" STREQUAL "crypto3"))
    cm_workspace(crypto3)
endif()

cm_project(kdf WORKSPACE_NAME ${CMAKE_WORKSPACE_NAME} LANGUAGES C CXX)

cm_find_package(${CMAKE_WORKSPACE_NAME}_block)
cm_find_package(${CMAKE_WORKSPACE_NAME}_hash)
cm_find_package(${CMAKE_WORKSPACE_NAME}_mac)

if(NOT Boost)
    find_package(Boost REQUIRED)
endif()

list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
     include/nil/crypto3/kdf/algorithm/derive.hpp

     include/nil/crypto3/kdf/kdf.hpp)

list(APPEND ${CURRENT_PROJECT_NAME}_UNGROUPED_SOURCES
     )

option(CRYPTO3_KDF_HKDF "Build with HKDF support" TRUE)
option(CRYPTO3_KDF_KDF1 "Build with HKDF support" TRUE)
option(CRYPTO3_KDF_KDF1_18033 "Build with HKDF support" TRUE)
option(CRYPTO3_KDF_KDF2 "Build with HKDF support" TRUE)
option(CRYPTO3_KDF_TLS_PRF "Build with HKDF support" TRUE)
option(CRYPTO3_KDF_X942_PRF "Build with HKDF support" TRUE)
option(CRYPTO3_KDF_SP800_108 "Build with HKDF support" TRUE)
option(CRYPTO3_KDF_SP800_56C "Build with HKDF support" TRUE)

if(CRYPTO3_KDF_HKDF)
    list(APPEND ${CURRENT_PROJECT_NAME}_HKDF_HEADERS
         include/nil/crypto3/kdf/hkdf.hpp
         )

    list(APPEND ${CURRENT_PROJECT_NAME}_HKDF_SOURCES
         )

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_HKDF)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_HKDF_HEADERS}
         )
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_HKDF_SOURCES}
         )
endif()

if(CRYPTO3_KDF_KDF1)
    list(APPEND ${CURRENT_PROJECT_NAME}_KDF1_HEADERS
         include/nil/crypto3/kdf/kdf1.hpp
         )

    list(APPEND ${CURRENT_PROJECT_NAME}_KDF1_SOURCES
         )

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_KDF1)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_KDF1_HEADERS}
         )
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_KDF1_SOURCES}
         )
endif()

if(CRYPTO3_KDF_KDF1_18033)
    list(APPEND ${CURRENT_PROJECT_NAME}_KDF1_18033_HEADERS
         include/nil/crypto3/kdf/kdf1_iso18033.hpp
         )

    list(APPEND ${CURRENT_PROJECT_NAME}_KDF1_18033_SOURCES
         )

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_KDF1_18033)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_KDF1_18033_HEADERS}
         )
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_KDF1_18033_SOURCES}
         )
endif()

if(CRYPTO3_KDF_KDF2)
    list(APPEND ${CURRENT_PROJECT_NAME}_KDF2_HEADERS
         include/nil/crypto3/kdf/kdf2.hpp
         )

    list(APPEND ${CURRENT_PROJECT_NAME}_KDF2_SOURCES
         )

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_KDF2)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_KDF2_HEADERS}
         )
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_KDF2_SOURCES}
         )
endif()

if(CRYPTO3_KDF_TLS_PRF)
    list(APPEND ${CURRENT_PROJECT_NAME}_TLS_PRF_HEADERS
         include/nil/crypto3/kdf/prf_tls.hpp
         )

    list(APPEND ${CURRENT_PROJECT_NAME}_TLS_PRF_SOURCES
         )

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_TLS_V10_PRF)
    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_TLS_V12_PRF)

    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_TLS_PRF_HEADERS}
         )
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_TLS_PRF_SOURCES}
         )
endif()

if(CRYPTO3_KDF_PRF_X942)
    list(APPEND ${CURRENT_PROJECT_NAME}_PRF_X942_HEADERS
         include/nil/crypto3/kdf/prf_x942.hpp
         )

    list(APPEND ${CURRENT_PROJECT_NAME}_PRF_X942_SOURCES
         )

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_X942_PRF)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_PRF_X942_HEADERS}
         )
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_PRF_X942_SOURCES}
         )
endif()

if(CRYPTO3_KDF_SP800_108)
    list(APPEND ${CURRENT_PROJECT_NAME}_SP800_108_HEADERS
         include/nil/crypto3/kdf/sp800_108.hpp
         )

    list(APPEND ${CURRENT_PROJECT_NAME}_SP800_108_SOURCES
         )

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_SP800_108)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_SP800_108_HEADERS}
         )
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_SP800_108_SOURCES}
         )
endif()

if(CRYPTO3_KDF_SP800_56C)
    list(APPEND ${CURRENT_PROJECT_NAME}_SP800_56C_HEADERS
         include/nil/crypto3/kdf/sp800_56c.hpp
         )

    list(APPEND ${CURRENT_PROJECT_NAME}_SP800_56C_SOURCES
         )

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_SP800_56C)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_SP800_56C_HEADERS}
         )
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_SP800_56C_SOURCES}
         )
endif()

if(CRYPTO3_KDF_SP800_56A)
    list(APPEND ${CURRENT_PROJECT_NAME}_SP800_56A_HEADERS
         include/nil/crypto3/kdf/sp800_56a.hpp
         )

    list(APPEND ${CURRENT_PROJECT_NAME}_SP800_56A_SOURCES
         )

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_SP800_56A)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_SP800_56A_HEADERS}
         )
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_SP800_56A_SOURCES}
         )
endif()

list(APPEND ${CURRENT_PROJECT_NAME}_HEADERS
     ${${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS})

list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
     ${${CURRENT_PROJECT_NAME}_UNGROUPED_SOURCES})

cm_setup_version(VERSION 0.1.0 PREFIX ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME})

add_library(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE)
set_target_properties(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PROPERTIES
                      EXPORT_NAME ${CURRENT_PROJECT_NAME})

target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
                      ${CMAKE_WORKSPACE_NAME}::block
                      ${CMAKE_WORKSPACE_NAME}::hash
                      ${CMAKE_WORKSPACE_NAME}::mac)

target_include_directories(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
                           "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                           "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>")

cm_deploy(TARGETS ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
          INCLUDE include
          NAMESPACE ${CMAKE_WORKSPACE_NAME}::)

include(CMTest)
cm_add_test_subdirectory(test)
