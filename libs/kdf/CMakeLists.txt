#---------------------------------------------------------------------------#
# Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

include(CMDeploy)
include(CMSetupVersion)
include(CMConfig)

cm_project(kdf WORKSPACE_NAME ${CMAKE_WORKSPACE_NAME} LANGUAGES C CXX)

cm_find_package(${CMAKE_WORKSPACE_NAME}_block)
cm_find_package(${CMAKE_WORKSPACE_NAME}_hash)
cm_find_package(${CMAKE_WORKSPACE_NAME}_mac)

option(CRYPTO3_KDF_HKDF "Build with HKDF support" TRUE)
option(CRYPTO3_KDF_KDF1 "Build with HKDF support" TRUE)
option(CRYPTO3_KDF_KDF1_18033 "Build with HKDF support" TRUE)
option(CRYPTO3_KDF_KDF2 "Build with HKDF support" TRUE)
option(CRYPTO3_KDF_TLS_PRF "Build with HKDF support" TRUE)
option(CRYPTO3_KDF_X942_PRF "Build with HKDF support" TRUE)
option(CRYPTO3_KDF_SP800_108 "Build with HKDF support" TRUE)
option(CRYPTO3_KDF_SP800_56C "Build with HKDF support" TRUE)

if(CRYPTO3_KDF_HKDF)
    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_HKDF)
endif()

if(CRYPTO3_KDF_KDF1)
    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_KDF1)
endif()

if(CRYPTO3_KDF_KDF1_18033)
    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_KDF1_18033)
endif()

if(CRYPTO3_KDF_KDF2)
    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_KDF2)
endif()

if(CRYPTO3_KDF_TLS_PRF)
    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_TLS_V10_PRF)
    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_TLS_V12_PRF)
endif()

if(CRYPTO3_KDF_PRF_X942)
    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_X942_PRF)
endif()

if(CRYPTO3_KDF_SP800_108)
    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_SP800_108)
endif()

if(CRYPTO3_KDF_SP800_56C)
    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_SP800_56C)
endif()

if(CRYPTO3_KDF_SP800_56A)
    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_SP800_56A)
endif()

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
