#---------------------------------------------------------------------------#
# Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

cmake_minimum_required(VERSION 2.8.12)

cmake_policy(SET CMP0042 NEW)
cmake_policy(SET CMP0028 NEW)

list(APPEND CMAKE_MODULE_PATH
     "${CMAKE_CURRENT_LIST_DIR}/cmake"
     "${CMAKE_CURRENT_LIST_DIR}/cmake/packages"
     "${CMAKE_CURRENT_LIST_DIR}/cmake/modules/share/modules/cmake")

if(NOT CMAKE_WORKSPACE_NAME OR NOT ("${CMAKE_WORKSPACE_NAME}" STREQUAL "crypto3"))
    cm_workspace(crypto3)
endif()

cm_project(mac WORKSPACE_NAME ${CMAKE_WORKSPACE_NAME})

include(CMDeploy)
include(CMSetupVersion)

cm_find_package(${CMAKE_WORKSPACE_NAME}_block)
cm_find_package(${CMAKE_WORKSPACE_NAME}_hash)
cm_find_package(${CMAKE_WORKSPACE_NAME}_modes)

option(CRYPTO3_MAC_CBC "Build with CBC MAC support" TRUE)
option(CRYPTO3_MAC_CMAC "Build with CMAC support" TRUE)
option(CRYPTO3_MAC_HMAC "Build with HMAC support" TRUE)
option(CRYPTO3_MAC_GMAC "Build with GMAC support" TRUE)
option(CRYPTO3_MAC_POLY1305 "Build with POLY1305 MAC support" TRUE)
option(CRYPTO3_MAC_SIPHASH "Build with SIPHASH MAC support" TRUE)
option(CRYPTO3_MAC_ANSI_X919 "Build with ANSI X919 MAC support" TRUE)

if(CRYPTO3_MAC_CBC)
    add_definitions(-DCRYPTO3_HAS_CBC_MAC)
endif()

if(CRYPTO3_MAC_CMAC)
    add_definitions(-DCRYPTO3_HAS_CMAC)
endif()

if(CRYPTO3_MAC_GMAC)
    add_definitions(-DCRYPTO3_HAS_GMAC)
endif()

if(CRYPTO3_MAC_HMAC)
    add_definitions(-DCRYPTO3_HAS_HMAC)
endif()

if(CRYPTO3_MAC_GMAC)
    add_definitions(-DCRYPTO3_HAS_GMAC)
endif()

if(CRYPTO3_MAC_POLY1305)
    add_definitions(-DCRYPTO3_HAS_POLY1305)
endif()

if(CRYPTO3_MAC_SIPHASH)
    add_definitions(-DCRYPTO3_HAS_SIPHASH)
endif()

if(CRYPTO3_MAC_ANSI_X919)
    add_definitions(-DCRYPTO3_HAS_ANSI_X919_MAC)
endif()

cm_setup_version(VERSION 0.1.0 PREFIX ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME})

add_library(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE)

set_target_properties(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PROPERTIES
                      EXPORT_NAME ${CURRENT_PROJECT_NAME})

target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
                      ${CMAKE_WORKSPACE_NAME}::block
                      ${CMAKE_WORKSPACE_NAME}::hash
                      ${CMAKE_WORKSPACE_NAME}::modes

                      Boost::container)

target_include_directories(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
                           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
                           $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>

                           $<$<BOOL:${Boost_FOUND}>:${Boost_INCLUDE_DIRS}>)

cm_deploy(TARGETS ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
          INCLUDE include
          NAMESPACE ${CMAKE_WORKSPACE_NAME}::)

include(CMTest)
cm_add_test_subdirectory(test)
