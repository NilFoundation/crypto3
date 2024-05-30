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

cm_project(modes WORKSPACE_NAME ${CMAKE_WORKSPACE_NAME})

include(CMConfig)
include(CMSetupVersion)

option(CRYPTO3_MODE_ECB "Build with ECB cipher mode support" TRUE)
option(CRYPTO3_MODE_CBC "Build with CBC cipher mode support" TRUE)
option(CRYPTO3_MODE_PAD "Build with cipher padding mode support" TRUE)
option(CRYPTO3_MODE_CFB "Build with CFB cipher mode support" TRUE)
option(CRYPTO3_MODE_OFB "Build with OFB cipher mode support" TRUE)
option(CRYPTO3_MODE_XTS "Build with XTS cipher mode support" TRUE)

if(CRYPTO3_MODE_ECB)
    add_definitions(-DCRYPTO3_HAS_MODE_ECB)
endif()

if(CRYPTO3_MODE_CBC)
    add_definitions(-DCRYPTO3_HAS_MODE_CBC)
endif()

if(CRYPTO3_MODE_PAD)
    add_definitions(-DCRYPTO3_HAS_MODE_PAD)
endif()

if(CRYPTO3_MODE_CFB)
    add_definitions(-DCRYPTO3_HAS_MODE_CFB)
endif()

if(CRYPTO3_MODE_OFB)
    add_definitions(-DCRYPTO3_HAS_MODE_OFB)
endif()

if(CRYPTO3_MODE_XTS)
    add_definitions(-DCRYPTO3_HAS_MODE_XTS)
endif()

cm_setup_version(VERSION 0.1.0 PREFIX ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME})

add_library(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE)

set_target_properties(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PROPERTIES
                      EXPORT_NAME ${CURRENT_PROJECT_NAME})

target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
                      ${CMAKE_WORKSPACE_NAME}::block
                      ${CMAKE_WORKSPACE_NAME}::codec
                      ${CMAKE_WORKSPACE_NAME}::hash

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
