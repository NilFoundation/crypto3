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

if(NOT ${CMAKE_WORKSPACE_NAME} STREQUAL crypto3)
    cm_workspace(crypto3)
endif()

cm_project(modes WORKSPACE_NAME ${CMAKE_WORKSPACE_NAME})

if(NOT Boost_FOUND)
    cm_find_package(Boost)
endif()

cm_find_package(CM)
include(CMDeploy)
include(CMSetupVersion)

cm_find_package(${CMAKE_WORKSPACE_NAME}_block)
cm_find_package(${CMAKE_WORKSPACE_NAME}_codec)
cm_find_package(${CMAKE_WORKSPACE_NAME}_hash)

list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS)

list(APPEND ${CURRENT_PROJECT_NAME}_UNGROUPED_SOURCES)

option(BUILD_TESTS "Build unit tests" FALSE)

option(CRYPTO3_MODE_ECB "Build with ECB cipher mode support" TRUE)
option(CRYPTO3_MODE_CBC "Build with CBC cipher mode support" TRUE)
option(CRYPTO3_MODE_PAD "Build with cipher padding mode support" TRUE)
option(CRYPTO3_MODE_CFB "Build with CFB cipher mode support" TRUE)
option(CRYPTO3_MODE_OFB "Build with OFB cipher mode support" TRUE)
option(CRYPTO3_MODE_XTS "Build with XTS cipher mode support" TRUE)

if(CRYPTO3_MODE_ECB)
    list(APPEND ${CURRENT_PROJECT_NAME}_MODE_ECB_HEADERS
         include/nil/crypto3/modes/ecb.hpp)

    list(APPEND ${CURRENT_PROJECT_NAME}_MODE_ECB_SOURCES)

    add_definitions(-DCRYPTO3_HAS_MODE_ECB)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_MODE_ECB_HEADERS})
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_MODE_ECB_SOURCES})
endif()

if(CRYPTO3_MODE_CBC)
    list(APPEND ${CURRENT_PROJECT_NAME}_MODE_CBC_HEADERS
         include/nil/crypto3/modes/cbc.hpp)

    list(APPEND ${CURRENT_PROJECT_NAME}_MODE_CBC_SOURCES)

    add_definitions(-DCRYPTO3_HAS_MODE_CBC)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_MODE_CBC_HEADERS})
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_MODE_CBC_SOURCES})
endif()

if(CRYPTO3_MODE_PAD)
    list(APPEND ${CURRENT_PROJECT_NAME}_MODE_PAD_HEADERS
         include/nil/crypto3/modes/padding.hpp)

    list(APPEND ${CURRENT_PROJECT_NAME}_MODE_PAD_SOURCES)

    add_definitions(-DCRYPTO3_HAS_MODE_PAD)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_MODE_PAD_HEADERS})
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_MODE_PAD_SOURCES})
endif()

if(CRYPTO3_MODE_CFB)
    list(APPEND ${CURRENT_PROJECT_NAME}_MODE_CFB_HEADERS
         include/nil/crypto3/modes/cfb.hpp)

    list(APPEND ${CURRENT_PROJECT_NAME}_MODE_CFB_SOURCES)

    add_definitions(-DCRYPTO3_HAS_MODE_CFB)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_MODE_CFB_HEADERS}
         )
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_MODE_CFB_SOURCES})
endif()

if(CRYPTO3_MODE_OFB)
    list(APPEND ${CURRENT_PROJECT_NAME}_MODE_OFB_HEADERS
         include/nil/crypto3/modes/ofb.hpp)

    list(APPEND ${CURRENT_PROJECT_NAME}_MODE_OFB_SOURCES)

    add_definitions(-DCRYPTO3_HAS_MODE_OFB)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_MODE_OFB_HEADERS})
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_MODE_OFB_SOURCES})
endif()

if(CRYPTO3_MODE_XTS)
    list(APPEND ${CURRENT_PROJECT_NAME}_MODE_XTS_HEADERS
         include/nil/crypto3/modes/xts.hpp)

    list(APPEND ${CURRENT_PROJECT_NAME}_MODE_XTS_SOURCES)

    add_definitions(-DCRYPTO3_HAS_MODE_XTS)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_MODE_XTS_HEADERS})
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_MODE_XTS_SOURCES})
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
                      ${CMAKE_WORKSPACE_NAME}::codec
                      ${CMAKE_WORKSPACE_NAME}::hash

                      ${Boost_LIBRARIES})

target_include_directories(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
                           "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                           "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                           ${Boost_INCLUDE_DIRS})

cm_deploy(TARGETS ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
          INCLUDE include
          NAMESPACE ${CMAKE_WORKSPACE_NAME}::)

if(BUILD_TESTS)
    add_subdirectory(test)
endif()
