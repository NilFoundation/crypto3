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

cm_project(mac WORKSPACE_NAME ${CMAKE_WORKSPACE_NAME})

if(NOT Boost_FOUND)
    cm_find_package(Boost)
endif()

cm_find_package(CM)
include(CMDeploy)
include(CMSetupVersion)

cm_find_package(${CMAKE_WORKSPACE_NAME}_block)
cm_find_package(${CMAKE_WORKSPACE_NAME}_hash)
cm_find_package(${CMAKE_WORKSPACE_NAME}_modes)

list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
     include/nil/crypto3/mac/algorithm/compute.hpp
     include/nil/crypto3/mac/algorithm/verify.hpp)

list(APPEND ${CURRENT_PROJECT_NAME}_UNGROUPED_SOURCES)

option(CRYPTO3_MAC_CBC "Build with CBC MAC support" TRUE)
option(CRYPTO3_MAC_CMAC "Build with CMAC support" TRUE)
option(CRYPTO3_MAC_HMAC "Build with HMAC support" TRUE)
option(CRYPTO3_MAC_GMAC "Build with GMAC support" TRUE)
option(CRYPTO3_MAC_POLY1305 "Build with POLY1305 MAC support" TRUE)
option(CRYPTO3_MAC_SIPHASH "Build with SIPHASH MAC support" TRUE)
option(CRYPTO3_MAC_ANSI_X919 "Build with ANSI X919 MAC support" TRUE)

if(CRYPTO3_MAC_CBC)
    list(APPEND ${CURRENT_PROJECT_NAME}_CBC_MAC_HEADERS
         include/nil/crypto3/mac/cbc_mac.hpp)

    list(APPEND ${CURRENT_PROJECT_NAME}_CBC_MAC_SOURCES)

    add_definitions(-DCRYPTO3_HAS_CBC_MAC)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_CBC_MAC_HEADERS})
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_CBC_MAC_SOURCES})
endif()

if(CRYPTO3_MAC_CMAC)
    list(APPEND ${CURRENT_PROJECT_NAME}_CMAC_HEADERS
         include/nil/crypto3/mac/cmac.hpp)

    list(APPEND ${CURRENT_PROJECT_NAME}_CMAC_SOURCES)

    add_definitions(-DCRYPTO3_HAS_CMAC)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_CMAC_HEADERS})
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_CMAC_SOURCES})
endif()

if(CRYPTO3_MAC_GMAC)
    list(APPEND ${CURRENT_PROJECT_NAME}_GMAC_HEADERS
         include/nil/crypto3/mac/gmac.hpp)

    list(APPEND ${CURRENT_PROJECT_NAME}_GMAC_SOURCES)

    add_definitions(-DCRYPTO3_HAS_GMAC)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_GMAC_HEADERS})
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_GMAC_SOURCES})
endif()

if(CRYPTO3_MAC_HMAC)
    list(APPEND ${CURRENT_PROJECT_NAME}_HMAC_HEADERS
         include/nil/crypto3/mac/hmac.hpp)

    list(APPEND ${CURRENT_PROJECT_NAME}_HMAC_SOURCES)

    add_definitions(-DCRYPTO3_HAS_HMAC)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_HMAC_HEADERS})
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_HMAC_SOURCES})
endif()

if(CRYPTO3_MAC_GMAC)
    list(APPEND ${CURRENT_PROJECT_NAME}_GMAC_HEADERS
         include/nil/crypto3/mac/gmac.hpp)

    list(APPEND ${CURRENT_PROJECT_NAME}_GMAC_SOURCES)

    add_definitions(-DCRYPTO3_HAS_GMAC)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_GMAC_HEADERS})
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_GMAC_SOURCES})
endif()

if(CRYPTO3_MAC_POLY1305)
    list(APPEND ${CURRENT_PROJECT_NAME}_MAC_POLY1305_HEADERS
         include/nil/crypto3/mac/poly1305.hpp)

    list(APPEND ${CURRENT_PROJECT_NAME}_MAC_POLY1305_SOURCES)

    add_definitions(-DCRYPTO3_HAS_POLY1305)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_MAC_POLY1305_HEADERS})
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_MAC_POLY1305_SOURCES})
endif()

if(CRYPTO3_MAC_SIPHASH)
    list(APPEND ${CURRENT_PROJECT_NAME}_SIPHASH_HEADERS
         include/nil/crypto3/mac/siphash.hpp)

    list(APPEND ${CURRENT_PROJECT_NAME}_SIPHASH_SOURCES)

    add_definitions(-DCRYPTO3_HAS_SIPHASH)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_SIPHASH_HEADERS})
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_SIPHASH_SOURCES})
endif()

if(CRYPTO3_MAC_ANSI_X919)
    list(APPEND ${CURRENT_PROJECT_NAME}_X919_HEADERS
         include/nil/crypto3/mac/x919_mac.hpp)

    list(APPEND ${CURRENT_PROJECT_NAME}_X919_SOURCES)

    add_definitions(-DCRYPTO3_HAS_ANSI_X919_MAC)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_X919_HEADERS})
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_X919_SOURCES})
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
                      ${CMAKE_WORKSPACE_NAME}::modes

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