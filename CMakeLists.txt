#---------------------------------------------------------------------------#
# Copyright (c) 2018-2019 Nil Foundation AG
# Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

cmake_minimum_required(VERSION 2.8.11)

cmake_policy(SET CMP0042 NEW)
cmake_policy(SET CMP0028 NEW)

cm_project(pbkdf WORKSPACE_NAME ${CMAKE_WORKSPACE_NAME})

cm_find_package(CM)
include(CMDeploy)
include(CMSetupVersion)

cm_find_package(${CMAKE_WORKSPACE_NAME}_hash)
cm_find_package(${CMAKE_WORKSPACE_NAME}_mac)

list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
     include/nil/crypto3/pbkdf/pbkdf.hpp)

list(APPEND ${CURRENT_PROJECT_NAME}_UNGROUPED_SOURCES)

option(CRYPTO3_PBKDF_PBKDF1 "Build with PBKDF1 support" TRUE)
option(CRYPTO3_PBKDF_PBKDF2 "Build with PBKDF2 support" TRUE)
option(CRYPTO3_PBKDF_PGP_S2K "Build with PGP S2K support" TRUE)

if(CRYPTO3_PBKDF_PBKDF1)
    list(APPEND ${CURRENT_PROJECT_NAME}_PBKDF1_HEADERS
         include/nil/crypto3/pbkdf/pbkdf1.hpp)

    add_definitions(-DCRYPTO3_HAS_PBKDF1)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_PBKDF1_HEADERS})
endif()

if(CRYPTO3_PBKDF_PBKDF2)
    list(APPEND ${CURRENT_PROJECT_NAME}_PBKDF2_HEADERS
         include/nil/crypto3/pbkdf/pbkdf2.hpp)

    add_definitions(-DCRYPTO3_HAS_PBKDF2)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_PBKDF2_HEADERS})
endif()

if(CRYPTO3_PBKDF_PGP_S2K)
    list(APPEND ${CURRENT_PROJECT_NAME}_PGP_S2K_HEADERS
         include/nil/crypto3/pbkdf/pgp_s2k.hpp)

    add_definitions(-DCRYPTO3_HAS_PGP_S2K)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_PGP_S2K_HEADERS})
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
                      ${CMAKE_WORKSPACE_NAME}::hash
                      ${CMAKE_WORKSPACE_NAME}::mac)

target_include_directories(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
                           "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                           "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>")

cm_deploy(TARGETS ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
          INCLUDE include
          NAMESPACE ${CMAKE_WORKSPACE_NAME}::)

if(BUILD_TESTS)
    add_subdirectory(test)
endif()