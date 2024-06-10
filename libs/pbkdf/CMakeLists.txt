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

cm_project(pbkdf WORKSPACE_NAME ${CMAKE_WORKSPACE_NAME})

cm_find_package(${CMAKE_WORKSPACE_NAME}_hash)
cm_find_package(${CMAKE_WORKSPACE_NAME}_mac)

option(CRYPTO3_PBKDF_PBKDF1 "Build with PBKDF1 support" TRUE)
option(CRYPTO3_PBKDF_PBKDF2 "Build with PBKDF2 support" TRUE)
option(CRYPTO3_PBKDF_PGP_S2K "Build with PGP S2K support" TRUE)

if(CRYPTO3_PBKDF_PBKDF1)
    add_definitions(-DCRYPTO3_HAS_PBKDF1)
endif()

if(CRYPTO3_PBKDF_PBKDF2)
    add_definitions(-DCRYPTO3_HAS_PBKDF2)
endif()

if(CRYPTO3_PBKDF_PGP_S2K)
    add_definitions(-DCRYPTO3_HAS_PGP_S2K)
endif()

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

include(CMTest)
cm_add_test_subdirectory(test)
