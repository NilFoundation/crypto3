#---------------------------------------------------------------------------#
# Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

cmake_minimum_required(VERSION 2.8.11)

cmake_policy(SET CMP0042 NEW)
cmake_policy(SET CMP0028 NEW)

if(NOT ${CMAKE_WORKSPACE_NAME} STREQUAL crypto3)
    cm_workspace(crypto3)
endif()

cm_project(threshold WORKSPACE_NAME ${CMAKE_WORKSPACE_NAME})

if(NOT Boost_FOUND)
    cm_find_package(Boost)
endif()

cm_find_package(CM)
include(CMDeploy)
include(CMSetupVersion)

cm_find_package(${CMAKE_WORKSPACE_NAME}_pubkey)

list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS)

list(APPEND ${CURRENT_PROJECT_NAME}_UNGROUPED_SOURCES)

option(BUILD_TESTS "Build unit tests" FALSE)

list(APPEND ${CURRENT_PROJECT_NAME}_HEADERS
     ${${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS})

list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
     ${${CURRENT_PROJECT_NAME}_UNGROUPED_SOURCES})

cm_setup_version(VERSION 0.1.0 PREFIX ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME})

add_library(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE)
set_target_properties(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PROPERTIES
                      EXPORT_NAME ${CURRENT_PROJECT_NAME})


target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
                      ${CMAKE_WORKSPACE_NAME}::pubkey

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
