#---------------------------------------------------------------------------#
# Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

cmake_minimum_required(VERSION 3.5)

set(BOOST_CMAKE FALSE)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake"
     "${CMAKE_CURRENT_LIST_DIR}/cmake/packages"
     "${CMAKE_CURRENT_LIST_DIR}/cmake/modules/share/modules/cmake")

include(CMDeploy)
include(CMConfig)
include(CMSetupVersion)

cm_workspace(crypto3 SOURCES_DIR "${CMAKE_CURRENT_LIST_DIR}")

cm_find_package(${CMAKE_WORKSPACE_NAME}_random)

cm_project(random WORKSPACE_NAME ${CMAKE_WORKSPACE_NAME})

cm_setup_version(VERSION 1.74.0 PREFIX ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME})

add_library(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE)
set_property(TARGET ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PROPERTY
             EXPORT_NAME ${CURRENT_PROJECT_NAME})

target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE

                      ${CMAKE_WORKSPACE_NAME}::algebra
                      ${CMAKE_WORKSPACE_NAME}::hash
                      ${CMAKE_WORKSPACE_NAME}::mac
                      ${CMAKE_WORKSPACE_NAME}::stream

                      marshalling::crypto3_algebra

                      Boost::container)
target_include_directories(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
                           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
                           $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>

                           $<$<BOOL:${Boost_FOUND}>:${Boost_INCLUDE_DIRS}>)

cm_deploy(TARGETS ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
          INCLUDE ${CURRENT_SOURCES_DIR}/include
          NAMESPACE ${CMAKE_WORKSPACE_NAME}::)

include(CMTest)
cm_add_test_subdirectory(test)

if(BUILD_EXAMPLES)
    add_subdirectory(example)
endif()
