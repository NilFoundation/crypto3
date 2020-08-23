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

cm_setup_version(VERSION 1.74.0)

option(BUILD_TESTS "Build unit tests" FALSE)

if("${CMAKE_WORKSPACE_NAME}" STREQUAL "boost")
    set(BOOST_CMAKE TRUE)

    cm_project(random WORKSPACE_NAME ${CMAKE_WORKSPACE_NAME})

    find_package(${CMAKE_WORKSPACE_NAME}_core)
    find_package(${CMAKE_WORKSPACE_NAME}_config)
    find_package(${CMAKE_WORKSPACE_NAME}_math)

    add_library(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} "src/random_device.cpp")
    set_property(TARGET ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PROPERTY EXPORT_NAME ${CURRENT_PROJECT_NAME})

    target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PRIVATE ${CMAKE_WORKSPACE_NAME}::core)
    target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PRIVATE ${CMAKE_WORKSPACE_NAME}::config)
    target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PRIVATE ${CMAKE_WORKSPACE_NAME}::math)
    target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PRIVATE
                          ${CMAKE_WORKSPACE_NAME}::multiprecision)

    target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PRIVATE crypto3::stream)

else()
    cm_workspace(boost SOURCES_DIR "${CMAKE_CURRENT_LIST_DIR}")

    find_package(Boost REQUIRED)

    cm_project(random WORKSPACE_NAME ${CMAKE_WORKSPACE_NAME})

    add_library(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} "src/random_device.cpp")
    set_property(TARGET ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PROPERTY EXPORT_NAME ${CURRENT_PROJECT_NAME})

    target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PRIVATE ${Boost_LIBRARIES})
    target_include_directories(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PRIVATE
                               $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
                               $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>

                               crypto3::stream

                               ${Boost_INCLUDE_DIR})
endif()

cm_deploy(TARGETS ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
          INCLUDE ${CURRENT_SOURCES_DIR}/include
          NAMESPACE ${CMAKE_WORKSPACE_NAME}::)

if(BUILD_TESTS)
    add_subdirectory(test)
endif()
