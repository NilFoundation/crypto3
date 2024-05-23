#---------------------------------------------------------------------------#
# Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
# Copyright (c) 2018-2020 Alexey Moskvin
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

option(BUILD_WITH_CI_KNOWN_ISSUES_SUPPRESS "Build for CI suppressing known issues" FALSE)

if(BUILD_WITH_CI_KNOWN_ISSUES_SUPPRESS)
    add_definitions(-DCI_SUPPRESS_KNOWN_ISSUES)
endif()

if("${CMAKE_WORKSPACE_NAME}" STREQUAL "boost")
    set(BOOST_CMAKE TRUE)
else()
    cm_workspace(crypto3 SOURCES_DIR "${CMAKE_CURRENT_LIST_DIR}")

    if(NOT Boost_FOUND AND NOT CMAKE_CROSSCOMPILING)
        find_package(Boost COMPONENTS REQUIRED random)
    endif()
endif()

cm_project(multiprecision WORKSPACE_NAME ${CMAKE_WORKSPACE_NAME})

cm_setup_version(VERSION 1.76.0 PREFIX ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME})

add_library(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE)

target_include_directories(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
                           $<$<BOOL:${Boost_FOUND}>:${Boost_INCLUDE_DIRS}>)

if("${CMAKE_WORKSPACE_NAME}" STREQUAL "boost")
    cm_find_package(${CMAKE_WORKSPACE_NAME}_core)
    cm_find_package(${CMAKE_WORKSPACE_NAME}_static_assert)
    cm_find_package(${CMAKE_WORKSPACE_NAME}_predef)
    cm_find_package(${CMAKE_WORKSPACE_NAME}_mpl)
    cm_find_package(${CMAKE_WORKSPACE_NAME}_random)
    cm_find_package(${CMAKE_WORKSPACE_NAME}_functional)
    cm_find_package(${CMAKE_WORKSPACE_NAME}_assert)
    cm_find_package(${CMAKE_WORKSPACE_NAME}_type_traits)
    cm_find_package(${CMAKE_WORKSPACE_NAME}_smart_ptr)
    cm_find_package(${CMAKE_WORKSPACE_NAME}_rational)
    cm_find_package(${CMAKE_WORKSPACE_NAME}_lexical_cast)
    cm_find_package(${CMAKE_WORKSPACE_NAME}_integer)
    cm_find_package(${CMAKE_WORKSPACE_NAME}_array)
    cm_find_package(${CMAKE_WORKSPACE_NAME}_config)
    cm_find_package(${CMAKE_WORKSPACE_NAME}_throw_exception)
    cm_find_package(${CMAKE_WORKSPACE_NAME}_math)

    target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE ${CMAKE_WORKSPACE_NAME}::core)
    target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE ${CMAKE_WORKSPACE_NAME}::static_assert)
    target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE ${CMAKE_WORKSPACE_NAME}::predef)
    target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE ${CMAKE_WORKSPACE_NAME}::mpl)
    target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE ${CMAKE_WORKSPACE_NAME}::random)
    target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE ${CMAKE_WORKSPACE_NAME}::functional)
    target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE ${CMAKE_WORKSPACE_NAME}::assert)
    target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE ${CMAKE_WORKSPACE_NAME}::type_traits)
    target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE ${CMAKE_WORKSPACE_NAME}::smart_ptr)
    target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE ${CMAKE_WORKSPACE_NAME}::rational)
    target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE ${CMAKE_WORKSPACE_NAME}::lexical_cast)
    target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE ${CMAKE_WORKSPACE_NAME}::integer)
    target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE ${CMAKE_WORKSPACE_NAME}::array)
    target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE ${CMAKE_WORKSPACE_NAME}::config)
    target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE ${CMAKE_WORKSPACE_NAME}::throw_exception)
    target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE ${CMAKE_WORKSPACE_NAME}::math)

else()
    target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
                          ${Boost_LIBRARIES})
endif()

set_target_properties(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PROPERTIES
                      EXPORT_NAME ${CURRENT_PROJECT_NAME})

cm_deploy(TARGETS ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
          INCLUDE ${CURRENT_SOURCES_DIR}/include
          NAMESPACE ${CMAKE_WORKSPACE_NAME}::)

include(CMTest)
cm_add_test_subdirectory(test)
