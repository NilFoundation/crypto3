#---------------------------------------------------------------------------#
# Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

include(CMConfig)
include(CMSetupVersion)

cm_project(algebra WORKSPACE_NAME ${CMAKE_WORKSPACE_NAME} LANGUAGES ASM C CXX)

include(CMDeploy)

# Blurprint components are using point {0, 0} as a point in infinity, while the stadard is {0, 1}
# for most curves. We will use compatibility mode with blueprint as default. Setting this flag to
# TRUE will change the value of inf point for all curves to the standard value.
option(STANDARD_EC_INF_POINTS "Use standard zero points for Eliptic Curves" FALSE)

if(STANDARD_EC_INF_POINTS)
    add_definitions(-DSTANDARD_EC_INF_POINTS_ENABLED)
endif()

cm_setup_version(VERSION 0.1.0 PREFIX ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME})

add_library(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE)

set_target_properties(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PROPERTIES
        EXPORT_NAME ${CURRENT_PROJECT_NAME})

target_include_directories(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>)

target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
        ${CMAKE_WORKSPACE_NAME}::multiprecision)

cm_deploy(TARGETS ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
        INCLUDE include
        NAMESPACE ${CMAKE_WORKSPACE_NAME}::)

include(CMTest)
cm_add_test_subdirectory(test)

if(BUILD_EXAMPLES)
    add_subdirectory(example)
endif()

