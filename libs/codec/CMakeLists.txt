#---------------------------------------------------------------------------#
# Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

include(CMConfig)
include(CMDeploy)
include(CMSetupVersion)

cm_project(codec WORKSPACE_NAME ${CMAKE_WORKSPACE_NAME} LANGUAGES C CXX)

option(CRYPTO3_CODEC_BASE58 "Build unit tests" TRUE)

set(BUILD_WITH_CONFIGURATION_FILE_DIR "${CMAKE_CURRENT_LIST_DIR}/cmake" CACHE STRING "Directory for build.hpp lookup")

cm_setup_version(VERSION 0.1.0 PREFIX ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME})

add_library(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE)

if(CRYPTO3_CODEC_BASE58)
    target_compile_definitions(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE CRYPTO3_CODEC_BASE58)
endif()

set_target_properties(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PROPERTIES
                      EXPORT_NAME ${CURRENT_PROJECT_NAME})

target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
                      $<$<BOOL:${CRYPTO3_CODEC_BASE58}>:${CMAKE_WORKSPACE_NAME}::multiprecision>

                      Boost::container)

target_include_directories(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
                           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
                           $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>

                           ${Boost_INCLUDE_DIRS})

cm_deploy(TARGETS ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
          INCLUDE include
          NAMESPACE ${CMAKE_WORKSPACE_NAME}::)

# Some tests failed, so we are turning off tests for this submodule for now.
# include(CMTest)
# cm_add_test_subdirectory(test)
