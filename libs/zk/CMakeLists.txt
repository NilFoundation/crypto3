include(CMConfig)
include(CMSetupVersion)

if(NOT CMAKE_WORKSPACE_NAME OR NOT ("${CMAKE_WORKSPACE_NAME}" STREQUAL "crypto3"))
    cm_workspace(crypto3)
endif()

option(PROFILING_ENABLED "Build with placeholder profiling" FALSE)
option(ZK_PLACEHOLDER_DEBUG_ENABLED "Build with placeholder testing inside" FALSE)

if(PROFILING_ENABLED)
    add_definitions(-DPROFILING_ENABLED)
endif()

if(ZK_PLACEHOLDER_DEBUG_ENABLED)
    add_definitions(-DZK_PLACEHOLDER_DEBUG_ENABLED)
endif()

cm_project(zk WORKSPACE_NAME ${CMAKE_WORKSPACE_NAME} LANGUAGES C CXX)

include(CMDeploy)
include(FindPkgConfig)

cm_setup_version(VERSION 0.1.0 PREFIX ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME})

add_library(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE)

set_target_properties(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PROPERTIES
                      EXPORT_NAME ${CURRENT_PROJECT_NAME})

target_include_directories(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
                           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
                           $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>

                           $<$<BOOL:${Boost_FOUND}>:${Boost_INCLUDE_DIRS}>)

target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE

                      Boost::container
                      Boost::log

                      ${CMAKE_WORKSPACE_NAME}::algebra
                      ${CMAKE_WORKSPACE_NAME}::block
                      ${CMAKE_WORKSPACE_NAME}::math
                      ${CMAKE_WORKSPACE_NAME}::hash
                      ${CMAKE_WORKSPACE_NAME}::multiprecision
                      ${CMAKE_WORKSPACE_NAME}::containers
                      ${CMAKE_WORKSPACE_NAME}::marshalling-zk
                      ${CMAKE_WORKSPACE_NAME}::benchmark_tools
                    )

cm_deploy(TARGETS ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
          INCLUDE include
          NAMESPACE ${CMAKE_WORKSPACE_NAME}::)

include(CMTest)
cm_add_test_subdirectory(test)
