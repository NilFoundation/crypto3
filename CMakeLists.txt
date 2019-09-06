cmake_minimum_required(VERSION 3.12.4)

cmake_policy(SET CMP0028 NEW)
cmake_policy(SET CMP0042 NEW)
cmake_policy(SET CMP0048 NEW)
cmake_policy(SET CMP0057 NEW)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake"
     "${CMAKE_CURRENT_LIST_DIR}/cmake/packages"
     "${CMAKE_CURRENT_LIST_DIR}/cmake/modules/share/modules/cmake")

include(CMConfig)
include(CMDeploy)
include(CMSetupVersion)

if(NOT CMAKE_WORKSPACE_NAME OR NOT ("${CMAKE_WORKSPACE_NAME}" STREQUAL "crypto3"))
    cm_workspace(crypto3)
endif()

cm_project(stream WORKSPACE_NAME ${CMAKE_WORKSPACE_NAME} LANGUAGES C CXX)

cm_find_package(CM)
include(CMDeploy)
include(CMSetupVersion)

option(BUILD_WITH_CCACHE "Build with ccache usage" TRUE)
option(BUILD_TESTS "Build unit tests" FALSE)

list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
     )

list(APPEND ${CURRENT_PROJECT_NAME}_UNGROUPED_SOURCES
     )

option(CRYPTO3_STREAM_CHACHA "Build with CHACHA stream encryption support" TRUE)
option(CRYPTO3_STREAM_SALSA20 "Build with SALSA20 stream encryption support" TRUE)
option(CRYPTO3_STREAM_RC4 "Build with RC4 stream encryption support" TRUE)

if(CRYPTO3_STREAM_CHACHA)
    list(APPEND ${CURRENT_PROJECT_NAME}_CHACHA_HEADERS
         include/nil/crypto3/stream/chacha.hpp
         )

    if(${CMAKE_TARGET_ARCHITECTURE} STREQUAL "x86_64" OR
       ${CMAKE_TARGET_ARCHITECTURE} STREQUAL "x86")
        add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_CHACHA_SSE2)
    endif()

    list(APPEND ${CURRENT_PROJECT_NAME}_CHACHA_SOURCES
         src/chacha_policy.cpp
         )

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_CHACHA)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_CHACHA_HEADERS}
         )
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_CHACHA_SOURCES}
         )
endif()

if(CRYPTO3_STREAM_SALSA20)
    list(APPEND ${CURRENT_PROJECT_NAME}_SALSA20_HEADERS
         include/nil/crypto3/stream/salsa20.hpp
         )

    list(APPEND ${CURRENT_PROJECT_NAME}_SALSA20_SOURCES
         src/salsa20_policy.cpp
         )

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_SALSA20)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_SALSA20_HEADERS}
         )
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_SALSA20_SOURCES}
         )
endif()

if(CRYPTO3_STREAM_RC4)
    list(APPEND ${CURRENT_PROJECT_NAME}_RC4_HEADERS
         include/nil/crypto3/stream/rc4.hpp
         )

    list(APPEND ${CURRENT_PROJECT_NAME}_RC4_SOURCES
         )

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_RC4)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_RC4_HEADERS}
         )
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_RC4_SOURCES}
         )
endif()

list(APPEND ${CURRENT_PROJECT_NAME}_HEADERS
     ${${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS}
     )

list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
     ${${CURRENT_PROJECT_NAME}_UNGROUPED_SOURCES}
     )

cm_setup_version(VERSION 0.1.0 PREFIX ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME})

if((NOT CMAKE_CXX_STANDARD) OR (CMAKE_CXX_STANDARD LESS 17))
    add_library(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
                ${${CURRENT_PROJECT_NAME}_HEADERS}
                ${${CURRENT_PROJECT_NAME}_SOURCES})
    target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PRIVATE
                          ${Boost_LIBRARIES})
    if(APPLE OR NOT ${CMAKE_TARGET_ARCHITECTURE} STREQUAL ${CMAKE_HOST_SYSTEM_PROCESSOR})
        set_target_properties(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PROPERTIES
                              EXPORT_NAME ${CURRENT_PROJECT_NAME}
                              CXX_STANDARD 11
                              CXX_STANDARD_REQUIRED TRUE
                              XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY "${APPLE_CODE_SIGN_IDENTITY}"
                              XCODE_ATTRIBUTE_DEVELOPMENT_TEAM "${CMAKE_XCODE_ATTRIBUTE_DEVELOPMENT_TEAM}")
    else()
        set_target_properties(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PROPERTIES
                              EXPORT_NAME ${CURRENT_PROJECT_NAME}
                              CXX_STANDARD 11
                              CXX_STANDARD_REQUIRED TRUE)
    endif()
    target_include_directories(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PRIVATE
                               "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                               "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                               ${Boost_INCLUDE_DIRS})
else()
    add_library(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE)
    target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
                          ${Boost_LIBRARIES})
    set_target_properties(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PROPERTIES
                          EXPORT_NAME ${CURRENT_PROJECT_NAME})
    target_include_directories(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
                               "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                               "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                               ${Boost_INCLUDE_DIRS})
endif()

cm_deploy(TARGETS ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
          INCLUDE include
          NAMESPACE ${CMAKE_WORKSPACE_NAME}::)

if(BUILD_TESTS)
    add_subdirectory(test)
endif()