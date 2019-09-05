cmake_minimum_required(VERSION 2.8.11)

cmake_policy(SET CMP0042 NEW)
cmake_policy(SET CMP0028 NEW)

cm_project(stream WORKSPACE_NAME ${CMAKE_WORKSPACE_NAME})

cm_find_package(CM)
include(CMDeploy)
include(CMSetupVersion)

cm_find_package(${CMAKE_WORKSPACE_NAME}_utilities)

list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
     )

list(APPEND ${CURRENT_PROJECT_NAME}_UNGROUPED_SOURCES
     )

option(CRYPTO3_STREAM_CHACHA "Build with CHACHA stream encryption support" TRUE)
option(CRYPTO3_STREAM_SALSA20 "Build with SALSA20 stream encryption support" TRUE)
option(CRYPTO3_STREAM_CTR_BE "Build with CTR BE stream encryption support" TRUE)
option(CRYPTO3_STREAM_OFB "Build with OFB stream encryption support" TRUE)
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

add_library(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
            ${${CURRENT_PROJECT_NAME}_HEADERS}
            ${${CURRENT_PROJECT_NAME}_SOURCES}
            )

set_target_properties(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PROPERTIES
                      LINKER_LANGUAGE CXX
                      EXPORT_NAME ${CURRENT_PROJECT_NAME}
                      CXX_STANDARD 14)

target_include_directories(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PRIVATE
                           "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                           "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>")

#target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PUBLIC
#                      ${CMAKE_WORKSPACE_NAME}::utilities)

cm_deploy(TARGETS ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
          INCLUDE include
          NAMESPACE ${CMAKE_WORKSPACE_NAME}::)

if(APPLE OR NOT ${CMAKE_TARGET_ARCHITECTURE} STREQUAL ${CMAKE_HOST_SYSTEM_PROCESSOR})
    set_target_properties(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PROPERTIES
                          XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY "${APPLE_CODE_SIGN_IDENTITY}"
                          XCODE_ATTRIBUTE_DEVELOPMENT_TEAM "${CMAKE_XCODE_ATTRIBUTE_DEVELOPMENT_TEAM}")
endif()

if(BUILD_TESTS)
    add_subdirectory(test)
endif()