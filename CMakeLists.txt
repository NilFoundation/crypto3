cmake_minimum_required(VERSION 2.8.11)

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

if(NOT ${CMAKE_WORKSPACE_NAME} STREQUAL crypto3)
    cm_workspace(crypto3)
endif()

cm_project(codec WORKSPACE_NAME ${CMAKE_WORKSPACE_NAME} LANGUAGES C CXX)

macro(cm_find_package NAME)
    if(NOT "${NAME}" MATCHES "^${CMAKE_WORKSPACE_NAME}_.*$" AND NOT "${NAME}" STREQUAL CM)
        find_package(${ARGV})
    else()
        set(${ARGV0}_FOUND ON CACHE BOOL "")
    endif()
endmacro()

if(NOT Boost_FOUND AND NOT BUILD_TESTS)
    cm_find_package(Boost REQUIRED COMPONENTS container)
    else()
    cm_find_package(Boost REQUIRED COMPONENTS container unit_test_framework)
endif()

option(BUILD_WITH_CCACHE "Build with ccache usage" TRUE)
option(BUILD_UNIT_TESTS "Build unit tests" FALSE)

configure_file(${CMAKE_CURRENT_LIST_DIR}/cmake/build.hpp.in
               ${CMAKE_BINARY_DIR}/include/nil/${CMAKE_WORKSPACE_NAME}/build.hpp @ONLY)

list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
     include/nil/crypto3/codec/detail/base_policy.hpp
     include/nil/crypto3/codec/detail/hex_policy.hpp

     include/nil/crypto3/codec/detail/exploder.hpp
     include/nil/crypto3/codec/detail/unbounded_shift.hpp
     include/nil/crypto3/codec/detail/imploder.hpp
     include/nil/crypto3/codec/detail/stream_endian.hpp

     include/nil/crypto3/codec/codec_value.hpp
     include/nil/crypto3/codec/codec_state.hpp

     include/nil/crypto3/codec/hex.hpp
     include/nil/crypto3/codec/base.hpp

     include/nil/crypto3/codec/algorithm/encode.hpp
     include/nil/crypto3/codec/algorithm/decode.hpp

     include/nil/crypto3/codec/adaptor/encoded.hpp
     include/nil/crypto3/codec/adaptor/decoded.hpp
     )

list(APPEND ${CURRENT_PROJECT_NAME}_HEADERS
     ${${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS}
     )

cm_setup_version(VERSION 0.1.0 PREFIX ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME})

if(${CMAKE_CXX_STANDARD} LESS 17)
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         src/base_policy.cpp
         src/hex_policy.cpp)

    add_library(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
                ${${CURRENT_PROJECT_NAME}_HEADERS}
                ${${CURRENT_PROJECT_NAME}_SOURCES})

    if(TARGET boost::multiprecision)
        target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PRIVATE

                              ${Boost_LIBRARIES}

                              boost::multiprecision)
    else()
        target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PRIVATE

                              ${Boost_LIBRARIES})
    endif()

    target_include_directories(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PRIVATE
                               "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                               "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                               ${Boost_INCLUDE_DIR})

    set_target_properties(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PROPERTIES
                          EXPORT_NAME ${CURRENT_PROJECT_NAME}
                          CXX_STANDARD 11
                          CXX_STANDARD_REQUIRED TRUE
                          CXX_EXTENSIONS FALSE)
else()
    add_library(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE)

    if(TARGET boost::multiprecision)
        target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE

                              ${Boost_LIBRARIES}

                              boost::multiprecision)
    else()
        target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE

                              ${Boost_LIBRARIES})
    endif()

    target_include_directories(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
                               "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                               "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                               ${Boost_INCLUDE_DIR})

    set_target_properties(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PROPERTIES
                          EXPORT_NAME ${CURRENT_PROJECT_NAME})
endif()

cm_deploy(TARGETS ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
          INCLUDE include
          NAMESPACE ${CMAKE_WORKSPACE_NAME}::)

if(BUILD_UNIT_TESTS)
    add_subdirectory(test)
endif()