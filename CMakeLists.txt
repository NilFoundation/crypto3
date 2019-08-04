cmake_minimum_required(VERSION 2.8.11)

cmake_policy(SET CMP0042 NEW)
cmake_policy(SET CMP0028 NEW)

if(NOT ${CMAKE_WORKSPACE_NAME} STREQUAL crypto3)
    cm_workspace(crypto3)
endif()

cm_project(codec WORKSPACE_NAME ${CMAKE_WORKSPACE_NAME} LANGUAGES C CXX)

if(NOT Boost_FOUND)
    cm_find_package(Boost REQUIRED)
endif()

option(BUILD_UNIT_TESTS "Build unit tests" FALSE)

list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
     include/nil/crypto3/codec/detail/base_policy.hpp
     include/nil/crypto3/codec/detail/hex_policy.hpp

     include/nil/crypto3/codec/detail/exploder.hpp
     include/nil/crypto3/codec/detail/unbounded_shift.hpp
     include/nil/crypto3/codec/detail/imploder.hpp
     include/nil/crypto3/codec/detail/codec_value.hpp

     include/nil/crypto3/codec/hex.hpp
     include/nil/crypto3/codec/zlib.hpp

     include/nil/crypto3/codec/detail/codec_state.hpp
     include/nil/crypto3/codec/stream_endian.hpp

     include/nil/crypto3/codec/algorithm/encode.hpp
     include/nil/crypto3/codec/algorithm/decode.hpp

     include/nil/crypto3/codec/adaptor/encoded.hpp
     include/nil/crypto3/codec/adaptor/decoded.hpp
     )

list(APPEND ${CURRENT_PROJECT_NAME}_HEADERS
     ${${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS}
     )

cm_setup_version(VERSION 0.1.0 PREFIX ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME})

add_library(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE)
set_property(TARGET ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PROPERTY EXPORT_NAME ${CURRENT_PROJECT_NAME})

target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE

                      ${Boost_LIBRARIES})

target_include_directories(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
                           "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                           "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                           ${Boost_INCLUDE_DIR})

cm_deploy(TARGETS ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INCLUDE include NAMESPACE ${CMAKE_WORKSPACE_NAME}::)

if(BUILD_UNIT_TESTS)
    add_subdirectory(test)
endif()