cmake_minimum_required(VERSION 2.8.12)

cmake_policy(SET CMP0028 NEW)
cmake_policy(SET CMP0042 NEW)
cmake_policy(SET CMP0048 NEW)
cmake_policy(SET CMP0057 NEW)
cmake_policy(SET CMP0076 NEW)

list(APPEND CMAKE_MODULE_PATH
     "${CMAKE_CURRENT_LIST_DIR}/cmake"
     "${CMAKE_CURRENT_LIST_DIR}/cmake/packages"
     "${CMAKE_CURRENT_LIST_DIR}/cmake/modules/share/modules/cmake")

include(CMConfig)
include(CMSetupVersion)

if(NOT CMAKE_WORKSPACE_NAME OR NOT ("${CMAKE_WORKSPACE_NAME}" STREQUAL "crypto3"))
    cm_workspace(crypto3)
endif()

option(ZK_PLACEHOLDER_PROFILING "Build with placeholder profiling" FALSE)
option(ZK_PLACEHOLDER_DEBUG "Build with placeholder debug output" FALSE)

if(ZK_PLACEHOLDER_PROFILING)
    add_definitions(-DZK_PLACEHOLDER_PROFILING_ENABLED)
endif()

if(ZK_PLACEHOLDER_DEBUG)
    add_definitions(-DZK_PLACEHOLDER_DEBUG_ENABLED)
endif()

option(BLUEPRINT_DEBUG "Build with blueprint debug output" FALSE)

if(BLUEPRINT_DEBUG)
    message(STATUS "BLUEPRINT DEBUG enabled")
    add_definitions(-DBLUEPRINT_DEBUG_ENABLED)
endif()

option(BLUEPRINT_TESTS_PROFILING "Build tests with blueprint table profiling" FALSE)
option(BLUEPRINT_PLACEHOLDER_PROOF_GEN "Build with placeholder proof generation running" FALSE)

if(BLUEPRINT_TESTS_PROFILING)
    message(STATUS "BLUEPRINT TESTS PROFILING enabled")
    add_definitions(-DBLUEPRINT_PLONK_PROFILING_ENABLED)
endif()

if(BLUEPRINT_PLACEHOLDER_PROOF_GEN)
    message(STATUS "BLUEPRINT PROOF GENERATION enabled")
    add_definitions(-DBLUEPRINT_PLACEHOLDER_PROOF_GEN_ENABLED)
endif()

macro(cm_find_package NAME)
    foreach(ITERATOR ${CMAKE_WORKSPACE_LIST})
        if(NOT "${NAME}" MATCHES "^${ITERATOR}_.*$" AND NOT "${NAME}" STREQUAL CM)
            find_package(${ARGV})
        else()
            set(${ARGV0}_FOUND ON CACHE BOOL "")
        endif()
    endforeach()
endmacro()

cm_project(blueprint WORKSPACE_NAME ${CMAKE_WORKSPACE_NAME} LANGUAGES C CXX)

cm_find_package(CM)
include(CMDeploy)
include(FindPkgConfig)

option(BUILD_WITH_CCACHE "Build with ccache usage" TRUE)
option(BUILD_TESTS "Build unit tests" FALSE)
option(BUILD_EXAMPLES "Build examples" FALSE)

if(UNIX AND BUILD_WITH_CCACHE)
    find_program(CCACHE_FOUND ccache)
    if(CCACHE_FOUND)
        set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
        set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache)
    endif(CCACHE_FOUND)
endif()

if(UNIX AND BUILD_WITH_PROCPS)
    find_package(Procps)
endif()

list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
    include/nil/crypto3/zk/components/algebra/curves/edwards/r1cs/element_g1.hpp
    include/nil/crypto3/zk/components/algebra/curves/weierstrass/r1cs/element_g1.hpp
    include/nil/crypto3/zk/components/algebra/curves/weierstrass/r1cs/element_g2.hpp
    include/nil/crypto3/zk/components/algebra/curves/detail/r1cs/scalar_mul.hpp

    include/nil/crypto3/zk/components/algebra/fields/r1cs/exponentiation.hpp
    include/nil/crypto3/zk/components/algebra/fields/r1cs/element_fp2.hpp
    include/nil/crypto3/zk/components/algebra/fields/r1cs/element_fp3.hpp
    include/nil/crypto3/zk/components/algebra/fields/r1cs/element_fp4.hpp
    include/nil/crypto3/zk/components/algebra/fields/r1cs/element_fp6.hpp

    include/nil/crypto3/zk/components/hashes/knapsack/r1cs/knapsack.hpp
    include/nil/crypto3/zk/components/hashes/sha256/r1cs/sha256_aux.hpp
    include/nil/crypto3/zk/components/hashes/sha256/r1cs/sha256_components.hpp
    include/nil/crypto3/zk/components/hashes/sha256/r1cs/sha256_component.hpp

    include/nil/crypto3/zk/components/merkle_tree/r1cs/authentication_path.hpp
    include/nil/crypto3/zk/components/merkle_tree/r1cs/check_read.hpp
    include/nil/crypto3/zk/components/merkle_tree/r1cs/check_update.hpp

    include/nil/crypto3/zk/components/algebra/pairing/detail/r1cs/mnt4.hpp
    include/nil/crypto3/zk/components/algebra/pairing/detail/r1cs/mnt6.hpp
    include/nil/crypto3/zk/components/algebra/pairing/weierstrass/r1cs/pairing_checks.hpp
    include/nil/crypto3/zk/components/algebra/pairing/weierstrass/r1cs/final_exponentiation.hpp
    include/nil/crypto3/zk/components/algebra/pairing/weierstrass/r1cs/miller_loop.hpp
    include/nil/crypto3/zk/components/algebra/pairing/weierstrass/r1cs/precomputation.hpp

    include/nil/crypto3/zk/components/systems/snark/r1cs_pp_zksnark/verifier.hpp
    include/nil/crypto3/zk/components/detail/r1cs/packing.hpp
    include/nil/crypto3/zk/components/boolean/r1cs/comparison.hpp
    include/nil/crypto3/zk/components/boolean/r1cs/conjunction.hpp
    include/nil/crypto3/zk/components/boolean/r1cs/disjunction.hpp
    include/nil/crypto3/zk/components/boolean/r1cs/inner_product.hpp
    include/nil/crypto3/zk/components/detail/r1cs/loose_multiplexing.hpp
    include/nil/crypto3/zk/components/component_from_r1cs.hpp
    include/nil/crypto3/zk/component.hpp
    include/nil/crypto3/zk/blueprint/r1cs.hpp
    include/nil/crypto3/zk/blueprint/plonk.hpp)

list(APPEND ${CURRENT_PROJECT_NAME}_UNGROUPED_SOURCES)

list(APPEND ${CURRENT_PROJECT_NAME}_HEADERS ${${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS})

list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES ${${CURRENT_PROJECT_NAME}_UNGROUPED_SOURCES})

cm_setup_version(VERSION 0.1.0 PREFIX ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME})

add_library(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE)

set_target_properties(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PROPERTIES
                      EXPORT_NAME ${CURRENT_PROJECT_NAME})

target_include_directories(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
                           "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                           "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                           ${Boost_INCLUDE_DIRS})

target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE

                      ${Boost_LIBRARIES}

                      ${CMAKE_WORKSPACE_NAME}::algebra
                      ${CMAKE_WORKSPACE_NAME}::math
                      ${CMAKE_WORKSPACE_NAME}::hash
                      ${CMAKE_WORKSPACE_NAME}::multiprecision
                      ${CMAKE_WORKSPACE_NAME}::random
                      ${CMAKE_WORKSPACE_NAME}::zk
                      ${CMAKE_WORKSPACE_NAME}::containers)

cm_deploy(TARGETS ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
          INCLUDE include
          NAMESPACE ${CMAKE_WORKSPACE_NAME}::)

if(BUILD_TESTS)
    add_subdirectory(test)
endif()

if(BUILD_EXAMPLES)
    add_subdirectory(example)
endif()