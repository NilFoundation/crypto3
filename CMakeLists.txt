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
option(BUILD_WITH_PROCPS "Build with procps for memory profiling" TRUE)
option(BUILD_TESTS "Build unit tests" FALSE)

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

     include/nil/crypto3/zk/snark/components/cpu_checkers/fooram/components/bar_component.hpp
     include/nil/crypto3/zk/snark/components/cpu_checkers/fooram/components/fooram_blueprint.hpp
     include/nil/crypto3/zk/snark/components/cpu_checkers/fooram/fooram_cpu_checker.hpp

     include/nil/crypto3/zk/snark/components/cpu_checkers/tinyram/components/alu_arithmetic.hpp
     include/nil/crypto3/zk/snark/components/cpu_checkers/tinyram/components/alu_control_flow.hpp
     include/nil/crypto3/zk/snark/components/cpu_checkers/tinyram/components/alu_component.hpp
     include/nil/crypto3/zk/snark/components/cpu_checkers/tinyram/components/argument_decoder_component.hpp
     include/nil/crypto3/zk/snark/components/cpu_checkers/tinyram/components/consistency_enforcer_component.hpp
     include/nil/crypto3/zk/snark/components/cpu_checkers/tinyram/components/memory_masking_component.hpp
     include/nil/crypto3/zk/snark/components/cpu_checkers/tinyram/components/tinyram_blueprint.hpp
     include/nil/crypto3/zk/snark/components/cpu_checkers/tinyram/components/word_variable_component.hpp
     include/nil/crypto3/zk/snark/components/cpu_checkers/tinyram/tinyram_cpu_checker.hpp

     include/nil/crypto3/zk/snark/components/curves/weierstrass_g1_component.hpp
     include/nil/crypto3/zk/snark/components/curves/weierstrass_g2_component.hpp

     include/nil/crypto3/zk/snark/components/delegated_ra_memory/memory_load_component.hpp
     include/nil/crypto3/zk/snark/components/delegated_ra_memory/memory_load_store_component.hpp

     include/nil/crypto3/zk/snark/components/fields/exponentiation_component.hpp
     include/nil/crypto3/zk/snark/components/fields/fp2_components.hpp
     include/nil/crypto3/zk/snark/components/fields/fp3_components.hpp
     include/nil/crypto3/zk/snark/components/fields/fp4_components.hpp
     include/nil/crypto3/zk/snark/components/fields/fp6_components.hpp

     include/nil/crypto3/zk/snark/components/hashes/knapsack/knapsack_component.hpp

     include/nil/crypto3/zk/snark/components/hashes/sha256/sha256_aux.hpp
     include/nil/crypto3/zk/snark/components/hashes/sha256/sha256_components.hpp
     include/nil/crypto3/zk/snark/components/hashes/sha256/sha256_component.hpp

     include/nil/crypto3/zk/snark/components/hashes/crh_component.hpp
     include/nil/crypto3/zk/snark/components/hashes/digest_selector_component.hpp
     include/nil/crypto3/zk/snark/components/hashes/hash_io.hpp

     include/nil/crypto3/zk/snark/components/merkle_tree/merkle_authentication_path_variable.hpp
     include/nil/crypto3/zk/snark/components/merkle_tree/merkle_tree_check_read_component.hpp
     include/nil/crypto3/zk/snark/components/merkle_tree/merkle_tree_check_update_component.hpp

     include/nil/crypto3/zk/snark/components/pairing/mnt_pairing_params.hpp
     include/nil/crypto3/zk/snark/components/pairing/pairing_checks.hpp
     include/nil/crypto3/zk/snark/components/pairing/pairing_params.hpp
     include/nil/crypto3/zk/snark/components/pairing/weierstrass_final_exponentiation.hpp
     include/nil/crypto3/zk/snark/components/pairing/weierstrass_miller_loop.hpp
     include/nil/crypto3/zk/snark/components/pairing/as_waksman.hpp

     include/nil/crypto3/zk/snark/components/routing/as_waksman_routing_component.hpp
     include/nil/crypto3/zk/snark/components/routing/benes_routing_component.hpp

     include/nil/crypto3/zk/snark/components/set_commitment/set_commitment_component.hpp
     include/nil/crypto3/zk/snark/components/set_commitment/set_membership_proof_variable.hpp

     include/nil/crypto3/zk/snark/components/verifiers/r1cs_ppzksnark_verifier_component.hpp
     include/nil/crypto3/zk/snark/components/basic_components.hpp
     include/nil/crypto3/zk/snark/components/component_from_r1cs.hpp

     include/nil/crypto3/zk/snark/relations/variable.hpp
     include/nil/crypto3/zk/snark/routing/as_waksman.hpp
     include/nil/crypto3/zk/snark/routing/benes.hpp
     include/nil/crypto3/zk/snark/constraint_profiling.hpp
     include/nil/crypto3/zk/snark/component.hpp
     include/nil/crypto3/zk/snark/integer_permutation.hpp
     include/nil/crypto3/zk/snark/merkle_tree.hpp
     include/nil/crypto3/zk/snark/blueprint_variable.hpp
     include/nil/crypto3/zk/snark/blueprint.hpp)

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

if(PROCPS_FOUND)
    target_compile_definitions(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
                               "${CMAKE_UPPER_WORKSPACE_NAME}_HAS_PROCPS")
endif()

target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE

                      ${Boost_LIBRARIES}

                      ${CMAKE_WORKSPACE_NAME}::algebra
                      ${CMAKE_WORKSPACE_NAME}::fft
                      ${CMAKE_WORKSPACE_NAME}::hash
                      ${CMAKE_WORKSPACE_NAME}::zk

                      $<TARGET_NAME_IF_EXISTS:boost_math>
                      $<TARGET_NAME_IF_EXISTS:boost_multiprecision>
                      )

cm_deploy(TARGETS ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
          INCLUDE include
          NAMESPACE ${CMAKE_WORKSPACE_NAME}::)


if(BUILD_TESTS)
    add_subdirectory(test)
endif()