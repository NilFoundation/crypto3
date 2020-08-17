cmake_minimum_required(VERSION 2.8.11)

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

cm_project(zk WORKSPACE_NAME ${CMAKE_WORKSPACE_NAME} LANGUAGES C CXX)

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
     include/nil/crypto3/zk/snark/common/data_structures/accumulation_vector.hpp
     include/nil/crypto3/zk/snark/common/data_structures/integer_permutation.hpp
     include/nil/crypto3/zk/snark/common/data_structures/merkle_tree.hpp
     include/nil/crypto3/zk/snark/common/data_structures/set_commitment.hpp
     include/nil/crypto3/zk/snark/common/data_structures/sparse_vector.hpp

     include/nil/crypto3/zk/snark/common/routing_algorithms/as_waksman_routing_algorithm.hpp
     include/nil/crypto3/zk/snark/common/routing_algorithms/benes_routing_algorithm.hpp
     include/nil/crypto3/zk/snark/common/serialization.hpp

     include/nil/crypto3/zk/snark/gadgets/cpu_checkers/fooram/components/bar_gadget.hpp
     include/nil/crypto3/zk/snark/gadgets/cpu_checkers/fooram/components/fooram_protoboard.hpp

     include/nil/crypto3/zk/snark/gadgets/cpu_checkers/fooram/fooram_cpu_checker.hpp

     include/nil/crypto3/zk/snark/gadgets/cpu_checkers/tinyram/components/alu_arithmetic.hpp
     include/nil/crypto3/zk/snark/gadgets/cpu_checkers/tinyram/components/alu_control_flow.hpp
     include/nil/crypto3/zk/snark/gadgets/cpu_checkers/tinyram/components/alu_gadget.hpp
     include/nil/crypto3/zk/snark/gadgets/cpu_checkers/tinyram/components/argument_decoder_gadget.hpp
     include/nil/crypto3/zk/snark/gadgets/cpu_checkers/tinyram/components/consistency_enforcer_gadget.hpp
     include/nil/crypto3/zk/snark/gadgets/cpu_checkers/tinyram/components/memory_masking_gadget.hpp
     include/nil/crypto3/zk/snark/gadgets/cpu_checkers/tinyram/components/tinyram_protoboard.hpp
     include/nil/crypto3/zk/snark/gadgets/cpu_checkers/tinyram/components/word_variable_gadget.hpp
     include/nil/crypto3/zk/snark/gadgets/cpu_checkers/tinyram/tinyram_cpu_checker.hpp

     include/nil/crypto3/zk/snark/gadgets/curves/weierstrass_g1_gadget.hpp
     include/nil/crypto3/zk/snark/gadgets/curves/weierstrass_g2_gadget.hpp

     include/nil/crypto3/zk/snark/gadgets/delegated_ra_memory/memory_load_gadget.hpp
     include/nil/crypto3/zk/snark/gadgets/delegated_ra_memory/memory_load_store_gadget.hpp

     include/nil/crypto3/zk/snark/gadgets/fields/exponentiation_gadget.hpp
     include/nil/crypto3/zk/snark/gadgets/fields/fp2_gadgets.hpp
     include/nil/crypto3/zk/snark/gadgets/fields/fp3_gadgets.hpp
     include/nil/crypto3/zk/snark/gadgets/fields/fp4_gadgets.hpp
     include/nil/crypto3/zk/snark/gadgets/fields/fp6_gadgets.hpp

     include/nil/crypto3/zk/snark/gadgets/hashes/knapsack/knapsack_gadget.hpp

     include/nil/crypto3/zk/snark/gadgets/hashes/sha256/sha256_aux.hpp
     include/nil/crypto3/zk/snark/gadgets/hashes/sha256/sha256_components.hpp
     include/nil/crypto3/zk/snark/gadgets/hashes/sha256/sha256_gadget.hpp
     include/nil/crypto3/zk/snark/gadgets/hashes/crh_gadget.hpp
     include/nil/crypto3/zk/snark/gadgets/hashes/digest_selector_gadget.hpp
     include/nil/crypto3/zk/snark/gadgets/hashes/hash_io.hpp

     include/nil/crypto3/zk/snark/gadgets/merkle_tree/merkle_authentication_path_variable.hpp
     include/nil/crypto3/zk/snark/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp
     include/nil/crypto3/zk/snark/gadgets/merkle_tree/merkle_tree_check_update_gadget.hpp

     include/nil/crypto3/zk/snark/gadgets/pairing/mnt_pairing_params.hpp
     include/nil/crypto3/zk/snark/gadgets/pairing/pairing_checks.hpp
     include/nil/crypto3/zk/snark/gadgets/pairing/pairing_params.hpp
     include/nil/crypto3/zk/snark/gadgets/pairing/weierstrass_final_exponentiation.hpp
     include/nil/crypto3/zk/snark/gadgets/pairing/weierstrass_miller_loop.hpp
     include/nil/crypto3/zk/snark/gadgets/pairing/weierstrass_precomputation.hpp

     include/nil/crypto3/zk/snark/gadgets/routing/as_waksman_routing_gadget.hpp
     include/nil/crypto3/zk/snark/gadgets/routing/benes_routing_gadget.hpp

     include/nil/crypto3/zk/snark/gadgets/set_commitment/set_commitment_gadget.hpp
     include/nil/crypto3/zk/snark/gadgets/set_commitment/set_membership_proof_variable.hpp

     include/nil/crypto3/zk/snark/gadgets/verifiers/r1cs_ppzksnark_verifier_gadget.hpp

     include/nil/crypto3/zk/snark/gadgets/basic_gadgets.hpp
     include/nil/crypto3/zk/snark/gadgets/gadget_from_r1cs.hpp

     include/nil/crypto3/zk/snark/constraint_profiling.hpp
     include/nil/crypto3/zk/snark/gadget.hpp
     include/nil/crypto3/zk/snark/pb_variable.hpp
     include/nil/crypto3/zk/snark/protoboard.hpp

     include/nil/crypto3/zk/snark/knowledge_commitment/kc_multiexp.hpp
     include/nil/crypto3/zk/snark/knowledge_commitment/knowledge_commitment.hpp

     include/nil/crypto3/zk/snark/reductions/bacs_to_r1cs/bacs_to_r1cs.hpp

     include/nil/crypto3/zk/snark/reductions/r1cs_to_qap/r1cs_to_qap.hpp

     include/nil/crypto3/zk/snark/reductions/r1cs_to_sap/r1cs_to_sap.hpp

     include/nil/crypto3/zk/snark/reductions/ram_to_r1cs/gadgets/memory_checker_gadget.hpp
     include/nil/crypto3/zk/snark/reductions/ram_to_r1cs/gadgets/ram_universal_gadget.hpp
     include/nil/crypto3/zk/snark/reductions/ram_to_r1cs/gadgets/trace_lines.hpp

     include/nil/crypto3/zk/snark/reductions/ram_to_r1cs/ram_to_r1cs.hpp

     include/nil/crypto3/zk/snark/reductions/tbcs_to_uscs/tbcs_to_uscs.hpp

     include/nil/crypto3/zk/snark/reductions/uscs_to_ssp/uscs_to_ssp.hpp

     include/nil/crypto3/zk/snark/relations/arithmetic_programs/qap/qap.hpp

     include/nil/crypto3/zk/snark/relations/arithmetic_programs/sap/sap.hpp

     include/nil/crypto3/zk/snark/relations/arithmetic_programs/ssp/ssp.hpp

     include/nil/crypto3/zk/snark/relations/circuit_satisfaction_problems/bacs/bacs.hpp

     include/nil/crypto3/zk/snark/relations/circuit_satisfaction_problems/tbcs/tbcs.hpp

     include/nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp

     include/nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/uscs/uscs.hpp

     include/nil/crypto3/zk/snark/relations/ram_computations/memory/delegated_ra_memory.hpp
     include/nil/crypto3/zk/snark/relations/ram_computations/memory/memory_interface.hpp
     include/nil/crypto3/zk/snark/relations/ram_computations/memory/memory_store_trace.hpp
     include/nil/crypto3/zk/snark/relations/ram_computations/memory/ra_memory.hpp

     include/nil/crypto3/zk/snark/relations/ram_computations/rams/fooram/fooram_aux.hpp
     include/nil/crypto3/zk/snark/relations/ram_computations/rams/fooram/fooram_params.hpp

     include/nil/crypto3/zk/snark/relations/ram_computations/rams/tinyram/tinyram_aux.hpp
     include/nil/crypto3/zk/snark/relations/ram_computations/rams/tinyram/tinyram_params.hpp
     include/nil/crypto3/zk/snark/relations/ram_computations/rams/ram_params.hpp
     include/nil/crypto3/zk/snark/relations/variable.hpp

     include/nil/crypto3/zk/snark/proof_systems/pcd/r1cs_pcd/compliance_predicate/compliance_predicate.hpp
     include/nil/crypto3/zk/snark/proof_systems/pcd/r1cs_pcd/compliance_predicate/cp_handler.hpp

     include/nil/crypto3/zk/snark/proof_systems/pcd/r1cs_pcd/r1cs_mp_ppzkpcd/mp_pcd_circuits.hpp
     include/nil/crypto3/zk/snark/proof_systems/pcd/r1cs_pcd/r1cs_mp_ppzkpcd/r1cs_mp_ppzkpcd.hpp
     include/nil/crypto3/zk/snark/proof_systems/pcd/r1cs_pcd/r1cs_mp_ppzkpcd/r1cs_mp_ppzkpcd_params.hpp

     include/nil/crypto3/zk/snark/proof_systems/pcd/r1cs_pcd/r1cs_sp_ppzkpcd/r1cs_sp_ppzkpcd.hpp
     include/nil/crypto3/zk/snark/proof_systems/pcd/r1cs_pcd/r1cs_sp_ppzkpcd/r1cs_sp_ppzkpcd_params.hpp
     include/nil/crypto3/zk/snark/proof_systems/pcd/r1cs_pcd/r1cs_sp_ppzkpcd/sp_pcd_circuits.hpp
     include/nil/crypto3/zk/snark/proof_systems/pcd/r1cs_pcd/ppzkpcd_compliance_predicate.hpp
     include/nil/crypto3/zk/snark/proof_systems/pcd/r1cs_pcd/r1cs_pcd_params.hpp

     include/nil/crypto3/zk/snark/proof_systems/ppzkadsnark/r1cs_ppzkadsnark/r1cs_ppzkadsnark.hpp
     include/nil/crypto3/zk/snark/proof_systems/ppzkadsnark/r1cs_ppzkadsnark/r1cs_ppzkadsnark_params.hpp
     include/nil/crypto3/zk/snark/proof_systems/ppzkadsnark/r1cs_ppzkadsnark/r1cs_ppzkadsnark_prf.hpp
     include/nil/crypto3/zk/snark/proof_systems/ppzkadsnark/r1cs_ppzkadsnark/r1cs_ppzkadsnark_signature.hpp

     include/nil/crypto3/zk/snark/proof_systems/ppzksnark/bacs_ppzksnark/bacs_ppzksnark.hpp
     include/nil/crypto3/zk/snark/proof_systems/ppzksnark/bacs_ppzksnark/bacs_ppzksnark_params.hpp

     include/nil/crypto3/zk/snark/proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp
     include/nil/crypto3/zk/snark/proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark_params.hpp

     include/nil/crypto3/zk/snark/proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp
     include/nil/crypto3/zk/snark/proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark_params.hpp

     include/nil/crypto3/zk/snark/proof_systems/ppzksnark/r1cs_se_ppzksnark/r1cs_se_ppzksnark.hpp
     include/nil/crypto3/zk/snark/proof_systems/ppzksnark/r1cs_se_ppzksnark/r1cs_se_ppzksnark_params.hpp

     include/nil/crypto3/zk/snark/proof_systems/ppzksnark/ram_ppzksnark/ram_ppzksnark.hpp
     include/nil/crypto3/zk/snark/proof_systems/ppzksnark/ram_ppzksnark/ram_ppzksnark_params.hpp

     include/nil/crypto3/zk/snark/proof_systems/ppzksnark/tbcs_ppzksnark/tbcs_ppzksnark.hpp
     include/nil/crypto3/zk/snark/proof_systems/ppzksnark/tbcs_ppzksnark/tbcs_ppzksnark_params.hpp

     include/nil/crypto3/zk/snark/proof_systems/ppzksnark/uscs_ppzksnark/uscs_ppzksnark.hpp
     include/nil/crypto3/zk/snark/proof_systems/ppzksnark/uscs_ppzksnark/uscs_ppzksnark_params.hpp

     include/nil/crypto3/zk/snark/proof_systems/zksnark/ram_zksnark/ram_compliance_predicate.hpp
     include/nil/crypto3/zk/snark/proof_systems/zksnark/ram_zksnark/ram_zksnark.hpp
     include/nil/crypto3/zk/snark/proof_systems/zksnark/ram_zksnark/ram_zksnark_params.hpp)

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

                      $<TARGET_NAME_IF_EXISTS:boost_math>
                      $<TARGET_NAME_IF_EXISTS:boost_multiprecision>)

cm_deploy(TARGETS ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
          INCLUDE include
          NAMESPACE ${CMAKE_WORKSPACE_NAME}::)


if(BUILD_TESTS)
    add_subdirectory(test)
endif()