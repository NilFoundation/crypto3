cmake_minimum_required(VERSION 2.8.12)

cmake_policy(SET CMP0025 NEW)
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
option(BUILD_TESTS "Build unit tests" FALSE)

if(UNIX AND BUILD_WITH_CCACHE)
    find_program(CCACHE_FOUND ccache)
    if(CCACHE_FOUND)
        set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
        set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache)
    endif(CCACHE_FOUND)
endif()

list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
     include/nil/crypto3/zk/snark/accumulators/snark.hpp

     include/nil/crypto3/zk/snark/detail/accumulation_vector.hpp
     include/nil/crypto3/zk/snark/detail/set_commitment.hpp
     include/nil/crypto3/zk/snark/detail/sparse_vector.hpp

     include/nil/crypto3/zk/snark/commitments/knowledge_commitment_multiexp.hpp
     include/nil/crypto3/zk/snark/commitments/knowledge_commitment.hpp

     include/nil/crypto3/zk/snark/schemes/pcd/r1cs_pcd/compliance_predicate/compliance_predicate.hpp
     include/nil/crypto3/zk/snark/schemes/pcd/r1cs_pcd/compliance_predicate/cp_handler.hpp

     include/nil/crypto3/zk/snark/schemes/pcd/r1cs_pcd/r1cs_mp_ppzkpcd/mp_pcd_circuits.hpp
     include/nil/crypto3/zk/snark/schemes/pcd/r1cs_pcd/r1cs_mp_ppzkpcd/r1cs_mp_ppzkpcd.hpp
     include/nil/crypto3/zk/snark/schemes/pcd/r1cs_pcd/r1cs_mp_ppzkpcd/r1cs_mp_ppzkpcd_params.hpp

     include/nil/crypto3/zk/snark/schemes/pcd/r1cs_pcd/r1cs_sp_ppzkpcd/r1cs_sp_ppzkpcd.hpp
     include/nil/crypto3/zk/snark/schemes/pcd/r1cs_pcd/r1cs_sp_ppzkpcd/r1cs_sp_ppzkpcd_params.hpp
     include/nil/crypto3/zk/snark/schemes/pcd/r1cs_pcd/r1cs_sp_ppzkpcd/sp_pcd_circuits.hpp
     include/nil/crypto3/zk/snark/schemes/pcd/r1cs_pcd/ppzkpcd_compliance_predicate.hpp
     include/nil/crypto3/zk/snark/schemes/pcd/r1cs_pcd/r1cs_pcd_params.hpp

     include/nil/crypto3/zk/snark/schemes/ppzkadsnark/r1cs_ppzkadsnark/r1cs_ppzkadsnark.hpp
     include/nil/crypto3/zk/snark/schemes/ppzkadsnark/r1cs_ppzkadsnark/prf.hpp
     include/nil/crypto3/zk/snark/schemes/ppzkadsnark/r1cs_ppzkadsnark/signature.hpp
     include/nil/crypto3/zk/snark/schemes/detail/ppzkadsnark/r1cs_ppzkadsnark/basic_policy.hpp

     include/nil/crypto3/zk/snark/schemes/ppzksnark/bacs_ppzksnark.hpp
     include/nil/crypto3/zk/snark/schemes/detail/ppzksnark/bacs_ppzksnark/basic_policy.hpp

     include/nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark.hpp
     include/nil/crypto3/zk/snark/schemes/detail/ppzksnark/r1cs_gg_ppzksnark/basic_policy.hpp

     include/nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_ppzksnark.hpp
     include/nil/crypto3/zk/snark/schemes/detail/ppzksnark/r1cs_ppzksnark/basic_policy.hpp

     include/nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_se_ppzksnark.hpp
     include/nil/crypto3/zk/snark/schemes/detail/ppzksnark/r1cs_se_ppzksnark/basic_policy.hpp

     include/nil/crypto3/zk/snark/schemes/ppzksnark/tbcs_ppzksnark.hpp
     include/nil/crypto3/zk/snark/schemes/detail/ppzksnark/tbcs_ppzksnark/basic_policy.hpp

     include/nil/crypto3/zk/snark/schemes/ppzksnark/uscs_ppzksnark.hpp
     include/nil/crypto3/zk/snark/schemes/detail/ppzksnark/uscs_ppzksnark/basic_policy.hpp

     include/nil/crypto3/zk/snark/reductions/bacs_to_r1cs.hpp

     include/nil/crypto3/zk/snark/reductions/r1cs_to_qap.hpp

     include/nil/crypto3/zk/snark/reductions/r1cs_to_sap.hpp

     include/nil/crypto3/zk/snark/reductions/tbcs_to_uscs.hpp

     include/nil/crypto3/zk/snark/reductions/uscs_to_ssp.hpp

     include/nil/crypto3/zk/snark/relations/arithmetic_programs/qap.hpp

     include/nil/crypto3/zk/snark/relations/arithmetic_programs/sap.hpp

     include/nil/crypto3/zk/snark/relations/arithmetic_programs/ssp.hpp

     include/nil/crypto3/zk/snark/relations/circuit_satisfaction_problems/bacs.hpp

     include/nil/crypto3/zk/snark/relations/circuit_satisfaction_problems/tbcs.hpp

     include/nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs.hpp

     include/nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/uscs.hpp

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
     include/nil/crypto3/zk/snark/routing/as_waksman.hpp
     include/nil/crypto3/zk/snark/routing/benes.hpp
     include/nil/crypto3/zk/snark/constraint_profiling.hpp
     include/nil/crypto3/zk/snark/integer_permutation.hpp
     include/nil/crypto3/zk/snark/merkle_tree.hpp)

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
                      ${CMAKE_WORKSPACE_NAME}::fft
                      ${CMAKE_WORKSPACE_NAME}::hash
                      ${CMAKE_WORKSPACE_NAME}::multiprecision
                      nil::marshalling)

cm_deploy(TARGETS ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
          INCLUDE include
          NAMESPACE ${CMAKE_WORKSPACE_NAME}::)


if(BUILD_TESTS)
    add_subdirectory(test)
endif()
