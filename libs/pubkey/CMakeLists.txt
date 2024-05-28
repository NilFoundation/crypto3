cmake_minimum_required(VERSION 2.8.12)

cmake_policy(SET CMP0028 NEW)
cmake_policy(SET CMP0042 NEW)
cmake_policy(SET CMP0048 NEW)
cmake_policy(SET CMP0076 NEW)

list(APPEND CMAKE_MODULE_PATH
        "${CMAKE_CURRENT_LIST_DIR}/cmake"
        "${CMAKE_CURRENT_LIST_DIR}/cmake/packages"
        "${CMAKE_CURRENT_LIST_DIR}/cmake/modules/share/modules/cmake")

if(NOT CMAKE_WORKSPACE_NAME OR NOT ("${CMAKE_WORKSPACE_NAME}" STREQUAL "crypto3"))
    cm_workspace(crypto3)
endif()

cm_project(pubkey WORKSPACE_NAME ${CMAKE_WORKSPACE_NAME})

cm_find_package(CM)
include(CMDeploy)
include(CMSetupVersion)

option(BUILD_EXAMPLES "Build examples" FALSE)

list(APPEND ${CURRENT_PROJECT_NAME}_LIBRARIES
        ${CMAKE_WORKSPACE_NAME}::algebra
        ${CMAKE_WORKSPACE_NAME}::random
        # TODO: add conditional link of zk depending on ElGamal
        ${CMAKE_WORKSPACE_NAME}::zk)

list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
        include/nil/crypto3/pubkey/algorithm/sign.hpp
        include/nil/crypto3/pubkey/algorithm/verify.hpp
        include/nil/crypto3/pubkey/algorithm/aggregate.hpp
        include/nil/crypto3/pubkey/algorithm/aggregate_verify.hpp
        include/nil/crypto3/pubkey/algorithm/aggregate_verify_single_msg.hpp
        include/nil/crypto3/pubkey/algorithm/deal_shares.hpp
        include/nil/crypto3/pubkey/algorithm/deal_share.hpp
        include/nil/crypto3/pubkey/algorithm/verify_share.hpp
        include/nil/crypto3/pubkey/algorithm/reconstruct_secret.hpp
        include/nil/crypto3/pubkey/algorithm/reconstruct_public_secret.hpp

        include/nil/crypto3/pubkey/keys/private_key.hpp
        include/nil/crypto3/pubkey/keys/public_key.hpp
        include/nil/crypto3/pubkey/keys/share_sss.hpp
        include/nil/crypto3/pubkey/keys/public_share_sss.hpp
        include/nil/crypto3/pubkey/keys/secret_sss.hpp
        include/nil/crypto3/pubkey/keys/public_secret_sss.hpp

        include/nil/crypto3/pubkey/modes/isomorphic.hpp

        include/nil/crypto3/pubkey/bls.hpp
        include/nil/crypto3/pubkey/ecdsa.hpp
        include/nil/crypto3/pubkey/eddsa.hpp

        include/nil/crypto3/pubkey/type_traits.hpp)

list(APPEND ${CURRENT_PROJECT_NAME}_PRIVATE_HEADERS
        include/nil/crypto3/pubkey/operations/aggregate_op.hpp
        include/nil/crypto3/pubkey/operations/aggregate_verify_op.hpp
        include/nil/crypto3/pubkey/operations/aggregate_verify_single_msg_op.hpp
        include/nil/crypto3/pubkey/operations/deal_share_op.hpp
        include/nil/crypto3/pubkey/operations/deal_shares_op.hpp
        include/nil/crypto3/pubkey/operations/reconstruct_public_secret_op.hpp
        include/nil/crypto3/pubkey/operations/reconstruct_secret_op.hpp
        include/nil/crypto3/pubkey/operations/verify_share_op.hpp)

list(APPEND ${CURRENT_PROJECT_NAME}_UNGROUPED_SOURCES)

option(CRYPTO3_PUBKEY_BLS "Build with BLS public key scheme support" TRUE)
option(CRYPTO3_PUBKEY_ECDSA "Build with ECDSA public key scheme support" TRUE)
option(CRYPTO3_PUBKEY_EDDSA "Build with EDDSA public key scheme support" TRUE)
option(CRYPTO3_PUBKEY_SHAMIR "Build with Shamir secret sharing scheme support" TRUE)
option(CRYPTO3_PUBKEY_FELDMAN "Build with Feldman secret sharing scheme support" TRUE)
option(CRYPTO3_PUBKEY_PEDERSEN "Build with Pedersen secret sharing scheme support" TRUE)
option(CRYPTO3_PUBKEY_WEIGHTED_SHAMIR "Build with weighted Shamir secret sharing scheme support" TRUE)

if(CRYPTO3_PUBKEY_BLS)
    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_BLS)
endif()

if(CRYPTO3_PUBKEY_ECDSA)
    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_ECDSA)
endif()

if(CRYPTO3_PUBKEY_EDDSA)
    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_EDDSA)
endif()

list(APPEND ${CURRENT_PROJECT_NAME}_HEADERS
        ${${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS})

list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
        ${${CURRENT_PROJECT_NAME}_UNGROUPED_SOURCES})

cm_setup_version(VERSION 0.1.0 PREFIX ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME})

add_library(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE)

set_target_properties(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PROPERTIES
        EXPORT_NAME ${CURRENT_PROJECT_NAME})

target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
        ${${CURRENT_PROJECT_NAME}_LIBRARIES}
        Boost::container)

target_include_directories(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>

        $<$<BOOL:${Boost_FOUND}>:${Boost_INCLUDE_DIRS}>)

cm_deploy(TARGETS ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
        INCLUDE include
        NAMESPACE ${CMAKE_WORKSPACE_NAME}::)

cm_add_test_subdirectory(test)

if(BUILD_EXAMPLES)
    add_subdirectory(example)
endif()
