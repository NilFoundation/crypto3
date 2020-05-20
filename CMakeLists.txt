cmake_minimum_required(VERSION 2.8.11)

cmake_policy(SET CMP0028 NEW)
cmake_policy(SET CMP0042 NEW)
cmake_policy(SET CMP0048 NEW)
cmake_policy(SET CMP0076 NEW)

if(NOT ${CMAKE_WORKSPACE_NAME} STREQUAL crypto3)
    cm_workspace(crypto3)
endif()

cm_project(pubkey WORKSPACE_NAME ${CMAKE_WORKSPACE_NAME})

cm_find_package(CM)
include(CMDeploy)
include(CMSetupVersion)

if(NOT Boost_FOUND)
    cm_find_package(Boost REQUIRED)
endif()

cm_find_package(${CMAKE_WORKSPACE_NAME}_asn1)
cm_find_package(${CMAKE_WORKSPACE_NAME}_codec)
cm_find_package(${CMAKE_WORKSPACE_NAME}_hash)
cm_find_package(${CMAKE_WORKSPACE_NAME}_modes)
cm_find_package(${CMAKE_WORKSPACE_NAME}_pk_pad)
cm_find_package(${CMAKE_WORKSPACE_NAME}_utilities)

option(BUILD_TESTS "Build unit tests" FALSE)

list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
     include//nil/crypto3/pubkey/algorithm/sign.hpp
     include//nil/crypto3/pubkey/algorithm/encrypt.hpp
     include//nil/crypto3/pubkey/algorithm/decrypt.hpp
     include//nil/crypto3/pubkey/algorithm/verify.hpp

     include//nil/crypto3/pubkey/pk_algs.hpp
     include//nil/crypto3/pubkey/blinding.hpp
     include//nil/crypto3/pubkey/pk_keys.hpp
     include//nil/crypto3/pubkey/pk_operations.hpp
     include//nil/crypto3/pubkey/pk_ops_fwd.hpp
     include//nil/crypto3/pubkey/pkcs8.hpp
     include//nil/crypto3/pubkey/pubkey.hpp
     include//nil/crypto3/pubkey/x509_key.hpp
     include//nil/crypto3/pubkey/workfactor.hpp
     include//nil/crypto3/pubkey/keypair.hpp
     include//nil/crypto3/pubkey/ecies.hpp
     include//nil/crypto3/pubkey/ecc_key.hpp

     include//nil/crypto3/pubkey/dl_group/dl_group.hpp
     include//nil/crypto3/pubkey/dl_group/dl_algorithm.hpp
     include//nil/crypto3/pubkey/dl_group/dl_group_info.hpp

     include//nil/crypto3/pubkey/ec_group/curve_gfp.hpp
     include//nil/crypto3/pubkey/ec_group/curve_nist.hpp
     include//nil/crypto3/pubkey/ec_group/p192.hpp
     include//nil/crypto3/pubkey/ec_group/p224.hpp
     include//nil/crypto3/pubkey/ec_group/p256.hpp
     include//nil/crypto3/pubkey/ec_group/p384.hpp
     include//nil/crypto3/pubkey/ec_group/p521.hpp
     include//nil/crypto3/pubkey/ec_group/curve_montgomery.hpp
     include//nil/crypto3/pubkey/ec_group/ec_group.hpp
     include//nil/crypto3/pubkey/ec_group/point_gfp.hpp
     include//nil/crypto3/pubkey/ec_group/point_mul.hpp)

list(APPEND ${CURRENT_PROJECT_NAME}_PRIVATE_HEADERS
     include/nil/crypto3/pubkey/detail/pk_ops_impl.hpp)

list(APPEND ${CURRENT_PROJECT_NAME}_UNGROUPED_SOURCES)

option(CRYPTO3_PUBKEY_RSA "Build with RSA public key scheme support" TRUE)
option(CRYPTO3_PUBKEY_DSA "Build with DSA public key scheme support" TRUE)
option(CRYPTO3_PUBKEY_DIFFIE_HELLMAN "Build with Diffie-Hellman public key scheme support" TRUE)
option(CRYPTO3_PUBKEY_DLIES "Build with Dlies public key scheme support" TRUE)
option(CRYPTO3_PUBKEY_ECDSA "Build with ECDSA public key scheme support" TRUE)
option(CRYPTO3_PUBKEY_ECGDSA "Build with ECGDSA public key scheme support" TRUE)
option(CRYPTO3_PUBKEY_ECKCDSA "Build with ECKCDSA public key scheme support" TRUE)
option(CRYPTO3_PUBKEY_ED25519 "Build with ED25519 public key scheme support" TRUE)
option(CRYPTO3_PUBKEY_GOST_34_10_2001 "Build with GOST 34.10.2001 public key scheme support" TRUE)
option(CRYPTO3_PUBKEY_PEM "Build with PEM public key scheme support" TRUE)
option(CRYPTO3_PUBKEY_PBES2 "Build with PBES2 public key scheme support" TRUE)
option(CRYPTO3_PUBKEY_NEWHOPE "Build with Newhope public key scheme support" TRUE)
option(CRYPTO3_PUBKEY_MCEIES "Build with Mceies public key scheme support" TRUE)
option(CRYPTO3_PUBKEY_ELGAMAL "Build with ElGamal public key scheme support" TRUE)
option(CRYPTO3_PUBKEY_ECDH "Build with ECDH public key scheme support" TRUE)
option(CRYPTO3_PUBKEY_CURVE_25519 "Build with Curve 25519 public key scheme support" TRUE)
option(CRYPTO3_PUBKEY_MCELIECE "Build with McEliece public key scheme support" TRUE)
option(CRYPTO3_PUBKEY_RFC6979 "Build with RFC6979 public key scheme support" TRUE)
option(CRYPTO3_PUBKEY_SM2 "Build with SM2 public key scheme support" TRUE)

if(CRYPTO3_PUBKEY_NEWHOPE)
    list(APPEND ${CURRENT_PROJECT_NAME}_NEWHOPE_HEADERS
         include//nil/crypto3/pubkey/newhope.hpp)

    list(APPEND ${CURRENT_PROJECT_NAME}_NEWHOPE_SOURCES)

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_NEWHOPE)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_NEWHOPE_HEADERS})
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_NEWHOPE_SOURCES})
endif()

if(CRYPTO3_PUBKEY_RFC6979)
    list(APPEND ${CURRENT_PROJECT_NAME}_RFC6979_HEADERS
         include//nil/crypto3/pubkey/rfc6979.hpp)

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_RFC6979)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_RFC6979_HEADERS})
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_RFC6979_SOURCES})
endif()

if(CRYPTO3_PUBKEY_PBES2)
    list(APPEND ${CURRENT_PROJECT_NAME}_PBES2_HEADERS
         include//nil/crypto3/pubkey/pbes2.hpp)

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_PBES2)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_PBES2_HEADERS})
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_PBES2_SOURCES})
endif()

if(CRYPTO3_PUBKEY_PEM)
    list(APPEND ${CURRENT_PROJECT_NAME}_PEM_HEADERS
         include//nil/crypto3/pubkey/pem.hpp)

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_PEM)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_PEM_HEADERS})
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_PEM_SOURCES})
endif()

if(CRYPTO3_PUBKEY_RSA)
    list(APPEND ${CURRENT_PROJECT_NAME}_RSA_HEADERS
         include//nil/crypto3/pubkey/rsa.hpp)

    list(APPEND ${CURRENT_PROJECT_NAME}_RSA_SOURCES)

    list(APPEND ${CURRENT_PROJECT_NAME}_LIBRARIES
         ${CMAKE_WORKSPACE_NAME}::pk_pad)

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_RSA)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_RSA_HEADERS})
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_RSA_SOURCES})
endif()

if(CRYPTO3_PUBKEY_DSA)
    list(APPEND ${CURRENT_PROJECT_NAME}_DSA_HEADERS
         include//nil/crypto3/pubkey/dsa.hpp)

    list(APPEND ${CURRENT_PROJECT_NAME}_DSA_SOURCES)

    list(APPEND ${CURRENT_PROJECT_NAME}_LIBRARIES
         ${CMAKE_WORKSPACE_NAME}::pk_pad)

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_DSA)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_DSA_HEADERS})
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_DSA_SOURCES})
endif()

if(CRYPTO3_PUBKEY_DIFFIE_HELLMAN)
    list(APPEND ${CURRENT_PROJECT_NAME}_DIFFIE_HELLMAN_HEADERS
         include//nil/crypto3/pubkey/dh.hpp)

    list(APPEND ${CURRENT_PROJECT_NAME}_DIFFIE_HELLMAN_SOURCES)

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_DIFFIE_HELLMAN)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_DIFFIE_HELLMAN_HEADERS})
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_DIFFIE_HELLMAN_SOURCES})
endif()

if(CRYPTO3_PUBKEY_ECDSA)
    list(APPEND ${CURRENT_PROJECT_NAME}_ECDSA_HEADERS
         include//nil/crypto3/pubkey/ecdsa.hpp)

    list(APPEND ${CURRENT_PROJECT_NAME}_ECDSA_SOURCES)

    list(APPEND ${CURRENT_PROJECT_NAME}_LIBRARIES
         ${CMAKE_WORKSPACE_NAME}::asn1
         ${CMAKE_WORKSPACE_NAME}::pk_pad)

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_ECDSA)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_ECDSA_HEADERS})
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_ECDSA_SOURCES})
endif()

if(CRYPTO3_PUBKEY_ECGDSA)
    list(APPEND ${CURRENT_PROJECT_NAME}_ECGDSA_HEADERS
         include//nil/crypto3/pubkey/ecgdsa.hpp)

    list(APPEND ${CURRENT_PROJECT_NAME}_ECGDSA_SOURCES)

    list(APPEND ${CURRENT_PROJECT_NAME}_LIBRARIES
         ${CMAKE_WORKSPACE_NAME}::asn1
         ${CMAKE_WORKSPACE_NAME}::pk_pad)

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_ECGDSA)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_ECGDSA_HEADERS})
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_ECGDSA_SOURCES})
endif()

if(CRYPTO3_PUBKEY_ECKCDSA)
    list(APPEND ${CURRENT_PROJECT_NAME}_ECKCDSA_HEADERS
         include//nil/crypto3/pubkey/eckcdsa.hpp)

    list(APPEND ${CURRENT_PROJECT_NAME}_ECKCDSA_SOURCES)

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_ECKCDSA)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_ECKCDSA_HEADERS})
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_ECKCDSA_SOURCES})
endif()

if(CRYPTO3_PUBKEY_ED25519)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_ED25519_HEADERS
         include//nil/crypto3/pubkey/ed25519.hpp)

    list(APPEND ${CURRENT_PROJECT_NAME}_PRIVATE_ED25519_HEADERS
         include//nil/crypto3/pubkey/detail/ed25519/ed25519_fe.hpp
         include//nil/crypto3/pubkey/detail/ed25519/ed25519_internal.hpp)

    list(APPEND ${CURRENT_PROJECT_NAME}_ED25519_SOURCES)

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_ED25519)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_PUBLIC_ED25519_HEADERS})
    list(APPEND ${CURRENT_PROJECT_NAME}_PRIVATE_HEADERS
         ${${CURRENT_PROJECT_NAME}_PRIVATE_ED25519_HEADERS})
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_ED25519_SOURCES})
endif()

if(CRYPTO3_PUBKEY_GOST_34_10_2001)
    list(APPEND ${CURRENT_PROJECT_NAME}_GOST_34_10_2001_HEADERS
         include//nil/crypto3/pubkey/gost_3410.hpp)

    list(APPEND ${CURRENT_PROJECT_NAME}_GOST_34_10_2001_SOURCES)

    list(APPEND ${CURRENT_PROJECT_NAME}_LIBRARIES
         ${CMAKE_WORKSPACE_NAME}::asn1)

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_GOST_34_10_2001)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_GOST_34_10_2001_HEADERS})

    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_GOST_34_10_2001_SOURCES})
endif()

if(CRYPTO3_PUBKEY_ELGAMAL)
    list(APPEND ${CURRENT_PROJECT_NAME}_ELGAMAL_HEADERS
         include//nil/crypto3/pubkey/elgamal.hpp)

    list(APPEND ${CURRENT_PROJECT_NAME}_ELGAMAL_SOURCES)

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_ELGAMAL)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_ELGAMAL_HEADERS})
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_ELGAMAL_SOURCES})
endif()

if(CRYPTO3_PUBKEY_ECDH)
    list(APPEND ${CURRENT_PROJECT_NAME}_ECDH_HEADERS
         include//nil/crypto3/pubkey/ecdh.hpp)

    list(APPEND ${CURRENT_PROJECT_NAME}_ECDH_SOURCES)

    list(APPEND ${CURRENT_PROJECT_NAME}_LIBRARIES
         ${CMAKE_WORKSPACE_NAME}::asn1)

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_ECDH)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_ECDH_HEADERS})
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_ECDH_SOURCES})
endif()

if(CRYPTO3_PUBKEY_CURVE_25519)
    list(APPEND ${CURRENT_PROJECT_NAME}_CURVE_25519_HEADERS
         include//nil/crypto3/pubkey/curve25519.hpp)

    list(APPEND ${CURRENT_PROJECT_NAME}_CURVE_25519_SOURCES)

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_CURVE_25519)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_CURVE_25519_HEADERS})
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_CURVE_25519_SOURCES})
endif()

if(CRYPTO3_PUBKEY_MCELIECE)
    list(APPEND ${CURRENT_PROJECT_NAME}_MCELIECE_PUBLIC_HEADERS
         include//nil/crypto3/pubkey/mceliece.hpp)

    list(APPEND ${CURRENT_PROJECT_NAME}_MCELIECE_INTERNAL_HEADERS
         include//nil/crypto3/pubkey/detail/mceliece/polyn_gf2m.hpp
         include//nil/crypto3/pubkey/detail/mceliece/gf2m_small_m.hpp
         include//nil/crypto3/pubkey/detail/mceliece/code_based_util.hpp
         include//nil/crypto3/pubkey/detail/mceliece/mce_internal.hpp)

    list(APPEND ${CURRENT_PROJECT_NAME}_MCELIECE_SOURCES)

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_MCELIECE)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_MCELIECE_PUBLIC_HEADERS})

    list(APPEND ${CURRENT_PROJECT_NAME}_PRIVATE_HEADERS
         ${${CURRENT_PROJECT_NAME}_MCELIECE_INTERNAL_HEADERS})

    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_MCELIECE_SOURCES})
endif()

if(CRYPTO3_PUBKEY_DLIES)
    list(APPEND ${CURRENT_PROJECT_NAME}_DLIES_PUBLIC_HEADERS
         include//nil/crypto3/pubkey/dlies.hpp)

    list(APPEND ${CURRENT_PROJECT_NAME}_DLIES_SOURCES)

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_DLIES)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_DLIES_PUBLIC_HEADERS})

    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_DLIES_SOURCES})
endif()

if(CRYPTO3_PUBKEY_MCEIES)
    list(APPEND ${CURRENT_PROJECT_NAME}_MCEIES_PUBLIC_HEADERS
         include//nil/crypto3/pubkey/mceies.hpp)

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_MCEIES)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_MCEIES_PUBLIC_HEADERS})

    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_MCEIES_SOURCES})
endif()

if(CRYPTO3_PUBKEY_SM2)
    list(APPEND ${CURRENT_PROJECT_NAME}_SM2_PUBLIC_HEADERS
         include//nil/crypto3/pubkey/sm2.hpp
         include//nil/crypto3/pubkey/sm2_encrypt.hpp)

    list(APPEND ${CURRENT_PROJECT_NAME}_SM2_SOURCES)

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_SM2)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_SM2_PUBLIC_HEADERS})

    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_SM2_SOURCES})
endif()

if(CRYPTO3_PUBKEY_XMSS)
    list(APPEND ${CURRENT_PROJECT_NAME}_XMSS_PUBLIC_HEADERS
         include/nil/crypto3/pubkey/xmss/atomic.hpp
         include/nil/crypto3/pubkey/xmss/xmss.hpp
         include/nil/crypto3/pubkey/xmss/xmss_address.hpp
         include/nil/crypto3/pubkey/xmss/xmss_common_ops.hpp
         include/nil/crypto3/pubkey/xmss/xmss_hash.hpp
         include/nil/crypto3/pubkey/xmss/xmss_index_registry.hpp
         include/nil/crypto3/pubkey/xmss/xmss_key_pair.hpp
         include/nil/crypto3/pubkey/xmss/xmss_parameters.hpp
         include/nil/crypto3/pubkey/xmss/xmss_privatekey.hpp
         include/nil/crypto3/pubkey/xmss/xmss_publickey.hpp
         include/nil/crypto3/pubkey/xmss/xmss_signature_operation.hpp
         include/nil/crypto3/pubkey/xmss/xmss_tools.hpp
         include/nil/crypto3/pubkey/xmss/xmss_verification_operation.hpp
         include/nil/crypto3/pubkey/xmss/xmss_wots_addressed_privatekey.hpp
         include/nil/crypto3/pubkey/xmss/xmss_wots_parameters.hpp
         include/nil/crypto3/pubkey/xmss/xmss_wots_privatekey.hpp
         include/nil/crypto3/pubkey/xmss/xmss_wots_publickey.hpp)

    list(APPEND ${CURRENT_PROJECT_NAME}_XMSS_PRIVATE_HEADERS
         include/nil/crypto3/pubkey/xmss/xmss_signature.hpp
         include/nil/crypto3/pubkey/xmss/xmss_wots_addressed_public_key.hpp)

    list(APPEND ${CURRENT_PROJECT_NAME}_XMSS_SOURCES)

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_XMSS)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_XMSS_PUBLIC_HEADERS})

    list(APPEND ${CURRENT_PROJECT_NAME}_PRIVATE_HEADERS
         ${${CURRENT_PROJECT_NAME}_XMSS_PRIVATE_HEADERS})

    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_XMSS_SOURCES})
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
                      ${CMAKE_WORKSPACE_NAME}::asn1
                      ${CMAKE_WORKSPACE_NAME}::codec
                      ${CMAKE_WORKSPACE_NAME}::hash
                      ${CMAKE_WORKSPACE_NAME}::modes
                      ${CMAKE_WORKSPACE_NAME}::pk_pad
                      ${CMAKE_WORKSPACE_NAME}::utilities

                      boost::multiprecision

                      ${Boost_LIBRARIES})

target_include_directories(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
                           "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                           "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                           "${Boost_INCLUDE_DIRS}")

cm_deploy(TARGETS ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
          INCLUDE include
          NAMESPACE ${CMAKE_WORKSPACE_NAME}::)

if(BUILD_TESTS)
    add_subdirectory(test)
endif()