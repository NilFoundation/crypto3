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

cm_project(pkpad WORKSPACE_NAME ${CMAKE_WORKSPACE_NAME})

include(CMDeploy)
include(CMSetupVersion)

list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
        include/nil/crypto3/pkpad/algorithm/encode.hpp
        include/nil/crypto3/pkpad/algorithm/verify.hpp)

list(APPEND ${CURRENT_PROJECT_NAME}_UNGROUPED_SOURCES)

option(CRYPTO3_PK_PAD_EME_OAEP "Build with EME OAEP support" TRUE)
option(CRYPTO3_PK_PAD_EME_PKCS1 "Build with EME PKCS1 support" TRUE)
option(CRYPTO3_PK_PAD_EME_RAW "Build with EME RAW support" TRUE)
option(CRYPTO3_PK_PAD_EMSA1 "Build with EMSA1 support" TRUE)
option(CRYPTO3_PK_PAD_EMSA_PKCS1 "Build with EMSA PKCS1 OAEP support" TRUE)
option(CRYPTO3_PK_PAD_EMSA_PSSR "Build with EMSA PSSR support" TRUE)
option(CRYPTO3_PK_PAD_EMSA_RAW "Build with EMSA RAW support" TRUE)
option(CRYPTO3_PK_PAD_EMSA_X931 "Build with EMSA x931 support" TRUE)
option(CRYPTO3_PK_PAD_EMSA_MGF1 "Build with MGF1 support" TRUE)
option(CRYPTO3_PK_PAD_ISO_9796 "Build with ISO9796 support" TRUE)

if(CRYPTO3_PK_PAD_EME_OAEP)
    list(APPEND ${CURRENT_PROJECT_NAME}_EME_OAEP_HEADERS
         include/nil/crypto3/pkpad/eme_oaep/oaep.hpp
         )

    list(APPEND ${CURRENT_PROJECT_NAME}_EME_OAEP_SOURCES
         )

    add_definitions(-DCRYPTO3_HAS_EME_OAEP)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_EME_OAEP_HEADERS}
         )
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_EME_OAEP_SOURCES}
         )
endif()

if(CRYPTO3_PK_PAD_MGF1)
    list(APPEND ${CURRENT_PROJECT_NAME}_MGF1_HEADERS
         include/nil/crypto3/pkpad/mgf1/mgf1.hpp
         )

    list(APPEND ${CURRENT_PROJECT_NAME}_MGF1_SOURCES
         )

    add_definitions(-DCRYPTO3_HAS_MGF1)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_MGF1_HEADERS}
         )
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_MGF1_SOURCES}
         )
endif()

if(CRYPTO3_PK_PAD_EME_PKCS1)
    list(APPEND ${CURRENT_PROJECT_NAME}_EME_PKCS1_HEADERS
         include/nil/crypto3/pkpad/eme_pkcs1/eme_pkcs.hpp
         )

    list(APPEND ${CURRENT_PROJECT_NAME}_EME_PKCS1_SOURCES
         )

    add_definitions(-DCRYPTO3_HAS_EME_PKCS)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_EME_PKCS1_HEADERS}
         )
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_EME_PKCS1_SOURCES}
         )
endif()

if(CRYPTO3_PK_PAD_EME_RAW)
    list(APPEND ${CURRENT_PROJECT_NAME}_EME_RAW_HEADERS
         include/nil/crypto3/pkpad/eme_raw/eme_raw.hpp
         )

    list(APPEND ${CURRENT_PROJECT_NAME}_EME_RAW_SOURCES
         )

    add_definitions(-DCRYPTO3_HAS_EME_RAW)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_EME_RAW_HEADERS}
         )
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_EME_RAW_SOURCES}
         )
endif()

if(CRYPTO3_PK_PAD_EMSA1)
    list(APPEND ${CURRENT_PROJECT_NAME}_EMSA1_HEADERS
         include/nil/crypto3/pkpad/emsa1/emsa1.hpp
         )

    list(APPEND ${CURRENT_PROJECT_NAME}_EMSA1_SOURCES
         )

    add_definitions(-DCRYPTO3_HAS_EMSA1)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_EMSA1_HEADERS}
         )
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_EMSA1_SOURCES}
         )
endif()

if(CRYPTO3_PK_PAD_EMSA_PKCS1)
    list(APPEND ${CURRENT_PROJECT_NAME}_EMSA_PKCS1_HEADERS
         include/nil/crypto3/pkpad/emsa_pkcs1/emsa_pkcs1.hpp
         include/nil/crypto3/pkpad/hash_id/hash_id.hpp
         )

    list(APPEND ${CURRENT_PROJECT_NAME}_EMSA_PKCS1_SOURCES
         )

    add_definitions(-DCRYPTO3_HAS_EMSA_PKCS1)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_EMSA_PKCS1_HEADERS}
         )
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_EMSA_PKCS1_SOURCES}
         )
endif()

if(CRYPTO3_PK_PAD_EMSA_PSSR)
    list(APPEND ${CURRENT_PROJECT_NAME}_EMSA_PSSR_HEADERS
         include/nil/crypto3/pkpad/emsa_pssr/emsa_pssr.hpp
         )

    list(APPEND ${CURRENT_PROJECT_NAME}_EMSA_PSSR_SOURCES
         )

    add_definitions(-DCRYPTO3_HAS_EMSA_PSSR)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_EMSA_PSSR_HEADERS}
         )
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_EMSA_PSSR_SOURCES}
         )
endif()

if(CRYPTO3_PK_PAD_EMSA_RAW)
    list(APPEND ${CURRENT_PROJECT_NAME}_EMSA_RAW_HEADERS
         include/nil/crypto3/pkpad/emsa_raw/emsa_raw.hpp
         )

    list(APPEND ${CURRENT_PROJECT_NAME}_EMSA_RAW_SOURCES
         )

    add_definitions(-DCRYPTO3_HAS_EMSA_RAW)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_EMSA_RAW_HEADERS}
         )
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_EMSA_RAW_SOURCES}
         )
endif()

if(CRYPTO3_PK_PAD_EMSA_X931)
    list(APPEND ${CURRENT_PROJECT_NAME}_EMSA_X931_HEADERS
         include/nil/crypto3/pkpad/emsa_x931/emsa_x931.hpp
         )

    list(APPEND ${CURRENT_PROJECT_NAME}_EMSA_X931_SOURCES
         )

    add_definitions(-DCRYPTO3_HAS_EMSA_X931)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_EMSA_X931_HEADERS}
         )
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_EMSA_X931_SOURCES}
         )
endif()

if(CRYPTO3_PK_PAD_ISO_9796)
    list(APPEND ${CURRENT_PROJECT_NAME}_ISO_9796_HEADERS
         include/nil/crypto3/pkpad/iso9796/iso9796.hpp
         )

    list(APPEND ${CURRENT_PROJECT_NAME}_ISO_9796_SOURCES
         )

    add_definitions(-DCRYPTO3_HAS_ISO_9796)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_ISO_9796_HEADERS}
         )
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_ISO_9796_SOURCES}
         )
endif()

list(APPEND ${CURRENT_PROJECT_NAME}_HEADERS
     ${${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS}
     )

list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
     ${${CURRENT_PROJECT_NAME}_UNGROUPED_SOURCES}
     )

cm_setup_version(VERSION 0.1.0 PREFIX ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME})

add_library(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE)

set_target_properties(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PROPERTIES
                      EXPORT_NAME ${CURRENT_PROJECT_NAME})

target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
#                      ${CMAKE_WORKSPACE_NAME}::codec
                      ${CMAKE_WORKSPACE_NAME}::hash
                      ${CMAKE_WORKSPACE_NAME}::algebra
                      marshalling::crypto3_algebra

                      Boost::container)

target_include_directories(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
                           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
                           $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>

                           $<$<BOOL:${Boost_FOUND}>:${Boost_INCLUDE_DIRS}>)

cm_deploy(TARGETS ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
          INCLUDE include
          NAMESPACE ${CMAKE_WORKSPACE_NAME}::)

include(CMTest)
cm_add_test_subdirectory(test)
