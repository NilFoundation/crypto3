cm_project(pkpad WORKSPACE_NAME ${CMAKE_WORKSPACE_NAME})

include(CMDeploy)
include(CMSetupVersion)

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
    add_definitions(-DCRYPTO3_HAS_EME_OAEP)
endif()

if(CRYPTO3_PK_PAD_MGF1)
    add_definitions(-DCRYPTO3_HAS_MGF1)
endif()

if(CRYPTO3_PK_PAD_EME_PKCS1)
    add_definitions(-DCRYPTO3_HAS_EME_PKCS)
endif()

if(CRYPTO3_PK_PAD_EME_RAW)
    add_definitions(-DCRYPTO3_HAS_EME_RAW)
endif()

if(CRYPTO3_PK_PAD_EMSA1)
    add_definitions(-DCRYPTO3_HAS_EMSA1)
endif()

if(CRYPTO3_PK_PAD_EMSA_PKCS1)
    add_definitions(-DCRYPTO3_HAS_EMSA_PKCS1)
endif()

if(CRYPTO3_PK_PAD_EMSA_PSSR)
    add_definitions(-DCRYPTO3_HAS_EMSA_PSSR)
endif()

if(CRYPTO3_PK_PAD_EMSA_RAW)
    add_definitions(-DCRYPTO3_HAS_EMSA_RAW)
endif()

if(CRYPTO3_PK_PAD_EMSA_X931)
    add_definitions(-DCRYPTO3_HAS_EMSA_X931)
endif()

if(CRYPTO3_PK_PAD_ISO_9796)
    add_definitions(-DCRYPTO3_HAS_ISO_9796)
endif()

cm_setup_version(VERSION 0.1.0 PREFIX ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME})

add_library(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE)

set_target_properties(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PROPERTIES
                      EXPORT_NAME ${CURRENT_PROJECT_NAME})

target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
#                      ${CMAKE_WORKSPACE_NAME}::codec
                      ${CMAKE_WORKSPACE_NAME}::hash
                      ${CMAKE_WORKSPACE_NAME}::algebra
                      crypto3::marshalling-algebra
                      Boost::container)

target_include_directories(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
                           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
                           $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>

                           $<$<BOOL:${Boost_FOUND}>:${Boost_INCLUDE_DIRS}>)

cm_deploy(TARGETS ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
          INCLUDE include
          NAMESPACE ${CMAKE_WORKSPACE_NAME}::)

# Disabling tests because ./libs/pkpad/test/pkpad_emsa1_test is unable to find it's test data.
# The paths need to be fixed.
# include(CMTest)
# cm_add_test_subdirectory(test)
