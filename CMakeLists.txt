cmake_minimum_required(VERSION 2.8.11)

cmake_policy(SET CMP0042 NEW)
cmake_policy(SET CMP0028 NEW)

cm_project(${CMAKE_WORKSPACE_NAME} hash)

cm_find_package(CM)
include(CMDeploy)
include(CMSetupVersion)

if(NOT Boost_FOUND)
    cm_find_package(Boost)
endif()

cm_find_package(${CMAKE_WORKSPACE_NAME}_block)

list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
     include/nil/crypto3/hash/algorithm/hash.hpp

     include/nil/crypto3/hash/detail/type_traits.hpp

     include/nil/crypto3/hash/adaptor/hashed.hpp
     )

option(CRYPTO3_HASH_BLAKE2B "Build with Blake2 hash support" TRUE)
option(CRYPTO3_HASH_CHECKSUM_ADLER32 "Build with Adler32 hash checksum support" TRUE)
option(CRYPTO3_HASH_CHECKSUM_CRC "Build with CRC hash checksum support" TRUE)
option(CRYPTO3_HASH_CUBEHSAH "Build with Cubehash hash support" TRUE)
option(CRYPTO3_HASH_COMB4P "Build with Comb4p hash support" TRUE)
option(CRYPTO3_HASH_GOST_34_11 "Build with GOST.34.11 hash support" TRUE)
option(CRYPTO3_HASH_KECCAK "Build with Keccak hash support" TRUE)
option(CRYPTO3_HASH_MD4 "Build with MD4 hash support" TRUE)
option(CRYPTO3_HASH_MD5 "Build with MD5 hash support" TRUE)
option(CRYPTO3_HASH_RIPEMD "Build with Ripemd160 hash support" TRUE)
option(CRYPTO3_HASH_SHA1 "Build with SHA1 hash support" TRUE)
option(CRYPTO3_HASH_SHA2 "Build with SHA2 hash support" TRUE)
option(CRYPTO3_HASH_SHA3 "Build with SHA3 hash support" TRUE)
option(CRYPTO3_HASH_SKEIN "Build with Skein hash support" TRUE)
option(CRYPTO3_HASH_SHAKE "Build with Snake hash support" TRUE)
option(CRYPTO3_HASH_STREEBOG "Build with Streebog hash support" TRUE)
option(CRYPTO3_HASH_TIGER "Build with Tiger hash support" TRUE)
option(CRYPTO3_HASH_WHIRLPOOL "Build with Whirlpool hash support" TRUE)

if(CRYPTO3_HASH_BLAKE2B)
    list(APPEND ${CURRENT_PROJECT_NAME}_BLAKE2B_HEADERS
         include/nil/crypto3/hash/blake2b.hpp

         include/nil/crypto3/hash/detail/blake2b/blake2b_policy.hpp
         include/nil/crypto3/hash/detail/blake2b/blake2b_functions.hpp
         )

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_BLAKE2B)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_BLAKE2B_HEADERS}
         )
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_BLAKE2B_SOURCES}
         )
endif()

if(CRYPTO3_HASH_CHECKSUM_ADLER32)
    list(APPEND ${CURRENT_PROJECT_NAME}_ADLER32_HEADERS
         include/nil/crypto3/hash/adler.hpp
         )

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_ADLER32)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_ADLER32_HEADERS}
         )
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_ADLER32_SOURCES}
         )
endif()

if(CRYPTO3_HASH_CHECKSUM_CRC)
    list(APPEND ${CURRENT_PROJECT_NAME}_CRC_HEADERS
         include/nil/crypto3/hash/crc.hpp
         )

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_CRC)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_CRC_HEADERS}
         )
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_CRC_SOURCES}
         )
endif()

if(CRYPTO3_HASH_GOST_34_11)
    list(APPEND ${CURRENT_PROJECT_NAME}_GOST_34_11_HEADERS
         include/nil/crypto3/hash/gost_3411.hpp
         )

    list(APPEND ${CURRENT_PROJECT_NAME}_GOST_34_11_SOURCES
         src/gost_3411/gost_3411.cpp
         )

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_GOST_34_11)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_GOST_34_11_HEADERS}
         )
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_GOST_34_11_SOURCES}
         )
endif()

if(CRYPTO3_HASH_KECCAK)
    list(APPEND ${CURRENT_PROJECT_NAME}_KECCAK_HEADERS
         include/nil/crypto3/hash/keccak.hpp
         )

    list(APPEND ${CURRENT_PROJECT_NAME}_KECCAK_SOURCES
         src/keccak/keccak.cpp
         )

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_KECCAK)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_KECCAK_HEADERS}
         )
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_KECCAK_SOURCES}
         )
endif()

if(CRYPTO3_HASH_MD4)
    list(APPEND ${CURRENT_PROJECT_NAME}_MD4_HEADERS
         include/nil/crypto3/hash/md4.hpp
         )

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_MD4)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_MD4_HEADERS}
         )
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_MD4_SOURCES}
         )
endif()

if(CRYPTO3_HASH_MD5)
    list(APPEND ${CURRENT_PROJECT_NAME}_MD5_HEADERS
         include/nil/crypto3/hash/md5.hpp
         )

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_MD5)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_MD5_HEADERS}
         )
endif()

if(CRYPTO3_HASH_RIPEMD)
    list(APPEND ${CURRENT_PROJECT_NAME}_RIPEMD_HEADERS
         include/nil/crypto3/hash/detail/ripemd/ripemd_functions.hpp
         include/nil/crypto3/hash/detail/ripemd/ripemd_policy.hpp
         include/nil/crypto3/hash/ripemd.hpp
         )

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_RIPEMD)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_RIPEMD_HEADERS}
         )
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_RIPEMD_SOURCES}
         )
endif()

if(CRYPTO3_HASH_SHA1)
    list(APPEND ${CURRENT_PROJECT_NAME}_SHA1_HEADERS
         include/nil/crypto3/hash/sha.hpp
         include/nil/crypto3/hash/sha1.hpp
         )

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_SHA1)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_SHA1_HEADERS}
         )
endif()

if(CRYPTO3_HASH_SHA2)
    list(APPEND ${CURRENT_PROJECT_NAME}_SHA2_HEADERS
         include/nil/crypto3/hash/sha.hpp
         include/nil/crypto3/hash/sha2.hpp
         )

    list(APPEND ${CURRENT_PROJECT_NAME}_SHA2_SOURCES)

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_SHA2_32)
    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_SHA2_64)

    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_SHA2_HEADERS}
         )
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_SHA2_SOURCES}
         )
endif()

if(CRYPTO3_HASH_SHA3)
    list(APPEND ${CURRENT_PROJECT_NAME}_SHA3_HEADERS
         include/nil/crypto3/hash/sha3.hpp
         )

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_SHA3)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_SHA3_HEADERS}
         )
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_SHA3_SOURCES}
         )
endif()

if(CRYPTO3_HASH_SKEIN)
    list(APPEND ${CURRENT_PROJECT_NAME}_SKEIN_512_HEADERS
         include/nil/crypto3/hash/skein.hpp
         )

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_SKEIN_512)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_SKEIN_512_HEADERS}
         )
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_SKEIN_512_SOURCES}
         )
endif()

if(CRYPTO3_HASH_SM3)
    list(APPEND ${CURRENT_PROJECT_NAME}_SM3_HEADERS
         include/nil/crypto3/hash/sm3.hpp
         )

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_SM3)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_SM3_HEADERS}
         )
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_SM3_SOURCES}
         )
endif()

if(CRYPTO3_HASH_STREEBOG)
    list(APPEND ${CURRENT_PROJECT_NAME}_STREEBOG_HEADERS
         include/nil/crypto3/hash/streebog.hpp
         )

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_STREEBOG)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_STREEBOG_HEADERS}
         )
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_STREEBOG_SOURCES}
         )
endif()

if(CRYPTO3_HASH_TIGER)
    list(APPEND ${CURRENT_PROJECT_NAME}_TIGER_HEADERS
         include/nil/crypto3/hash/tiger.hpp
         )

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_TIGER)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_TIGER_HEADERS}
         )
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_TIGER_SOURCES}
         )
endif()

if(CRYPTO3_HASH_WHIRLPOOL)
    list(APPEND ${CURRENT_PROJECT_NAME}_WHIRLPOOL_HEADERS
         include/nil/crypto3/hash/whirlpool.hpp
         )

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_WHIRLPOOL)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_WHIRLPOOL_HEADERS}
         )
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_WHIRLPOOL_SOURCES}
         )
endif()

if(CRYPTO3_HASH_CUBEHASH)
    list(APPEND ${CURRENT_PROJECT_NAME}_CUBEHASH_HEADERS
         include/nil/crypto3/hash/cubehash.hpp
         include/nil/crypto3/hash/detail/cubehash_policy.hpp
         )

    list(APPEND ${CURRENT_PROJECT_NAME}_CUBEHASH_SOURCES
         src/cubehash/cubehash.cpp
         )

    add_definitions(-D${CMAKE_UPPER_WORKSPACE_NAME}_HAS_CUBEHASH)
    list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
         ${${CURRENT_PROJECT_NAME}_CUBEHASH_HEADERS}
         )
    list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES
         ${${CURRENT_PROJECT_NAME}_CUBEHASH_SOURCES}
         )
endif()

list(APPEND ${CURRENT_PROJECT_NAME}_HEADERS
     ${${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS}
     )

cm_setup_version(VERSION 0.3.0 PREFIX ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME})

add_library(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
            ${${CURRENT_PROJECT_NAME}_HEADERS}
            ${${CURRENT_PROJECT_NAME}_SOURCES})
set_target_properties(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PROPERTIES LINKER_LANGUAGE CXX EXPORT_NAME
                      ${CURRENT_PROJECT_NAME} CXX_STANDARD 14)

target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PUBLIC
                      ${CMAKE_WORKSPACE_NAME}::block
                      ${CMAKE_WORKSPACE_NAME}::utilities

                      ${Boost_LIBRARIES})

target_include_directories(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PRIVATE
                           "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                           "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                           ${Boost_INCLUDE_DIR})

cm_deploy(TARGETS ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INCLUDE include NAMESPACE ${CMAKE_WORKSPACE_NAME}::)

if(APPLE OR NOT ${CMAKE_TARGET_ARCHITECTURE} STREQUAL ${CMAKE_HOST_SYSTEM_PROCESSOR})
    set_target_properties(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PROPERTIES
                          XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY "${APPLE_CODE_SIGN_IDENTITY}"
                          XCODE_ATTRIBUTE_DEVELOPMENT_TEAM "${CMAKE_XCODE_ATTRIBUTE_DEVELOPMENT_TEAM}")
endif()

add_subdirectory(test)
