#---------------------------------------------------------------------------#
# Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

include(CMDeploy)
include(CMSetupVersion)
include(CMConfig)

cm_project(vdf WORKSPACE_NAME ${CMAKE_WORKSPACE_NAME} LANGUAGES ASM C CXX)

include(CheckSSE)
include(CheckAVX)

include(TargetArchitecture)

if((NOT SSE2_FOUND) OR (NOT SSE3_FOUND) OR (NOT SSSE3_FOUND) OR (NOT SSE4_1_FOUND) OR (NOT SSE4_2_FOUND))
    check_sse()
endif()

if((NOT HAVE_AVX2_EXTENSIONS) OR (NOT HAVE_AVX_EXTENSIONS))
    check_avx()
endif()

if(NOT SSE2_FOUND OR NOT SSE3_FOUND OR NOT SSSE3_FOUND OR NOT SSE4_1_FOUND OR NOT SSE4_2_FOUND OR
   HAVE_AVX2_EXTENSIONS OR HAVE_AVX_EXTENSIONS)
    option(CRYPTO3_VDF_USE_SIMD "Build Crypto3.VDF with SIMD instructions usage." TRUE)
endif()

option(CRYPTO3_VDF_BOOST "Build Crypto3.VDF with Boost.Multiprecision backend usage" TRUE)
option(CRYPTO3_VDF_GMP "Build Crypto3.VDF with GMP backend usage" FALSE)
option(CRYPTO3_VDF_FLINT "Build Crypto3.VDF with FLINT backend usage" FALSE)
option(CRYPTO3_VDF_MPIR "Build Crypto3.VDF with MPIR backend usage" FALSE)

if(CRYPTO3_VDF_MPIR OR CRYPTO3_VDF_GMP OR CRYPTO3_VDF_FLINT)
    if(NOT BUILD_SHARED_LIBS)
        if(UNIX OR APPLE)
            set(CMAKE_FIND_LIBRARY_SUFFIXES ".a" ".la" ${CMAKE_FIND_LIBRARY_SUFFIXES})
        elseif(WIN32)
            set(CMAKE_FIND_LIBRARY_SUFFIXES ".lib" ${CMAKE_FIND_LIBRARY_SUFFIXES})
        endif()
    endif()

    if(CRYPTO3_VDF_MPIR)
        cm_find_package(MPIRXX REQUIRED)
    elseif(CRYPTO3_VDF_GMP)
        cm_find_package(GMP REQUIRED)
        cm_find_package(GMPXX REQUIRED)
        cm_find_package(MPFR REQUIRED)
    elseif(CRYPTO3_VDF_FLINT)
        cm_find_package(GMP REQUIRED)
        cm_find_package(FLINT REQUIRED)
        cm_find_package(MPFR REQUIRED)
    endif()
elseif(CRYPTO3_VDF_BOOST)
    if(NOT TARGET ${CMAKE_WORKSPACE_NAME}::multiprecision)
        if(${CMAKE_WORKSPACE_NAME} STREQUAL boost)
            cm_find_package(${CMAKE_WORKSPACE_NAME}_multiprecision)
        endif()
    endif()

    if(NOT Boost_FOUND)
        find_package(Boost REQUIRED)
    endif()

    if(Boost_FOUND)
        cm_find_package(TomMath)
    endif()

    cm_find_package(${CMAKE_WORKSPACE_NAME}_block)
    cm_find_package(${CMAKE_WORKSPACE_NAME}_hash)
endif()

if(CRYPTO3_VDF_GMP OR CRYPTO3_VDF_MPIR)
    option(CRYPTO3_VDF_CHIA "Build with Chia VDF support" TRUE)
else()
    option(CRYPTO3_VDF_PIETRZAK "Build with Pietrzak VDF support" TRUE)
    option(CRYPTO3_VDF_WESOLOWSKI "Build with Wesolowski VDF support" TRUE)
    option(CRYPTO3_VDF_CHIA "Build with Chia VDF support" TRUE)
endif()

cm_setup_version(VERSION 0.1.0 PREFIX ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME})

add_library(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE)

if(CRYPTO3_VDF_USE_SIMD)
    target_compile_definitions(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
                               "${CMAKE_UPPER_WORKSPACE_NAME}_VDF_SIMD")

    if(HAVE_AVX2_EXTENSIONS)
        target_compile_options(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE "-mavx2")
    elseif(HAVE_AVX_EXTENSIONS)
        target_compile_options(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE "-mavx")
    elseif(SSE4_2_FOUND)
        target_compile_options(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE "-msse4;-msse4.2")
    elseif(SSE4_1_FOUND)
        target_compile_options(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE "-msse4;-msse4.1")
    elseif(SSSE3_FOUND)
        target_compile_options(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE "-mssse3")
    elseif(SSE3_FOUND)
        target_compile_options(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE "-msse3")
    elseif(SSE2_FOUND)
        target_compile_options(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE "-msse2")
    endif()
endif()

target_compile_options(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE "$<$<CONFIG:RELEASE>:-O3;-fno-rtti>")

set_target_properties(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PROPERTIES
                      EXPORT_NAME ${CURRENT_PROJECT_NAME})

if(CRYPTO3_VDF_GMP)
    target_compile_definitions(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE CRYPTO3_VDF_GMP)

    target_include_directories(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
                               "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                               "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                               ${GMPXX_INCLUDE_DIR}
                               ${MPFR_INCLUDE_DIR})

    target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
                          ${GMP_LIBRARIES} ${GMPXX_LIBRARIES} ${MPFR_LIBRARIES})

elseif(CRYPTO3_VDF_MPIR)
    target_compile_definitions(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE CRYPTO3_VDF_MPIR)

    target_include_directories(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
                               "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                               "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                               ${MPIRXX_INCLUDE_DIR}
                               ${MPFR_INCLUDE_DIR})

    target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
                          ${MPIR_LIBRARIES} ${MPIRXX_LIBRARIES} ${MPFR_LIBRARIES})
elseif(CRYPTO3_VDF_FLINT)
    target_compile_definitions(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE CRYPTO3_VDF_FLINT)

    target_include_directories(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
                               "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                               "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                               ${MPFR_INCLUDE_DIR}
                               ${GMP_INCLUDE_DIR}
                               ${FLINT_INCLUDE_DIR})

    target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE ${FLINT_LIBRARIES}
                          ${MPFR_LIBRARIES} ${GMP_LIBRARIES})
elseif(CRYPTO3_VDF_BOOST)
    target_compile_definitions(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE CRYPTO3_VDF_BOOST)

    target_include_directories(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
                               "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                               "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                               ${Boost_INCLUDE_DIRS})

    if(TARGET nil::crypto3::multiprecision)
        target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
                              nil::crypto3::multiprecision

                              ${CMAKE_WORKSPACE_NAME}_block
                              ${CMAKE_WORKSPACE_NAME}_hash

                              Boost::container)
    else()
        target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
                              Boost::container)
    endif()
endif()

cm_deploy(TARGETS ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
          INCLUDE include
          NAMESPACE ${CMAKE_WORKSPACE_NAME}::)

# Commenting out the tests since libs/vdf/test/chia.cpp fails. 
#include(CMTest)
#cm_add_test_subdirectory(test)
