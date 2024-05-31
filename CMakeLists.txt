#---------------------------------------------------------------------------#
# Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

cmake_minimum_required(VERSION 3.2)

cmake_policy(SET CMP0042 NEW)
cmake_policy(SET CMP0028 NEW)
cmake_policy(SET CMP0057 NEW)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake"
     "${CMAKE_CURRENT_LIST_DIR}/cmake/packages"
     "${CMAKE_CURRENT_LIST_DIR}/cmake/modules/share/modules/cmake")

include(CMConfig)
include(CMSetupVersion)

cm_workspace(crypto3)
cm_setup_version(VERSION 0.3.0 PREFIX ${CMAKE_WORKSPACE_NAME})

option(BUILD_SHARED_LIBS "Build shared library" FALSE) # TODO: it makes no sense for header-only lib, remove
option(Boost_USE_STATIC_LIBS "Use static libraries for Boost" OFF)
option(CMAKE_ENABLE_TESTS "Enable tests" FALSE) # used by CMTest module
option(BUILD_BENCH_TESTS "Build performance benchmark tests" FALSE)
option(BUILD_DOCS "Build with configuring Doxygen documentation compiler" FALSE)

set(BUILD_WITH_TARGET_ARCHITECTURE "" CACHE STRING "Target build architecture") # TODO: check if we can do cross-compilation
set(DOXYGEN_OUTPUT_DIR "${CMAKE_CURRENT_LIST_DIR}/docs" CACHE STRING "Specify doxygen output directory")

include(TargetArchitecture)

if(BUILD_WITH_TARGET_ARCHITECTURE)
    set(CMAKE_TARGET_ARCHITECTURE ${BUILD_WITH_TARGET_ARCHITECTURE})
else()
    target_architecture(CMAKE_TARGET_ARCHITECTURE)
endif()

find_package(Boost REQUIRED COMPONENTS container random filesystem log log_setup program_options thread system)
if(CMAKE_ENABLE_TESTS)
    find_package(Boost REQUIRED COMPONENTS unit_test_framework timer)
endif()

add_subdirectories("${CMAKE_CURRENT_LIST_DIR}/libs/")
add_subdirectories("${CMAKE_CURRENT_LIST_DIR}/libs/marshalling")

configure_file(${CMAKE_CURRENT_LIST_DIR}/docs/doxygen/${CMAKE_WORKSPACE_NAME}.doxyfile.in
    ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_WORKSPACE_NAME}.doxyfile @ONLY)

# Configure package file to be able to import crypto3 headers
# TODO: remove it after resolving cyclical dependencies in crypto3 modules
include(CMakePackageConfigHelpers)
include(GNUInstallDirs)
set(CONFIG_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/crypto3)

configure_package_config_file(
    cmake/Config.cmake.in
    crypto3Config.cmake
    INSTALL_DESTINATION ${CONFIG_DIR}
)

install(
    FILES
    ${CMAKE_CURRENT_BINARY_DIR}/crypto3Config.cmake
    DESTINATION ${CONFIG_DIR}
)
