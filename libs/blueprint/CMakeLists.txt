cmake_minimum_required(VERSION 3.21.4)

project(crypto3_blueprint VERSION 0.1.0 LANGUAGES C CXX)

option(CMAKE_ENABLE_TESTS "Enable tests" FALSE) # used by CMTest module
option(BUILD_EXAMPLES "Build examples" FALSE)

find_package(CM)
find_package(crypto3 REQUIRED)
find_package(Boost REQUIRED COMPONENTS container random filesystem log log_setup program_options thread system)


add_library(blueprint INTERFACE)
add_library(crypto3::blueprint ALIAS blueprint)

include(GNUInstallDirs)
target_include_directories(blueprint INTERFACE
                           "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                           "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
)

target_link_libraries(blueprint INTERFACE
                      ${Boost_LIBRARIES}
                      crypto3::all
)

include(CMTest)
cm_add_test_subdirectory(test)

if(BUILD_EXAMPLES)
    add_subdirectory(example)
endif()

# Install phase

set(EXPORT_NAME crypto3_blueprint-targets)
# Install target
install(TARGETS blueprint EXPORT ${EXPORT_NAME})
# Install headers
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

# Generate and install package config files

include(CMakePackageConfigHelpers)
set(CONFIG_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/crypto3_blueprint)
set(PACKAGE_CONFIG_NAME crypto3_blueprint-config)

write_basic_config_version_file(
    ${PACKAGE_CONFIG_NAME}-version.cmake
    VERSION ${crypto3_blueprint_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(
    FILES
    ${CMAKE_CURRENT_BINARY_DIR}/${PACKAGE_CONFIG_NAME}.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/${PACKAGE_CONFIG_NAME}-version.cmake
    DESTINATION ${CONFIG_DIR}
)

install(EXPORT ${EXPORT_NAME}
        NAMESPACE crypto3::
        DESTINATION ${CONFIG_DIR})
