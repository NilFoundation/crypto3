cmake_minimum_required(VERSION 3.21.4)

project(crypto3_blueprint VERSION 0.1.0 LANGUAGES C CXX)

option(CMAKE_ENABLE_TESTS "Enable tests" FALSE) # used by CMTest module
option(BUILD_EXAMPLES "Build examples" FALSE)

find_package(CM)

add_library(blueprint INTERFACE)
add_library(crypto3::blueprint ALIAS blueprint)

include(GNUInstallDirs)
target_include_directories(blueprint INTERFACE
                           "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                           "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
)

target_link_libraries(blueprint INTERFACE
                      ${Boost_LIBRARIES}
)

include(CMTest)
cm_add_test_subdirectory(test)

if(BUILD_EXAMPLES)
    add_subdirectory(example)
endif()
