cmake_minimum_required(VERSION 3.2)

cmake_policy(SET CMP0042 NEW)
cmake_policy(SET CMP0028 NEW)
cmake_policy(SET CMP0057 NEW)

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

cm_project(marshalling WORKSPACE_NAME ${CMAKE_WORKSPACE_NAME} LANGUAGES C CXX)

cm_find_package(CM)
include(CMDeploy)
include(FindPkgConfig)

include(CMSetupVersion)

option(BUILD_TESTS "Build unit tests" TRUE)
option(BUILD_WITH_NO_WARNINGS "Build threading warnings as errors" FALSE)

if((UNIX) AND (NOT CC_NO_CCACHE))
    find_program(CCACHE_FOUND ccache)
    if(CCACHE_FOUND)
        set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
        set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache)
    endif(CCACHE_FOUND)
endif()


list(APPEND ${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS
     include/nil/marshalling/status_type.hpp
     include/nil/marshalling/algorithms/pack.hpp
     include/nil/marshalling/types/array_list.hpp)

list(APPEND ${CURRENT_PROJECT_NAME}_UNGROUPED_SOURCES)

list(APPEND ${CURRENT_PROJECT_NAME}_HEADERS ${${CURRENT_PROJECT_NAME}_PUBLIC_HEADERS})

list(APPEND ${CURRENT_PROJECT_NAME}_SOURCES ${${CURRENT_PROJECT_NAME}_UNGROUPED_SOURCES})

cm_setup_version(VERSION 0.1.0 PREFIX ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME})

add_library(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE)

set_target_properties(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} PROPERTIES
                      EXPORT_NAME ${CURRENT_PROJECT_NAME})

target_include_directories(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
                           "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                           "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>")

cm_deploy(TARGETS ${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
          INCLUDE include
          NAMESPACE ${CMAKE_WORKSPACE_NAME}::)

if(BUILD_TESTS)
    add_subdirectory(test)
endif()

if((CMAKE_COMPILER_IS_GNUCC) OR ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang"))
    set(extra_flags_list -Wall -Wextra -Wcast-align -Wcast-qual
        -Wctor-dtor-privacy -Wmissing-include-dirs -Woverloaded-virtual
        -Wredundant-decls -Wshadow -Wundef -Wunused -Wno-unknown-pragmas
        -fdiagnostics-show-option)

    if(CMAKE_COMPILER_IS_GNUCC)
        list(APPEND extra_flags_list -Wnoexcept -Wlogical-op -Wstrict-null-sentinel)

        if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "4.8")
            list(APPEND extra_flags_list -Wno-pragmas -Wno-type-limits)
        endif()

    endif()

    if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
        list(APPEND extra_flags_list -Wno-dangling-field -Wno-unused-command-line-argument)
    endif()

    if(NOT BUILD_WITH_NO_WARNINGS)
        list(APPEND extra_flags_list -Werror)
    endif()

    target_compile_options(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE ${extra_flags})

    if(NOT BUILD_SHARED_LIBS AND NOT "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libstdc++ -static-libgcc")
    endif()
elseif(MSVC)

    add_definitions("/wd4503" "/wd4309" "/wd4267" "-D_SCL_SECURE_NO_WARNINGS")

    if(NOT BUILD_WITH_NO_WARNINGS)
        add_definitions("/WX")
    endif()

    if(NOT BUILD_SHARED_LIBS)
        foreach(flag_var
                CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE
                CMAKE_CXX_FLAGS_MINSIZEREL CMAKE_CXX_FLAGS_RELWITHDEBINFO)
            if(${flag_var} MATCHES "/MD")
                string(REGEX REPLACE "/MD" "/MT" ${flag_var} "${${flag_var}}")
            endif()
        endforeach()
    endif()
endif()

if(CMAKE_TOOLCHAIN_FILE AND EXISTS ${CMAKE_TOOLCHAIN_FILE})
    message(STATUS "Loading toolchain from ${CMAKE_TOOLCHAIN_FILE}")
endif()

find_package(Doxygen)
if(DOXYGEN_FOUND)
    set(doc_output_dir "${DOC_INSTALL_DIR}/marshalling")
    make_directory(${doc_output_dir})

    set(match_str "OUTPUT_DIRECTORY[^\n]*")
    set(replacement_str "OUTPUT_DIRECTORY = ${doc_output_dir}")
    set(output_file "${CMAKE_CURRENT_BINARY_DIR}/docs/doxygen.conf")

    set(config_file "${CMAKE_CURRENT_SOURCE_DIR}/docs/doxygen.conf")
    file(READ ${config_file} config_text)
    string(REGEX REPLACE "${match_str}" "${replacement_str}" modified_config_text "${config_text}")
    file(WRITE "${output_file}" "${modified_config_text}")

    add_custom_target("doc_${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}"
                      COMMAND ${DOXYGEN_EXECUTABLE} ${output_file}
                      COMMAND ${CMAKE_COMMAND} -DDOC_OUTPUT_DIR="${doc_output_dir}" -P
                      ${CMAKE_SOURCE_DIR}/cmake/DocCleanupScript.cmake
                      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
endif()