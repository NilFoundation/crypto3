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

cm_workspace(nil)

macro(cm_find_package NAME)
    if(NOT "${NAME}" MATCHES "^${CMAKE_WORKSPACE_NAME}_.*$" AND NOT "${NAME}" STREQUAL CM)
        find_package(${ARGV})
    else()
        set(${ARGV0}_FOUND ON CACHE BOOL "")
    endif()
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
     include/nil/marshalling/accumulators/parameters/buffer_length.hpp
     include/nil/marshalling/accumulators/parameters/expected_status.hpp
     include/nil/marshalling/accumulators/marshalling.hpp
     include/nil/marshalling/algorithms/pack.hpp
     include/nil/marshalling/detail/message/implementation_builder.hpp
     include/nil/marshalling/detail/message/implementation_options_parser.hpp
     include/nil/marshalling/detail/message/interface_builder.hpp
     include/nil/marshalling/detail/message/interface_options_parser.hpp
     include/nil/marshalling/detail/msg_factory/base.hpp
     include/nil/marshalling/detail/msg_factory/bin_search_base.hpp
     include/nil/marshalling/detail/msg_factory/direct.hpp
     include/nil/marshalling/detail/msg_factory/generic.hpp
     include/nil/marshalling/detail/msg_factory/options_parser.hpp
     include/nil/marshalling/detail/msg_factory/selector.hpp
     include/nil/marshalling/detail/msg_factory/uniq.hpp
     include/nil/marshalling/detail/base_detection.hpp
     include/nil/marshalling/detail/bits_access.hpp
     include/nil/marshalling/detail/detect.hpp
     include/nil/marshalling/detail/field_base.hpp
     include/nil/marshalling/detail/fields_access.hpp
     include/nil/marshalling/detail/gen_enum.hpp
     include/nil/marshalling/detail/macro_common.hpp
     include/nil/marshalling/detail/protocol_layers_access.hpp
     include/nil/marshalling/detail/reverse_macro_args.hpp
     include/nil/marshalling/detail/transport_fields_access.hpp
     include/nil/marshalling/detail/type_traits.hpp
     include/nil/marshalling/detail/variant_access.hpp
     include/nil/marshalling/processing/access.hpp
     include/nil/marshalling/processing/aligned_union.hpp
     include/nil/marshalling/processing/alloc.hpp
     include/nil/marshalling/processing/bit_size_to_byte_size.hpp
     include/nil/marshalling/processing/scope_guard.hpp
     include/nil/marshalling/processing/size_to_type.hpp
     include/nil/marshalling/processing/tuple.hpp
     include/nil/marshalling/container/array_view.hpp
     include/nil/marshalling/container/static_queue.hpp
     include/nil/marshalling/container/static_string.hpp
     include/nil/marshalling/container/static_vector.hpp
     include/nil/marshalling/container/string_view.hpp
     include/nil/marshalling/protocol/checksum/basic_sum.hpp
     include/nil/marshalling/protocol/checksum/crc.hpp
     include/nil/marshalling/protocol/detail/checksum_layer_options_parser.hpp
     include/nil/marshalling/protocol/detail/protocol_layer_base_options_parser.hpp
     include/nil/marshalling/protocol/detail/transport_value_layer_adapter.hpp
     include/nil/marshalling/protocol/detail/transport_value_layer_options_parser.hpp
     include/nil/marshalling/protocol/checksum_layer.hpp
     include/nil/marshalling/protocol/checksum_prefix_layer.hpp
     include/nil/marshalling/protocol/msg_data_layer.hpp
     include/nil/marshalling/protocol/msg_id_layer.hpp
     include/nil/marshalling/protocol/msg_size_layer.hpp
     include/nil/marshalling/protocol/protocol_layer_base.hpp
     include/nil/marshalling/protocol/sync_prefix_layer.hpp
     include/nil/marshalling/protocol/transport_value_layer.hpp
     include/nil/marshalling/types/adapter/custom_refresher.hpp
     include/nil/marshalling/types/adapter/custom_validator.hpp
     include/nil/marshalling/types/adapter/custom_value_reader.hpp
     include/nil/marshalling/types/adapter/default_value_initialiser.hpp
     include/nil/marshalling/types/adapter/empty_serialization.hpp
     include/nil/marshalling/types/adapter/exists_between_versions.hpp
     include/nil/marshalling/types/adapter/fail_on_invalid.hpp
     include/nil/marshalling/types/adapter/fixed_bit_length.hpp
     include/nil/marshalling/types/adapter/fixed_length.hpp
     include/nil/marshalling/types/adapter/ignore_invalid.hpp
     include/nil/marshalling/types/adapter/invalid_by_default.hpp
     include/nil/marshalling/types/adapter/num_value_multi_range_validator.hpp
     include/nil/marshalling/types/adapter/sequence_elem_fixed_ser_length_field_prefix.hpp
     include/nil/marshalling/types/adapter/sequence_elem_length_forcing.hpp
     include/nil/marshalling/types/adapter/sequence_elem_ser_length_field_prefix.hpp
     include/nil/marshalling/types/adapter/sequence_fixed_size.hpp
     include/nil/marshalling/types/adapter/sequence_length_forcing.hpp
     include/nil/marshalling/types/adapter/sequence_ser_length_field_prefix.hpp
     include/nil/marshalling/types/adapter/sequence_size_field_prefix.hpp
     include/nil/marshalling/types/adapter/sequence_size_forcing.hpp
     include/nil/marshalling/types/adapter/sequence_termination_field_suffix.hpp
     include/nil/marshalling/types/adapter/sequence_trailing_field_suffix.hpp
     include/nil/marshalling/types/adapter/ser_offset.hpp
     include/nil/marshalling/types/adapter/var_length.hpp
     include/nil/marshalling/types/adapter/version_storage.hpp
     include/nil/marshalling/types/basic/array_list.hpp
     include/nil/marshalling/types/basic/bitfield.hpp
     include/nil/marshalling/types/basic/bundle.hpp
     include/nil/marshalling/types/basic/common_funcs.hpp
     include/nil/marshalling/types/basic/enum_value.hpp
     include/nil/marshalling/types/basic/float_value.hpp
     include/nil/marshalling/types/basic/int_value.hpp
     include/nil/marshalling/types/basic/no_value.hpp
     include/nil/marshalling/types/basic/optional.hpp
     include/nil/marshalling/types/basic/string.hpp
     include/nil/marshalling/types/basic/variant.hpp
     include/nil/marshalling/types/detail/adapt_basic_field.hpp
     include/nil/marshalling/types/detail/adapters.hpp
     include/nil/marshalling/types/detail/options_parser.hpp
     include/nil/marshalling/types/array_list.hpp
     include/nil/marshalling/types/bitfield.hpp
     include/nil/marshalling/types/bitmask_value.hpp
     include/nil/marshalling/types/bundle.hpp
     include/nil/marshalling/types/enum_value.hpp
     include/nil/marshalling/types/float_value.hpp
     include/nil/marshalling/types/int_value.hpp
     include/nil/marshalling/types/no_value.hpp
     include/nil/marshalling/types/optional.hpp
     include/nil/marshalling/types/optional_mode.hpp
     include/nil/marshalling/types/string.hpp
     include/nil/marshalling/types/tag.hpp
     include/nil/marshalling/types/variant.hpp
     include/nil/marshalling/assert_type.hpp
     include/nil/marshalling/compile_control.hpp
     include/nil/marshalling/empty_handler.hpp
     include/nil/marshalling/field_cast.hpp
     include/nil/marshalling/field_type.hpp
     include/nil/marshalling/generic_handler.hpp
     include/nil/marshalling/generic_message.hpp
     include/nil/marshalling/marshalling_state.hpp
     include/nil/marshalling/message.hpp
     include/nil/marshalling/message_base.hpp
     include/nil/marshalling/msg_factory.hpp
     include/nil/marshalling/options.hpp
     include/nil/marshalling/status_type.hpp
     include/nil/marshalling/traits.hpp
     include/nil/marshalling/units.hpp
     include/nil/marshalling/version.hpp)

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

target_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME} INTERFACE
                      ${Boost_LIBRARIES})

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
