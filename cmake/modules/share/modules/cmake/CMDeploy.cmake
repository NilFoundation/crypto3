
include(CMPkgConfig)
include(CMInstallTargets)
include(CMExport)

function(cm_deploy)
    set(options SKIP_HEADER_INSTALL)
    set(oneValueArgs NAMESPACE COMPATIBILITY PACKAGE_NAME)
    set(multiValueArgs TARGETS INCLUDE)

    cmake_parse_arguments(PARSE "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    if(PARSE_PACKAGE_NAME)
        set(PACKAGE_NAME ${PARSE_PACKAGE_NAME})
    else()
        set(PACKAGE_NAME ${PROJECT_NAME})
    endif()

    if(PARSE_SKIP_HEADER_INSTALL)
        cm_install_targets(TARGETS ${PARSE_TARGETS} INCLUDE ${PARSE_INCLUDE} SKIP_HEADER_INSTALL)
    else()
        cm_install_targets(TARGETS ${PARSE_TARGETS} INCLUDE ${PARSE_INCLUDE})
    endif()

    get_property(isMultiConfig GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)

    if(NOT isMultiConfig)
        cm_auto_pkgconfig(TARGET ${PARSE_TARGETS})
    endif()

    cm_auto_export(TARGETS ${PARSE_TARGETS} NAMESPACE ${PARSE_NAMESPACE} COMPATIBILITY ${PARSE_COMPATIBILITY})

    foreach(TARGET ${PARSE_TARGETS})
        get_target_property(TARGET_NAME ${TARGET} EXPORT_NAME)
        if(NOT TARGET_NAME)
            get_target_property(TARGET_NAME ${TARGET} NAME)
        endif()
        set(EXPORT_LIB_TARGET ${PARSE_NAMESPACE}${TARGET_NAME})
        if(NOT TARGET ${EXPORT_LIB_TARGET})
            add_library(${EXPORT_LIB_TARGET} ALIAS ${TARGET})
        endif()
        if(CMAKE_WORKSPACE_NAME)
            string(TOLOWER ${CMAKE_WORKSPACE_NAME} CMAKE_WORKSPACE_NAME_LOWER)
            SET(PACKAGE_NAME "${CMAKE_WORKSPACE_NAME_LOWER}_${PACKAGE_NAME}")
        endif()
        set_target_properties(${TARGET} PROPERTIES INTERFACE_FIND_PACKAGE_NAME ${PACKAGE_NAME})

        if(COMMAND cm_add_rpath)
            get_target_property(TARGET_TYPE ${TARGET} TYPE)
            if(NOT "${TARGET_TYPE}" STREQUAL "INTERFACE_LIBRARY")
                cm_add_rpath("$<TARGET_FILE_DIR:${TARGET}>")
            endif()
        endif()
        cm_shadow_notify(${EXPORT_LIB_TARGET})
        cm_shadow_notify(${TARGET})
    endforeach()

endfunction()
