#---------------------------------------------------------------------------#
# Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

include(CheckTypeSize)

function(define_target_platform_features prefix_name)
    include(CheckSymbolExists)

    string(TOUPPER ${prefix_name} UPPER_PREFIX_NAME)

    if(UNIX)
        if(APPLE)
            add_definitions(-D${UPPER_PREFIX_NAME}_TARGET_OS_IS_DARWIN)

            add_definitions(-D${UPPER_PREFIX_NAME}_TARGET_OS_HAS_ARC4RANDOM)
            add_definitions(-D${UPPER_PREFIX_NAME}_TARGET_OS_HAS_MEMSET_S)
        else()
            add_definitions(-D${UPPER_PREFIX_NAME}_TARGET_OS_HAS_POSIX_MLOCK)
        endif()

        add_definitions(-D${UPPER_PREFIX_NAME}_TARGET_OS_TYPE_IS_UNIX)

        add_definitions(-D${UPPER_PREFIX_NAME}_TARGET_OS_HAS_GMTIME_R)
        add_definitions(-D${UPPER_PREFIX_NAME}_TARGET_OS_HAS_DEV_RANDOM)
        add_definitions(-D${UPPER_PREFIX_NAME}_TARGET_OS_HAS_POSIX1)
        add_definitions(-D${UPPER_PREFIX_NAME}_TARGET_OS_HAS_FILELSYSTEM)
        add_definitions(-D${UPPER_PREFIX_NAME}_TARGET_OS_HAS_TIMEGM)
        add_definitions(-D${UPPER_PREFIX_NAME}_TARGET_OS_HAS_SOCKETS)
        add_definitions(-D${UPPER_PREFIX_NAME}_TARGET_OS_HAS_READDIR)
        add_definitions(-D${UPPER_PREFIX_NAME}_TARGET_OS_HAS_DLOPEN)
    elseif(WIN32)
        add_definitions(-D${UPPER_PREFIX_NAME}_TARGET_OS_TYPE_IS_WINDOWS)
        add_definitions(-D${UPPER_PREFIX_NAME}_TARGET_OS_HAS_WIN32)

        add_definitions(-D${UPPER_PREFIX_NAME}_TARGET_OS_HAS_RTLGENRANDOM)
        add_definitions(-D${UPPER_PREFIX_NAME}_TARGET_OS_HAS_GMTIME_S)
        add_definitions(-D${UPPER_PREFIX_NAME}_TARGET_OS_HAS_LOADLIBRARY)
        add_definitions(-D${UPPER_PREFIX_NAME}_TARGET_OS_HAS_MKGMTIME)
        add_definitions(-D${UPPER_PREFIX_NAME}_TARGET_OS_HAS_QUERY_PREF_COUNTER)
        add_definitions(-D${UPPER_PREFIX_NAME}_TARGET_OS_HAS_VIRTUAL_LOCK)
        add_definitions(-D${UPPER_PREFIX_NAME}_TARGET_OS_HAS_RTLSECUREZEROMEMORY)
        add_definitions(-D${UPPER_PREFIX_NAME}_TARGET_OS_HAS_STL_FILESYSTEM_MSVC)
    endif()

    add_definitions(-D${UPPER_PREFIX_NAME}_TARGET_OS_HAS_THREADS)
endfunction()