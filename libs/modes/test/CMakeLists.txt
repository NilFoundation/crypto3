#---------------------------------------------------------------------------#
# Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

include(CMTest)

cm_test_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}

                       ${CMAKE_WORKSPACE_NAME}::block
                       ${CMAKE_WORKSPACE_NAME}::codec
                       ${CMAKE_WORKSPACE_NAME}::multiprecision

                       Boost::unit_test_framework)

macro(define_mode_test name)
    cm_test(NAME mode_${name}_test SOURCES ${name}.cpp)

    target_include_directories(mode_${name}_test PRIVATE
                               "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                               "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                               ${Boost_INCLUDE_DIRS})

    set_target_properties(mode_${name}_test PROPERTIES CXX_STANDARD 14)
endmacro()

set(TESTS_NAMES
    #cbc
    #cfb
    #ctr
    cts
    #ofb
    #xts
    #ecb
    #padding
    #aead_ccm
    #aead_chacha20poly1305
    #aead_eax
    #aead_gcm
    #aead_ocb
    #aead_siv
    )

foreach(TEST_NAME ${TESTS_NAMES})
    define_mode_test(${TEST_NAME})
endforeach()
