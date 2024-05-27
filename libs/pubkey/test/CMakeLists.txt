include(CMTest)

if(NOT Boost_UNIT_TEST_FRAMEWORK_FOUND)
    find_package(Boost REQUIRED COMPONENTS unit_test_framework)
endif()

cm_find_package(${CMAKE_WORKSPACE_NAME}_marshalling)
cm_find_package(${CMAKE_WORKSPACE_NAME}_random)
cm_find_package(${CMAKE_WORKSPACE_NAME}_blueprint)

cm_test_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
                       ${${CURRENT_PROJECT_NAME}_LIBRARIES}
                       marshalling::crypto3_zk
                       ${CMAKE_WORKSPACE_NAME}::containers
                       ${CMAKE_WORKSPACE_NAME}::pkpad
                       ${CMAKE_WORKSPACE_NAME}::random

                       ${Boost_LIBRARIES})

macro(define_pubkey_test name)

    set(additional_args "")
    if(ENABLE_JUNIT_TEST_OUTPUT)
        set(TEST_RESULTS_DIR "${CMAKE_CURRENT_BINARY_DIR}/junit_results")
        set(TEST_LOGS_DIR "${TEST_RESULTS_DIR}/logs")
        file(MAKE_DIRECTORY ${TEST_LOGS_DIR})

        set(additional_args "--log_format=JUNIT"
                            "--log_sink=${TEST_LOGS_DIR}/${test_name}.xml")
    endif()

    cm_test(NAME pubkey_${name}_test SOURCES ${name}.cpp ARGS ${additional_args})

    target_include_directories(pubkey_${name}_test PRIVATE
                               "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                               "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                               ${Boost_INCLUDE_DIRS})

    
    set_target_properties(pubkey_${name}_test PROPERTIES CXX_STANDARD 17)

    get_target_property(target_type Boost::unit_test_framework TYPE)
    if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        target_compile_options(pubkey_${name}_test PRIVATE "-fconstexpr-steps=2147483647" "-ftemplate-backtrace-limit=0")
    elseif (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(pubkey_${name}_test PRIVATE "-fconstexpr-ops-limit=4294967295" "-ftemplate-backtrace-limit=0")
    endif()

    if(target_type STREQUAL "SHARED_LIB")
        target_compile_definitions(pubkey_${name}_test PRIVATE BOOST_TEST_DYN_LINK)
    elseif(target_type STREQUAL "STATIC_LIB")

    endif()
endmacro()

set(TESTS_NAMES
    "ecdsa"
    "bls"
    "secret_sharing"
    "eddsa"
    "elgamal_verifiable")

foreach(TEST_NAME ${TESTS_NAMES})
    define_pubkey_test(${TEST_NAME})
endforeach()
