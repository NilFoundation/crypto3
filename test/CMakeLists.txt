include(CMTest)

if(NOT Boost_UNIT_TEST_FRAMEWORK_FOUND)
    cm_find_package(Boost REQUIRED COMPONENTS unit_test_framework)
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
    cm_test(NAME pubkey_${name}_test SOURCES ${name}.cpp)

    target_include_directories(pubkey_${name}_test PRIVATE
                               "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                               "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                               ${Boost_INCLUDE_DIRS})

    set_target_properties(pubkey_${name}_test PROPERTIES CXX_STANDARD 17)

    get_target_property(target_type Boost::unit_test_framework TYPE)
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
