include(CMTest)

cm_test_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
                       ${CMAKE_WORKSPACE_NAME}::codec
                       ${CMAKE_WORKSPACE_NAME}::hash
                       ${CMAKE_WORKSPACE_NAME}::algebra
                       marshalling::crypto3_algebra

                       Boost::unit_test_framework)

macro(define_pkpad_test name)
    cm_test(NAME pkpad_${name}_test SOURCES ${name}.cpp)

    target_include_directories(pkpad_${name}_test PRIVATE
            "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
            "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

            ${Boost_INCLUDE_DIRS})

    set_target_properties(pkpad_${name}_test PROPERTIES CXX_STANDARD 17)

endmacro()

set(TESTS_NAMES
        "emsa1"
        )

foreach (TEST_NAME ${TESTS_NAMES})
    define_pkpad_test(${TEST_NAME})
endforeach ()
