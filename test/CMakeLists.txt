include(CMTest)

cm_find_package(${CMAKE_WORKSPACE_NAME}_codec)
cm_find_package(${CMAKE_WORKSPACE_NAME}_hash)
cm_find_package(${CMAKE_WORKSPACE_NAME}_algebra)

if (NOT Boost_UNIT_TEST_FRAMEWORK_FOUND)
    cm_find_package(Boost REQUIRED COMPONENTS unit_test_framework)
endif ()

cm_test_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
                       ${CMAKE_WORKSPACE_NAME}::codec
                       ${CMAKE_WORKSPACE_NAME}::hash
                       ${CMAKE_WORKSPACE_NAME}::algebra
                       marshalling::crypto3_algebra

                       ${Boost_LIBRARIES})

macro(define_pkpad_test name)
    cm_test(NAME pkpad_${name}_test SOURCES ${name}.cpp)

    target_include_directories(pkpad_${name}_test PRIVATE
            "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
            "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

            ${Boost_INCLUDE_DIRS})

    set_target_properties(pkpad_${name}_test PROPERTIES CXX_STANDARD 17)

    get_target_property(target_type Boost::unit_test_framework TYPE)
    if (target_type STREQUAL "SHARED_LIB")
        target_compile_definitions(pkpad_${name}_test PRIVATE BOOST_TEST_DYN_LINK)
    elseif (target_type STREQUAL "STATIC_LIB")

    endif ()
endmacro()

set(TESTS_NAMES
        "emsa1"
        )

foreach (TEST_NAME ${TESTS_NAMES})
    define_pkpad_test(${TEST_NAME})
endforeach ()
