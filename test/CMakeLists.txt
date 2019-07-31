include(CMTest)

if(NOT Boost_UNIT_TEST_FRAMEWORK_FOUND)
    cm_find_package(Boost REQUIRED COMPONENTS unit_test_framework)
endif()

cm_test_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
                       ${CMAKE_WORKSPACE_NAME}::codec
                       ${CMAKE_WORKSPACE_NAME}::hash

                       ${Boost_LIBRARIES})

macro(define_block_cipher_test name)
    cm_test(NAME block_${name}_test SOURCES ${name}.cpp)

    target_include_directories(block_${name}_test PRIVATE
                               "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                               "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

                               ${Boost_INCLUDE_DIRS})

    set_target_properties(block_${name}_test PROPERTIES CXX_STANDARD 14)

    get_target_property(target_type Boost::unit_test_framework TYPE)
    if(target_type STREQUAL "SHARED_LIB")
        target_compile_definitions(block_${name}_test PRIVATE BOOST_TEST_DYN_LINK)
    elseif(target_type STREQUAL "STATIC_LIB")

    endif()
endmacro()

set(TESTS_NAMES
    "pack"
    "rijndael"
    "aria"
    "blowfish"
    "camellia"
    "cast"
    "des"
    "gost28147"
    "idea"
    "kasumi"
    "misty1"
    "noekeon"
    "seed"
    "serpent"
    "shacal"
    "sm4"
#    "threefish"
    "twofish"
    "xtea"
    )

foreach(TEST_NAME ${TESTS_NAMES})
    define_block_cipher_test(${TEST_NAME})
endforeach()
