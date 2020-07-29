include(CMTest)

if(Boost_FOUND AND BUILD_SHARED_LIBS)
    set(Boost_USE_STATIC_LIBS FALSE)
else()
    set(Boost_USE_STATIC_LIBS TRUE)
endif()

cm_test_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}
                       ${Boost_LIBRARIES})

cm_test(NAME mgf1_test SOURCES mgf1.cpp)
target_include_directories(mgf1_test PRIVATE ${Boost_INCLUDE_DIRS})
set_target_properties(mgf1_test PROPERTIES CXX_STANDARD 14)
target_compile_definitions(mgf1_test PRIVATE $<$<STREQUAL:$<UPPER_CASE:$<TARGET_PROPERTY:BUILD_SHARED_LIBS>>,
                           TRUE>:BOOST_TEST_DYN_LINK>)
