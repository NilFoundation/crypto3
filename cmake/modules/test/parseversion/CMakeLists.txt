
project(simple)

find_package(CM)

include(CMInstallTargets)
include(CMDeploy)
include(CMSetupVersion)
include(CMTest)

cm_setup_version(PARSE_HEADER include/version.h)

if(NOT "${PROJECT_VERSION}" STREQUAL "2.3.5")
    message(SEND_ERROR "Incorrect version was parsed: ${PROJECT_VERSION}")
endif()

add_library(simple INTERFACE)

cm_install_targets(TARGETS simple INCLUDE include)

cm_test(NAME simpletest SOURCES test.cpp)
target_link_libraries(simpletest simple)

cm_test(NAME simpletestcompile SOURCES compiletest.cpp COMPILE_ONLY)
target_link_libraries(simpletestcompile simple)

cm_test_header(NAME simpletestheader HEADER simple.h)
target_link_libraries(simpletestheader simple)

cm_test_header(NAME simpleteststaticheader HEADER simple.h STATIC)
target_link_libraries(simpleteststaticheader simple)

