
project(superproject)

find_package(CM)
include(CMIgnorePackage)

cm_ignore_package(simple)

add_subdirectory(../libbasicnamespace libbasicnamespace)
add_subdirectory(../libsimplenamespace libsimplenamespace)
