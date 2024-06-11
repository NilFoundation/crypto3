macro(define_current_target target_name project_name)
    set(CMAKE_CURRENT_TARGET ${target_name})
    string(TOUPPER ${target_name} CMAKE_UPPER_CURRENT_TARGET)
    string(TOUPPER ${project_name} CMAKE_UPPER_PROJECT_NAME)
    add_definitions(-D${CMAKE_UPPER_PROJECT_NAME}_HAS_${CMAKE_UPPER_CURRENT_TARGET})
endmacro()
