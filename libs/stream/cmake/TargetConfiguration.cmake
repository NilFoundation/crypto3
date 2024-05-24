#---------------------------------------------------------------------------#
# Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

macro(define_current_target target_name project_name)
    set(CMAKE_CURRENT_TARGET ${target_name})
    string(TOUPPER ${target_name} CMAKE_UPPER_CURRENT_TARGET)
    string(TOUPPER ${project_name} CMAKE_UPPER_PROJECT_NAME)
    add_definitions(-D${CMAKE_UPPER_PROJECT_NAME}_HAS_${CMAKE_UPPER_CURRENT_TARGET})
endmacro()