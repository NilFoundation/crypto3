#---------------------------------------------------------------------------#
# Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

if(FLINT_INCLUDE_DIR AND FLINT_LIBRARIES)
    # Already in cache, be silent
    set(FLINT_FIND_QUIETLY TRUE)
endif()

find_path(FLINT_INCLUDE_DIR flint/flint.h)
find_library(FLINT_LIBRARIES NAMES flint)

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(FLINT DEFAULT_MSG FLINT_INCLUDE_DIR FLINT_LIBRARIES)

mark_as_advanced(FLINT_INCLUDE_DIR FLINT_LIBRARIES)