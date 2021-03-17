///////////////////////////////////////////////////////////////////////////////
//  Copyright 2018 John Maddock. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

#include <nil/crypto3/multiprecision/mpfr.hpp>

#include "eigen.hpp"

int main() {
    using namespace nil::crypto3::multiprecision;
    test_float_type_3<nil::crypto3::multiprecision::mpfr_float>();
    return 0;
}
