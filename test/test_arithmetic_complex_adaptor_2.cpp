///////////////////////////////////////////////////////////////
//  Copyright 2012 John Maddock. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at https://www.boost.org/LICENSE_1_0.txt

#define MIXED_OPS_ONLY

#include <nil/crypto3/multiprecision/cpp_complex.hpp>

#include "libs/multiprecision/test/test_arithmetic.hpp"

int main() {
    test<nil::crypto3::multiprecision::cpp_complex_50>();
    test<nil::crypto3::multiprecision::number<
        nil::crypto3::multiprecision::complex_adaptor<nil::crypto3::multiprecision::cpp_bin_float<50>>,
        nil::crypto3::multiprecision::et_on>>();
    return boost::report_errors();
}
