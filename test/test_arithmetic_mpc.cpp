///////////////////////////////////////////////////////////////
//  Copyright 2012 John Maddock. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at https://www.boost.org/LICENSE_1_0.txt

#include <nil/crypto3/multiprecision/mpc.hpp>
#define TEST_MPC

#include "libs/multiprecision/test/test_arithmetic.hpp"

template<unsigned D>
struct related_type<nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::mpc_complex_backend<D>>> {
    typedef nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::mpfr_float_backend<D>> type;
};

int main() {
    test<nil::crypto3::multiprecision::mpc_complex_50>();
    return boost::report_errors();
}
