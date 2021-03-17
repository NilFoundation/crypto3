///////////////////////////////////////////////////////////////
//  Copyright 2012 John Maddock. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at https://www.boost.org/LICENSE_1_0.txt

#ifdef _MSC_VER
#define _SCL_SECURE_NO_WARNINGS
#endif

#include <nil/crypto3/multiprecision/mpfr.hpp>
#define TEST_MPFR
#include "test_arithmetic.hpp"

template<unsigned D>
struct related_type<nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::mpfr_float_backend<D>>> {
    typedef nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::mpfr_float_backend<D / 2>> type;
};

int main() {
    test<nil::crypto3::multiprecision::static_mpfr_float_50>();
    return boost::report_errors();
}
