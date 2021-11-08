///////////////////////////////////////////////////////////////
//  Copyright 2012 John Maddock. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at https://www.boost.org/LICENSE_1_0.txt

#ifdef _MSC_VER
#define _SCL_SECURE_NO_WARNINGS
#endif

#include <nil/crypto3/multiprecision/gmp.hpp>

#include "test_arithmetic.hpp"

template<unsigned D>
struct related_type<nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::gmp_float<D>>> {
    typedef nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::gmp_float<D / 2>> type;
};
template<>
struct related_type<nil::crypto3::multiprecision::mpf_float> {
    typedef nil::crypto3::multiprecision::mpz_int type;
};

int main() {
    test<nil::crypto3::multiprecision::mpf_float_50>();
    return boost::report_errors();
}
