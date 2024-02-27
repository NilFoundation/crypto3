///////////////////////////////////////////////////////////////
//  Copyright 2019 John Maddock. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at https://www.boost.org/LICENSE_1_0.txt

#include "../performance_test.hpp"
#if defined(TEST_TOMMATH)
#include <nil/crypto3/multiprecision/tommath.hpp>
#endif

void test43() {
#ifdef TEST_TOMMATH
    test<nil::crypto3::multiprecision::tom_int>("tommath_int", 1024 * 2);
    /*
    //
    // These are actually too slow to test!!!
    //
    test<nil::crypto3::multiprecision::tom_rational>("tom_rational", 128);
    test<nil::crypto3::multiprecision::tom_rational>("tom_rational", 256);
    test<nil::crypto3::multiprecision::tom_rational>("tom_rational", 512);
    test<nil::crypto3::multiprecision::tom_rational>("tom_rational", 1024);
    */
#endif
}
