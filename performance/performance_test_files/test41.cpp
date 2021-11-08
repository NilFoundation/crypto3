///////////////////////////////////////////////////////////////
//  Copyright 2019 John Maddock. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at https://www.boost.org/LICENSE_1_0.txt

#include "../performance_test.hpp"
#if defined(TEST_CPP_INT)
#include <nil/crypto3/multiprecision/cpp_int.hpp>
#endif

void test41() {
#ifdef TEST_CPP_INT
    test<nil::crypto3::multiprecision::cpp_int>("cpp_int",
                                                (nil::crypto3::multiprecision::backends::karatsuba_cutoff + 2) *
                                                    sizeof(nil::crypto3::multiprecision::limb_type) * CHAR_BIT);
#endif
}
