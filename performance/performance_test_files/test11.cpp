///////////////////////////////////////////////////////////////
//  Copyright 2019 John Maddock. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at https://www.boost.org/LICENSE_1_0.txt

#include "../performance_test.hpp"
#if defined(TEST_CPP_INT)
#include <nil/crypto3/multiprecision/cpp_int.hpp>
#endif

void test11() {
#ifdef TEST_CPP_INT
    test<nil::crypto3::multiprecision::number<
        nil::crypto3::multiprecision::cpp_int_backend<512, 512, nil::crypto3::multiprecision::signed_magnitude,
                                                      nil::crypto3::multiprecision::unchecked, void>,
        nil::crypto3::multiprecision::et_off>>("cpp_int(fixed)", 512);
#endif
}
