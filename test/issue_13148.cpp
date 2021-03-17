///////////////////////////////////////////////////////////////////////////////
//  Copyright 2016 John Maddock. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

#include <nil/crypto3/multiprecision/cpp_int.hpp>
#include <nil/crypto3/multiprecision/cpp_dec_float.hpp>
#include <nil/crypto3/multiprecision/cpp_bin_float.hpp>

nil::crypto3::multiprecision::cpp_rational rationalfromStr(const char* str) {
    nil::crypto3::multiprecision::cpp_dec_float_50 d1(str);
    nil::crypto3::multiprecision::cpp_rational result(d1);    // <--- eats CPU forever
    return result;
}

nil::crypto3::multiprecision::cpp_rational rationalfromStr2(const char* str) {
    nil::crypto3::multiprecision::cpp_bin_float_50 d1(str);
    nil::crypto3::multiprecision::cpp_rational result(d1);    // <--- eats CPU forever
    return result;
}

int main() {
    // This example is OK.
    {
        nil::crypto3::multiprecision::cpp_rational expected = 1;
        BOOST_ASSERT(expected == rationalfromStr("1"));
    }
    // This example is OK.
    {
        nil::crypto3::multiprecision::cpp_rational expected =
            nil::crypto3::multiprecision::cpp_rational(25) / nil::crypto3::multiprecision::cpp_rational(10);
        BOOST_ASSERT(expected == rationalfromStr("2.5"));
    }
    // This example is OK.
    {
        nil::crypto3::multiprecision::cpp_rational expected =
            nil::crypto3::multiprecision::cpp_rational(5) / nil::crypto3::multiprecision::cpp_rational(1000);
        BOOST_ASSERT(expected == rationalfromStr("0.005"));
    }
    // This example is OK.
    {
        nil::crypto3::multiprecision::cpp_rational expected = 0;
        BOOST_ASSERT(expected ==
                     nil::crypto3::multiprecision::cpp_rational("0"));    // direct cpp_rational from str is OK.
    }
    // This example fails.
    {
        nil::crypto3::multiprecision::cpp_rational expected = 0;
        // reachable code
        BOOST_ASSERT(expected == rationalfromStr("0"));    // cpp_rational from cpp_dec_float_50 is not OK.
                                                           // unreachable code
    }
    {
        nil::crypto3::multiprecision::cpp_rational expected = 0;
        // reacheble code
        BOOST_ASSERT(expected == rationalfromStr2("0"));    // cpp_rational from cpp_dec_float_50 is not OK.
                                                            // unreachable code
    }
    return 0;
}
