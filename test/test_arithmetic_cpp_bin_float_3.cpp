///////////////////////////////////////////////////////////////
//  Copyright 2012 John Maddock. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at https://www.boost.org/LICENSE_1_0.txt

#include <nil/crypto3/multiprecision/cpp_bin_float.hpp>

#include "libs/multiprecision/test/test_arithmetic.hpp"

template<unsigned Digits,
         nil::crypto3::multiprecision::backends::digit_base_type DigitBase,
         class Allocator,
         class Exponent,
         Exponent MinExponent,
         Exponent MaxExponent,
         nil::crypto3::multiprecision::expression_template_option ET>
struct related_type<nil::crypto3::multiprecision::number<
    nil::crypto3::multiprecision::cpp_bin_float<Digits, DigitBase, Allocator, Exponent, MinExponent, MaxExponent>,
    ET>> {
    typedef nil::crypto3::multiprecision::number<
        nil::crypto3::multiprecision::cpp_bin_float<Digits, DigitBase, Allocator, Exponent, MinExponent, MaxExponent>,
        ET>
        number_type;
    typedef nil::crypto3::multiprecision::number<
        nil::crypto3::multiprecision::cpp_bin_float<
            ((std::numeric_limits<number_type>::digits / 2) > std::numeric_limits<long double>::digits ? Digits / 2 :
                                                                                                         Digits),
            DigitBase,
            Allocator,
            Exponent,
            MinExponent,
            MaxExponent>,
        ET>
        type;
};

int main() {
    // test<nil::crypto3::multiprecision::cpp_bin_float_50>();
    // test<nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::cpp_bin_float<1000,
    // nil::crypto3::multiprecision::digit_base_10, std::allocator<char> > > >();
    test<nil::crypto3::multiprecision::cpp_bin_float_quad>();
    return boost::report_errors();
}
