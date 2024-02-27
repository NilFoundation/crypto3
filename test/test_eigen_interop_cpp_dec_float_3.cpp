///////////////////////////////////////////////////////////////////////////////
//  Copyright 2018 John Maddock. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

#include <nil/crypto3/multiprecision/cpp_dec_float.hpp>

#include "eigen.hpp"

template<>
struct related_number<nil::crypto3::multiprecision::cpp_dec_float_100> {
    typedef nil::crypto3::multiprecision::cpp_dec_float_50 type;
};

int main() {
    using namespace nil::crypto3::multiprecision;
    // test_float_type_2<double>();
    test_float_type_3<nil::crypto3::multiprecision::cpp_dec_float_100>();
    return 0;
}
