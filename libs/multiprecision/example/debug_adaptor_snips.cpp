///////////////////////////////////////////////////////////////
//  Copyright 2011 John Maddock. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at https://www.boost.org/LICENSE_1_0.txt

#include <nil/crypto3/multiprecision/cpp_dec_float.hpp>
#include <nil/crypto3/multiprecision/debug_adaptor.hpp>
#include <iostream>

void t1() {
    //[debug_adaptor_eg
    //=#include <nil/crypto3/multiprecision/debug_adaptor.hpp>
    //=#include <nil/crypto3/multiprecision/cpp_dec_float.hpp>

    using namespace nil::crypto3::multiprecision;

    typedef number<debug_adaptor<cpp_dec_float<50>>> fp_type;

    fp_type denom = 1;
    fp_type sum = 1;

    for (unsigned i = 2; i < 50; ++i) {
        denom *= i;
        sum += 1 / denom;
    }

    std::cout << std::setprecision(std::numeric_limits<fp_type>::digits) << sum << std::endl;
    //]
}

int main() {
    t1();
    return 0;
}

