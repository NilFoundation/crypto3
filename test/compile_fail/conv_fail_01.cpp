///////////////////////////////////////////////////////////////////////////////
//  Copyright 2012 John Maddock. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

#include <nil/crypto3/multiprecision/cpp_int.hpp>

using namespace nil::crypto3::multiprecision;

void foo(cpp_int) {
}

int main() {
    foo(2.3);    // conversion from float is explicit
}
