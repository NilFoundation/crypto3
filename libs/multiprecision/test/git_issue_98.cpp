///////////////////////////////////////////////////////////////////////////////
//  Copyright 2018 John Maddock. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

#include <nil/crypto3/multiprecision/cpp_int_modular.hpp>

struct A {
    virtual void g() = 0;
};

void f(A&);
void f(boost::multiprecision::cpp_int);

void h(A& a) {
    f(a);
}
