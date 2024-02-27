///////////////////////////////////////////////////////////////////////////////
//  Copyright 2018 John Maddock. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

#include <nil/crypto3/multiprecision/cpp_bin_float.hpp>
#include <nil/crypto3/multiprecision/cpp_int.hpp>
#include <nil/crypto3/multiprecision/cpp_dec_float.hpp>
#include <nil/crypto3/multiprecision/cpp_complex.hpp>
#ifdef BOOST_HAS_FLOAT128
#include <nil/crypto3/multiprecision/float128.hpp>
#endif
#ifdef TEST_GMP
#include <nil/crypto3/multiprecision/gmp.hpp>
#endif
#ifdef TEST_MPFR
#include <nil/crypto3/multiprecision/mpfr.hpp>
#endif
#ifdef TEST_MPC
#include <nil/crypto3/multiprecision/mpc.hpp>
#endif

struct A {
    virtual void g() = 0;
};

void f(A&);
void f(nil::crypto3::multiprecision::cpp_bin_float_50);
void f(nil::crypto3::multiprecision::cpp_int);
void f(nil::crypto3::multiprecision::cpp_rational);
void f(nil::crypto3::multiprecision::cpp_dec_float_50);
void f(nil::crypto3::multiprecision::cpp_complex_100);
#ifdef TEST_FLOAT128
void f(nil::crypto3::multiprecision::float128);
#endif
#ifdef TEST_GMP
void f(nil::crypto3::multiprecision::mpz_int);
void f(nil::crypto3::multiprecision::mpf_float);
void f(nil::crypto3::multiprecision::mpq_rational);
#endif
#ifdef TEST_MPFR
void f(nil::crypto3::multiprecision::mpfr_float);
#endif
#ifdef TEST_MPC
void f(nil::crypto3::multiprecision::mpc_complex);
#endif

void h(A& a) {
    f(a);
}
