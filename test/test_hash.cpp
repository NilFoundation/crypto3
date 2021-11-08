// Copyright John Maddock 2015.

// Use, modification and distribution are subject to the
// Boost Software License, Version 1.0.
// (See accompanying file LICENSE_1_0.txt
// or copy at http://www.boost.org/LICENSE_1_0.txt)

#ifdef _MSC_VER
#define _SCL_SECURE_NO_WARNINGS
#endif

#include <nil/crypto3/multiprecision/cpp_int.hpp>
#include <nil/crypto3/multiprecision/cpp_bin_float.hpp>
#include <nil/crypto3/multiprecision/cpp_dec_float.hpp>
#include <nil/crypto3/multiprecision/debug_adaptor.hpp>
#include <nil/crypto3/multiprecision/logged_adaptor.hpp>

#ifdef TEST_FLOAT128
#include <nil/crypto3/multiprecision/float128.hpp>
#endif
#ifdef TEST_GMP
#include <nil/crypto3/multiprecision/gmp.hpp>
#endif
#ifdef TEST_MPFR
#include <nil/crypto3/multiprecision/mpfr.hpp>
#endif
#ifdef TEST_MPFI
#include <nil/crypto3/multiprecision/mpfi.hpp>
#endif
#ifdef TEST_TOMMATH
#include <nil/crypto3/multiprecision/tommath.hpp>
#endif

#include <boost/functional/hash.hpp>

#include "test.hpp"
#include <iostream>
#include <iomanip>

template<class T>
void test() {
    T val = 23;
    std::size_t t1 = boost::hash<T>()(val);
    BOOST_CHECK(t1);

#ifndef BOOST_NO_CXX11_HDR_FUNCTIONAL
    std::size_t t2 = std::hash<T>()(val);
    BOOST_CHECK_EQUAL(t1, t2);
#endif
    val = -23;
    std::size_t t3 = boost::hash<T>()(val);
    BOOST_CHECK_NE(t1, t3);
#ifndef BOOST_NO_CXX11_HDR_FUNCTIONAL
    t2 = std::hash<T>()(val);
    BOOST_CHECK_EQUAL(t3, t2);
#endif
}

int main() {
    test<nil::crypto3::multiprecision::cpp_int>();
    test<nil::crypto3::multiprecision::checked_int1024_t>();
    // test<nil::crypto3::multiprecision::checked_uint512_t >();
    test<nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::cpp_int_backend<
        64, 64, nil::crypto3::multiprecision::signed_magnitude, nil::crypto3::multiprecision::checked, void>>>();

    test<nil::crypto3::multiprecision::cpp_bin_float_100>();
    test<nil::crypto3::multiprecision::cpp_dec_float_100>();

    test<nil::crypto3::multiprecision::cpp_rational>();

    test<nil::crypto3::multiprecision::number<
        nil::crypto3::multiprecision::debug_adaptor<nil::crypto3::multiprecision::cpp_int::backend_type>>>();

    test<nil::crypto3::multiprecision::number<
        nil::crypto3::multiprecision::logged_adaptor<nil::crypto3::multiprecision::cpp_int::backend_type>>>();

#ifdef TEST_FLOAT128
    test<nil::crypto3::multiprecision::float128>();
#endif
#ifdef TEST_GMP
    test<nil::crypto3::multiprecision::mpz_int>();
    test<nil::crypto3::multiprecision::mpq_rational>();
    test<nil::crypto3::multiprecision::mpf_float>();
#endif

#ifdef TEST_MPFR
    test<nil::crypto3::multiprecision::mpfr_float_50>();
#endif
#ifdef TEST_MPFI
    test<nil::crypto3::multiprecision::mpfi_float_50>();
#endif

#ifdef TEST_TOMMATH
    test<nil::crypto3::multiprecision::tom_int>();
    test<nil::crypto3::multiprecision::tom_rational>();
#endif

    return boost::report_errors();
}
