// Copyright John Maddock 2015.

// Use, modification and distribution are subject to the
// Boost Software License, Version 1.0.
// (See accompanying file LICENSE_1_0.txt
// or copy at http://www.boost.org/LICENSE_1_0.txt)

#ifdef _MSC_VER
#define _SCL_SECURE_NO_WARNINGS
#endif

#include <nil/crypto3/multiprecision/cpp_int_modular.hpp>

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
    test<boost::multiprecision::cpp_int>();
    test<boost::multiprecision::checked_int1024_t>();
    test<boost::multiprecision::number<boost::multiprecision::cpp_int_modular_backend<
        64, 64, boost::multiprecision::signed_magnitude, boost::multiprecision::checked, void>>>();

    return boost::report_errors();
}
