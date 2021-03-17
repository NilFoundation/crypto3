// Copyright John Maddock 2011.

// Use, modification and distribution are subject to the
// Boost Software License, Version 1.0.
// (See accompanying file LICENSE_1_0.txt
// or copy at http://www.boost.org/LICENSE_1_0.txt)

#ifdef _MSC_VER
#define _SCL_SECURE_NO_WARNINGS
#endif

#if !defined(TEST_MPQ) && !defined(TEST_TOMMATH) && !defined(TEST_CPP_INT)
#define TEST_MPQ
#define TEST_TOMMATH
#define TEST_CPP_INT

#ifdef _MSC_VER
#pragma message("CAUTION!!: No backend type specified so testing everything.... this will take some time!!")
#endif
#ifdef __GNUC__
#pragma warning "CAUTION!!: No backend type specified so testing everything.... this will take some time!!"
#endif

#endif

#if defined(TEST_MPQ)
#include <nil/crypto3/multiprecision/gmp.hpp>
#endif
#if defined(TEST_TOMMATH)
#include <nil/crypto3/multiprecision/tommath.hpp>
#endif
#ifdef TEST_CPP_INT
#include <nil/crypto3/multiprecision/cpp_int.hpp>
#endif

#include <boost/algorithm/string/case_conv.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int.hpp>
#include <nil/crypto3/multiprecision/rational_adaptor.hpp>
#include "test.hpp"
#include <iostream>
#include <iomanip>

template<class T>
T generate_random() {
    typedef typename nil::crypto3::multiprecision::component_type<T>::type int_type;
    static boost::random::uniform_int_distribution<unsigned> ui(0, 20);
    static boost::random::mt19937 gen;
    int_type val = int_type(gen());
    unsigned lim = ui(gen);
    for (unsigned i = 0; i < lim; ++i) {
        val *= (gen.max)();
        val += gen();
    }
    int_type denom = int_type(gen());
    lim = ui(gen);
    for (unsigned i = 0; i < lim; ++i) {
        denom *= (gen.max)();
        denom += gen();
    }
    return T(val, denom);
}

template<class T>
void do_round_trip(const T& val, std::ios_base::fmtflags f, const boost::mpl::true_&) {
    std::stringstream ss;
#ifndef BOOST_NO_CXX11_NUMERIC_LIMITS
    ss << std::setprecision(std::numeric_limits<T>::max_digits10);
#else
    ss << std::setprecision(std::numeric_limits<T>::digits10 + 5);
#endif
    ss.flags(f);
    ss << val;
    T new_val = static_cast<T>(ss.str());
    BOOST_CHECK_EQUAL(new_val, val);
    new_val = static_cast<T>(val.str(0, f));
    BOOST_CHECK_EQUAL(new_val, val);
}

template<class T>
void do_round_trip(const T& val, std::ios_base::fmtflags f, const boost::mpl::false_&) {
    std::stringstream ss;
    ss << std::setprecision(std::numeric_limits<T>::digits10 + 4);
    ss.flags(f);
    ss << val;
    T new_val;
    ss >> new_val;
    BOOST_CHECK_EQUAL(new_val, val);
}

template<class T>
struct is_number : public boost::mpl::false_ { };
template<class T>
struct is_number<nil::crypto3::multiprecision::number<T>> : public boost::mpl::true_ { };

template<class T>
void do_round_trip(const T& val, std::ios_base::fmtflags f) {
    do_round_trip(val, f, is_number<T>());
}

template<class T>
void do_round_trip(const T& val) {
    do_round_trip(val, std::ios_base::fmtflags(0));
    if (val >= 0) {
        do_round_trip(val, std::ios_base::fmtflags(std::ios_base::showbase | std::ios_base::hex));
        do_round_trip(val, std::ios_base::fmtflags(std::ios_base::showbase | std::ios_base::oct));
    }
}

template<class T>
void test_round_trip() {
    for (unsigned i = 0; i < 1000; ++i) {
        T val = generate_random<T>();
        do_round_trip(val);
        do_round_trip(T(-val));
    }
}

int main() {
#ifdef TEST_MPQ
    test_round_trip<nil::crypto3::multiprecision::mpq_rational>();
    test_round_trip<boost::rational<nil::crypto3::multiprecision::mpz_int>>();
    test_round_trip<nil::crypto3::multiprecision::number<
        nil::crypto3::multiprecision::rational_adaptor<nil::crypto3::multiprecision::gmp_int>>>();
#endif
#ifdef TEST_TOMMATH
    test_round_trip<boost::rational<nil::crypto3::multiprecision::tom_int>>();
    test_round_trip<nil::crypto3::multiprecision::tom_rational>();
#endif
#ifdef TEST_CPP_INT
    test_round_trip<boost::rational<nil::crypto3::multiprecision::cpp_int>>();
    test_round_trip<nil::crypto3::multiprecision::cpp_rational>();
#endif
    return boost::report_errors();
}
