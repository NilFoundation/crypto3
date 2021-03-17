//  Copyright John Maddock 2012.
//  Use, modification and distribution are subject to the
//  Boost Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

//
// This tests that cpp_dec_float_50 meets our
// conceptual requirements when used with Boost.Math.
//
#ifdef _MSC_VER
#define _SCL_SECURE_NO_WARNINGS
#pragma warning(disable : 4800)
#pragma warning(disable : 4512)
#pragma warning(disable : 4127)
#pragma warning(disable : 4512)
#pragma warning(disable : 4503)    // decorated name length exceeded, name was truncated
#endif

#include <boost/container_hash/hash.hpp>
#include <libs/math/test/compile_test/poison.hpp>

#if !defined(TEST_MPF_50) && !defined(TEST_BACKEND) && !defined(TEST_MPZ) && !defined(TEST_CPP_DEC_FLOAT) && \
    !defined(TEST_MPFR_50) && !defined(TEST_MPFR_6) && !defined(TEST_MPFR_15) && !defined(TEST_MPFR_17) &&   \
    !defined(TEST_MPFR_30) && !defined(TEST_CPP_DEC_FLOAT_NO_ET) && !defined(TEST_LOGGED_ADAPTER) &&         \
    !defined(TEST_CPP_BIN_FLOAT)
#define TEST_MPF_50
#define TEST_BACKEND
#define TEST_MPZ
#define TEST_MPFR_50
#define TEST_MPFR_6
#define TEST_MPFR_15
#define TEST_MPFR_17
#define TEST_MPFR_30
#define TEST_CPP_DEC_FLOAT
#define TEST_CPP_DEC_FLOAT_NO_ET
#define TEST_LOGGED_ADAPTER
#define TEST_CPP_BIN_FLOAT

#ifdef _MSC_VER
#pragma message("CAUTION!!: No backend type specified so testing everything.... this will take some time!!")
#endif
#ifdef __GNUC__
#pragma warning "CAUTION!!: No backend type specified so testing everything.... this will take some time!!"
#endif

#endif

#if defined(TEST_MPF_50) || defined(TEST_MPZ)
#include <nil/crypto3/multiprecision/gmp.hpp>
#endif
#ifdef TEST_BACKEND
#include <nil/crypto3/multiprecision/concepts/mp_number_archetypes.hpp>
#endif
#if defined(TEST_CPP_DEC_FLOAT) || defined(TEST_CPP_DEC_FLOAT_NO_ET) || defined(TEST_LOGGED_ADAPTER)
#include <nil/crypto3/multiprecision/cpp_dec_float.hpp>
#endif
#if defined(TEST_MPFR_50) || defined(TEST_MPFR_6) || defined(TEST_MPFR_15) || defined(TEST_MPFR_17) || \
    defined(TEST_MPFR_30)
#include <nil/crypto3/multiprecision/mpfr.hpp>
#endif
#if defined(TEST_CPP_BIN_FLOAT)
#include <nil/crypto3/multiprecision/cpp_bin_float.hpp>
#endif
#ifdef TEST_LOGGED_ADAPTER
#include <nil/crypto3/multiprecision/logged_adaptor.hpp>
#endif

#include <boost/math/special_functions.hpp>

template<class T>
void test_extra(T) {
    T v1, v2, v3;
    boost::math::ibeta_inva(v1, v2, v3);
    boost::math::ibetac_inva(v1, v2, v3);
    boost::math::ibeta_invb(v1, v2, v3);
    boost::math::ibetac_invb(v1, v2, v3);
}

void foo() {
#ifdef TEST_BACKEND
    test_extra(nil::crypto3::multiprecision::concepts::mp_number_float_architype());
#endif
#ifdef TEST_MPF_50
    test_extra(nil::crypto3::multiprecision::mpf_float_50());
#endif
#ifdef TEST_MPFR_50
    test_extra(nil::crypto3::multiprecision::mpfr_float_50());
#endif
#ifdef TEST_MPFR_6
    test_extra(nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::mpfr_float_backend<6>>());
#endif
#ifdef TEST_MPFR_15
    test_extra(nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::mpfr_float_backend<15>>());
#endif
#ifdef TEST_MPFR_17
    test_extra(nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::mpfr_float_backend<17>>());
#endif
#ifdef TEST_MPFR_30
    test_extra(nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::mpfr_float_backend<30>>());
#endif
#ifdef TEST_CPP_DEC_FLOAT
    test_extra(nil::crypto3::multiprecision::cpp_dec_float_50());
#endif
#ifdef TEST_CPP_BIN_FLOAT
    test_extra(nil::crypto3::multiprecision::cpp_bin_float_50());
#endif
#ifdef TEST_CPP_DEC_FLOAT_NO_ET
    test_extra(nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::cpp_dec_float<100>,
                                                    nil::crypto3::multiprecision::et_off>());
#endif
#ifdef TEST_LOGGED_ADAPTER
    typedef nil::crypto3::multiprecision::number<
        nil::crypto3::multiprecision::logged_adaptor<nil::crypto3::multiprecision::cpp_dec_float<50>>>
        num_t;
    test_extra(num_t());
#endif
}

int main() {
    foo();
}
