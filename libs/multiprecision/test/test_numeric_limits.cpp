///////////////////////////////////////////////////////////////
//  Copyright 2011 John Maddock. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at https://www.boost.org/LICENSE_1_0.txt

#ifdef _MSC_VER
#define _SCL_SECURE_NO_WARNINGS
#endif

#include "test.hpp"

#include <nil/crypto3/multiprecision/cpp_int_modular.hpp>

template<class Number>
void test_specific(const std::integral_constant<int, boost::multiprecision::number_kind_integer>&) {
    if (std::numeric_limits<Number>::is_modulo) {
        if (!std::numeric_limits<Number>::is_signed) {
            BOOST_TEST(1 + (std::numeric_limits<Number>::max)() == 0);
            BOOST_TEST(--Number(0) == (std::numeric_limits<Number>::max)());
        }
    }
}

template<class Number, class T>
void test_specific(const T&) {
}

template<class Number>
void test() {
    typedef typename std::conditional<std::numeric_limits<Number>::is_specialized,
                                      typename boost::multiprecision::number_category<Number>::type,
                                      std::integral_constant<int, 500>    // not a number type
                                      >::type fp_test_type;

    test_specific<Number>(fp_test_type());

    //
    // Note really a test just yet, but we can at least print out all the values:
    //
    std::cout << "numeric_limits values for type " << typeid(Number).name() << std::endl;

    PRINT(is_specialized);
    if (std::numeric_limits<Number>::is_integer) {
        std::cout << std::hex << std::showbase;
    }
    std::cout << "max()"
              << " = " << (std::numeric_limits<Number>::max)() << std::endl;
    if (std::numeric_limits<Number>::is_integer) {
        std::cout << std::dec;
    }
    std::cout << "max()"
              << " = " << (std::numeric_limits<Number>::max)() << std::endl;
    std::cout << "min()"
              << " = " << (std::numeric_limits<Number>::min)() << std::endl;
#ifndef BOOST_NO_CXX11_NUMERIC_LIMITS
    PRINT(lowest());
#endif
    PRINT(digits);
    PRINT(digits10);
#if !defined(BOOST_NO_CXX11_NUMERIC_LIMITS) || defined(PRINT_MAX_DIGITS10)
    PRINT(max_digits10);
#endif
    PRINT(is_signed);
    PRINT(is_integer);
    PRINT(is_exact);
    PRINT(radix);
    PRINT(epsilon());
    PRINT(round_error());
    PRINT(min_exponent);
    PRINT(min_exponent10);
    PRINT(max_exponent);
    PRINT(max_exponent10);
    PRINT(has_infinity);
    PRINT(has_quiet_NaN);
    PRINT(has_signaling_NaN);
    PRINT(has_denorm);
    PRINT(has_denorm_loss);
    PRINT(infinity());
    PRINT(quiet_NaN());
    PRINT(signaling_NaN());
    PRINT(denorm_min());
    PRINT(is_iec559);
    PRINT(is_bounded);
    PRINT(is_modulo);
    PRINT(traps);
    PRINT(tinyness_before);
    PRINT(round_style);
}

int main() {
    test<boost::multiprecision::cpp_int>();
    test<boost::multiprecision::int256_t>();
    test<boost::multiprecision::uint512_t>();
    test<boost::multiprecision::number<boost::multiprecision::cpp_int_modular_backend<
        200, 200, boost::multiprecision::unsigned_magnitude, boost::multiprecision::checked, void>>>();
    test<boost::multiprecision::number<boost::multiprecision::cpp_int_modular_backend<
        70, 70, boost::multiprecision::signed_magnitude, boost::multiprecision::unchecked, void>>>();
    return boost::report_errors();
}
