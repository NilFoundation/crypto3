//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2019-2021 Aleksei Moskvin <alalmoskvin@gmail.com>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE modular_multiprecision_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <iostream>
#include <vector>

#include <nil/crypto3/multiprecision/modular/modular_adaptor.hpp>
#include <nil/crypto3/multiprecision/modular/modular_params.hpp>

#ifdef TEST_CPP_INT
#include <nil/crypto3/multiprecision/cpp_int.hpp>
#include <nil/crypto3/multiprecision/cpp_modular.hpp>
#endif

#ifdef TEST_GMP
#include <nil/crypto3/multiprecision/gmp.hpp>
#include <nil/crypto3/multiprecision/gmp_modular.hpp>
#endif

#ifdef TEST_TOMMATH
#include <nil/crypto3/multiprecision/tommath.hpp>
#include <nil/crypto3/multiprecision/modular/modular_params_tommath.hpp>
#endif

#include "test.hpp"

using namespace nil::crypto3::multiprecision;

#ifdef TEST_CPP_INT
        using Backend = cpp_int_backend<>;
#endif

#ifdef TEST_GMP
        using Backend = gmp_int;
#endif

#ifdef TEST_TOMMATH
        using Backend = tommath_int;
#endif

static const std::string even_mod[] = {
    "8", "64", "31232", "3242343244", "32444223445648", "2342345878437578", "39083287423897423784987234876"};
static const std::string odd_mod[] = {
    "7", "23", "23133", "384828945", "938423847897893", "58976234672378752477", "345943598934088945908589591"};

static const std::string big_numbers_a = "3777078316807535813265472776245476795571913941214974396352";
static const std::string big_numbers_b = "7730650700335662967298805496078834074815880969722197781616";

static const size_t numbers_size[] = {8, 16, 20, 25, 30, 35, 40};

BOOST_AUTO_TEST_SUITE(modular_adaptor_tests)

BOOST_DATA_TEST_CASE(base_opeartions, numbers_size * (boost::unit_test::data::make(even_mod) + boost::unit_test::data::make(odd_mod)), num, exp)
{
    typedef number<modular_adaptor<Backend, backends::modular_params_rt<Backend>>> modular_number;
    typedef modular_params<Backend> params_number;
    typedef number<Backend> standart_number;

    std::string a_string = big_numbers_a.substr(0, num);
    std::string b_string = big_numbers_b.substr(0, num);
    std::string mod_string = exp;

    standart_number a_s(a_string), b_s(b_string), mod_s(mod_string), result_s(0);

    params_number mod(mod_s);
    modular_number a(a_s, mod), b(b_s, mod), result(0, mod);

    BOOST_CHECK_EQUAL(a.mod(), standart_number(mod_s));
    BOOST_CHECK_EQUAL(b.mod(), standart_number(mod_s));

    result = a + b;
    result_s = result.template convert_to<standart_number>();
    BOOST_CHECK_EQUAL(result_s, (a_s + b_s) % mod_s);

    result = a - b;
    result_s = result.template convert_to<standart_number>();
    if (a_s < b_s) {
        BOOST_CHECK_EQUAL(result_s, (a_s - b_s) % mod_s + mod_s);
    } else {
        BOOST_CHECK_EQUAL(result_s, (a_s - b_s) % mod_s);
    }

    result = a * b;
    result_s = result.template convert_to<standart_number>();
    BOOST_CHECK_EQUAL(result_s, (a_s * b_s) % mod_s);

    if ((b_s % mod_s) != 0) {
        result = a / b;
        result_s = result.template convert_to<standart_number>();
        BOOST_CHECK_EQUAL(result_s, ((a_s % mod_s) / (b_s % mod_s)));

        result = a % b;
        result_s = result.template convert_to<standart_number>();
        BOOST_CHECK_EQUAL(result_s, ((a_s % mod_s) % (b_s % mod_s)));
    }
}

BOOST_DATA_TEST_CASE(comparsion_operators, numbers_size * (boost::unit_test::data::make(even_mod) + boost::unit_test::data::make(odd_mod)), num, exp) {
    typedef number<modular_adaptor<Backend, backends::modular_params_rt<Backend>>> modular_number;
    typedef modular_params<Backend> params_number;
    typedef number<Backend> standart_number;

    std::string a_string = big_numbers_a.substr(0, num);
    std::string b_string = big_numbers_b.substr(0, num);
    std::string mod_string = exp;

    standart_number a_s(a_string), b_s(b_string), mod_s(mod_string), result_s(0);
    params_number mod(mod_s);
    modular_number a(a_s, mod), b(b_s, mod);

    BOOST_CHECK_EQUAL(a < b, (a_s % mod_s) < (b_s % mod_s));
    BOOST_CHECK_EQUAL(a <= b, (a_s % mod_s) <= (b_s % mod_s));
    BOOST_CHECK_EQUAL(a > b, (a_s % mod_s) > (b_s % mod_s));
    BOOST_CHECK_EQUAL(a >= b, (a_s % mod_s) >= (b_s % mod_s));
    BOOST_CHECK_EQUAL(a == b, (a_s % mod_s) == (b_s % mod_s));
    BOOST_CHECK_EQUAL(a != b, (a_s % mod_s) != (b_s % mod_s));
}

BOOST_DATA_TEST_CASE(bitwise_operators, numbers_size * (boost::unit_test::data::make(even_mod) + boost::unit_test::data::make(odd_mod)), num, exp) {
    typedef number<modular_adaptor<Backend, backends::modular_params_rt<Backend>>> modular_number;
    typedef modular_params<Backend> params_number;
    typedef number<Backend> standart_number;

    std::string a_string = big_numbers_a.substr(0, num);
    std::string b_string = big_numbers_b.substr(0, num);
    std::string mod_string = exp;

    standart_number a_s(a_string), b_s(b_string), mod_s(mod_string), result_s(0);
    params_number mod(mod_s);
    modular_number a(a_s, mod), b(b_s, mod), result(0, mod);

    BOOST_CHECK_EQUAL((a & b).template convert_to<standart_number>(),
                      (((a_s % mod_s) & (b_s % mod_s))) % mod_s);
    BOOST_CHECK_EQUAL((a | b).template convert_to<standart_number>(),
                      (((a_s % mod_s) | (b_s % mod_s))) % mod_s);
    BOOST_CHECK_EQUAL((a ^ b).template convert_to<standart_number>(),
                      (((a_s % mod_s) ^ (b_s % mod_s))) % mod_s);
}

BOOST_DATA_TEST_CASE(pow_test, numbers_size * (boost::unit_test::data::make(even_mod) + boost::unit_test::data::make(odd_mod)), num, exp) {
    typedef number<modular_adaptor<Backend, backends::modular_params_rt<Backend>>> modular_number;
    typedef modular_params<Backend> params_number;
    typedef number<Backend> standart_number;

    std::string a_string = big_numbers_a.substr(0, num);
    std::string b_string = big_numbers_b.substr(0, num);
    std::string mod_string = exp;

    standart_number a_s(a_string), b_s(b_string), mod_s(mod_string), result_s(0);
    params_number mod(mod_s);
    modular_number a(a_s, mod), b(b_s, mod), result(0, mod);
    BOOST_CHECK_EQUAL(pow(a, b).template convert_to<standart_number>(), powm(a_s % mod_s, b_s % mod_s, mod_s));
}

BOOST_DATA_TEST_CASE(mod_assigment, boost::unit_test::data::make(even_mod) + boost::unit_test::data::make(odd_mod), exp) {
    typedef number<modular_adaptor<Backend, backends::modular_params_rt<Backend>>> modular_number;
    typedef modular_params<Backend> params_number;
    typedef number<Backend> standart_number;

    modular_number a;
    std::string mod_string = exp;

    standart_number mod_s(mod_string);
    modular_number b(1, mod_s);
    a = b;
    BOOST_CHECK_EQUAL(a.mod(), mod_s);
}

BOOST_AUTO_TEST_SUITE_END()