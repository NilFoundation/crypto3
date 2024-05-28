//---------------------------------------------------------------------------//
// Copyright (c) 2024 Martun Karapetyan <martun@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE modular_fixed_multiprecision_test

// Suddenly, BOOST_MP_ASSERT is NOT constexpr, and it is used in constexpr functions throughout the boost, resulting to compilation errors on all compilers in debug mode. We need to switch assertions off inside cpp_int to make this code compile in debug mode. So we use this workaround to turn off file 'boost/multiprecision/detail/assert.hpp' which contains definition of BOOST_MP_ASSERT and BOOST_MP_ASSERT_MSG. 
#ifndef BOOST_MP_DETAIL_ASSERT_HPP
    #define BOOST_MP_DETAIL_ASSERT_HPP
    #define BOOST_MP_ASSERT(expr) ((void)0)
    #define BOOST_MP_ASSERT_MSG(expr, msg) ((void)0)
#endif

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <chrono>
#include <iostream>
#include <vector>

#include <nil/crypto3/multiprecision/cpp_int_modular.hpp>
#include <nil/crypto3/multiprecision/cpp_int_modular/literals.hpp>
#include <nil/crypto3/multiprecision/cpp_modular.hpp>

#include <nil/crypto3/multiprecision/modular/modular_adaptor.hpp>
#include <nil/crypto3/multiprecision/modular/modular_params_fixed.hpp>

#include <nil/crypto3/multiprecision/inverse.hpp>

using namespace boost::multiprecision;

using boost::multiprecision::backends::cpp_int_modular_backend;
using boost::multiprecision::backends::modular_adaptor;
using boost::multiprecision::backends::modular_params;
using boost::multiprecision::backends::modular_params_rt;


BOOST_AUTO_TEST_SUITE(runtime_tests)

// This directly calls montgomery_mul from modular_functions_fixed.hpp.
BOOST_AUTO_TEST_CASE(modular_adaptor_montgomery_mult_perf_test) {
    using Backend = cpp_int_modular_backend<256>;
    using standart_number = boost::multiprecision::number<Backend>;
    using params_safe_type = modular_params_rt<Backend>;
    using modular_backend = modular_adaptor<Backend, params_safe_type>;
    using modular_number = boost::multiprecision::number<modular_backend>;
    constexpr standart_number modulus = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f_cppui_modular256;
    constexpr standart_number x_value = 0xb5d724ce6f44c3c587867bbcb417e9eb6fa05e7e2ef029166568f14eb3161387_cppui_modular256;
    constexpr modular_number x(modular_backend(x_value.backend(), modulus.backend()));
    auto x_modular = x.backend();

    constexpr standart_number res_value = 0xad6e1fcc680392abfb075838eafa513811112f14c593e0efacb6e9d0d7770b4_cppui_modular256;
    constexpr modular_number res(modular_backend(
        res_value.backend(), modulus.backend()));
    auto res_modular = res.backend();
    std::chrono::time_point<std::chrono::high_resolution_clock> start(std::chrono::high_resolution_clock::now());

    int SAMPLES = 10000000;
    auto mod_object = x_modular.mod_data().get_mod_obj();
    auto base_data = x_modular.base_data();
    for (int i = 0; i < SAMPLES; ++i) {
        mod_object.montgomery_mul(base_data, res_modular.base_data());
    }

    std::cout << base_data << std::endl;
    auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::high_resolution_clock::now() - start);
    std::cout << "Multiplication time: " << std::fixed << std::setprecision(3)
        << std::dec << elapsed.count() / SAMPLES << " ns" << std::endl;
}

// Averge subtraction time is 37 ns.
BOOST_AUTO_TEST_CASE(modular_adaptor_backend_sub_perf_test) {
    using namespace boost::multiprecision::default_ops;

    using Backend = cpp_int_modular_backend<256>;
    using standart_number = boost::multiprecision::number<Backend>;
    using params_safe_type = modular_params_rt<Backend>;
    using modular_backend = modular_adaptor<Backend, params_safe_type>;
    using modular_number = boost::multiprecision::number<modular_backend>;
    constexpr standart_number modulus = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f_cppui_modular256;
    constexpr standart_number x_value = 0xb5d724ce6f44c3c587867bbcb417e9eb6fa05e7e2ef029166568f14eb3161387_cppui_modular256;
    constexpr modular_number x(modular_backend(x_value.backend(), modulus.backend()));
    auto x_modular = x.backend();

    constexpr standart_number res_value = 0xad6e1fcc680392abfb075838eafa513811112f14c593e0efacb6e9d0d7770b4_cppui_modular256;
    constexpr modular_number res(modular_backend(res_value.backend(), modulus.backend()));
    auto res_modular = res.backend();
    std::chrono::time_point<std::chrono::high_resolution_clock> start(std::chrono::high_resolution_clock::now());

    int SAMPLES = 10000000;
    for (int i = 0; i < SAMPLES; ++i) {
        eval_subtract(x_modular, res_modular);
    }

    std::cout << x_modular << std::endl;

    auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::high_resolution_clock::now() - start);
    std::cout << "Substraction time: " << std::fixed << std::setprecision(3)
        << std::dec << elapsed.count() / SAMPLES << " ns" << std::endl;
}

// Averge addition time is 37 ns.
BOOST_AUTO_TEST_CASE(modular_adaptor_backend_add_perf_test) {
    using namespace boost::multiprecision::default_ops;

    using Backend = cpp_int_modular_backend<256>;
    using standart_number = boost::multiprecision::number<Backend>;
    using params_safe_type = modular_params_rt<Backend>;
    using modular_backend = modular_adaptor<Backend, params_safe_type>;
    using modular_number = boost::multiprecision::number<modular_backend>;
    constexpr standart_number modulus = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f_cppui_modular256;
    constexpr standart_number x_value = 0xb5d724ce6f44c3c587867bbcb417e9eb6fa05e7e2ef029166568f14eb3161387_cppui_modular256;
    constexpr modular_number x(modular_backend(x_value.backend(), modulus.backend()));
    auto x_modular = x.backend();

    constexpr standart_number res_value = 0xad6e1fcc680392abfb075838eafa513811112f14c593e0efacb6e9d0d7770b4_cppui_modular256;
    constexpr modular_number res(modular_backend(res_value.backend(), modulus.backend()));
    auto res_modular = res.backend();
    std::chrono::time_point<std::chrono::high_resolution_clock> start(std::chrono::high_resolution_clock::now());

    int SAMPLES = 10000000;
    for (int i = 0; i < SAMPLES; ++i) {
        eval_add(x_modular, res_modular);
    }

    std::cout << x_modular << std::endl;

    auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::high_resolution_clock::now() - start);
    std::cout << "Addition time: " << std::fixed << std::setprecision(3)
        << std::dec << elapsed.count() / SAMPLES << " ns" << std::endl;
}

// Averge multiplication time is 130 ns.
BOOST_AUTO_TEST_CASE(modular_adaptor_backend_mult_perf_test) {
    using Backend = cpp_int_modular_backend<256>;
    using standart_number = boost::multiprecision::number<Backend>;
    using params_safe_type = modular_params_rt<Backend>;
    using modular_backend = modular_adaptor<Backend, params_safe_type>;
    using modular_number = boost::multiprecision::number<modular_backend>;
    constexpr standart_number modulus = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f_cppui_modular256;
    constexpr standart_number x_value = 0xb5d724ce6f44c3c587867bbcb417e9eb6fa05e7e2ef029166568f14eb3161387_cppui_modular256;
    constexpr modular_number x(modular_backend(x_value.backend(), modulus.backend()));
    auto x_modular = x.backend();

    constexpr standart_number res_value = 0xad6e1fcc680392abfb075838eafa513811112f14c593e0efacb6e9d0d7770b4_cppui_modular256;
    constexpr modular_number res(modular_backend(res_value.backend(), modulus.backend()));
    constexpr auto res_modular = res.backend();
    std::chrono::time_point<std::chrono::high_resolution_clock> start(std::chrono::high_resolution_clock::now());

    int SAMPLES = 10000000;
    for (int i = 0; i < SAMPLES; ++i) {
        eval_multiply(x_modular, res_modular);
    }

    auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::high_resolution_clock::now() - start);
    std::cout << "Multiplication time: " << std::fixed << std::setprecision(3)
        << elapsed.count() / SAMPLES << " ns" << std::endl;

    // Print something so the whole computation is not optimized out.
    std::cout << x_modular << std::endl;
}

// Averge multiplication time is 130 ns.
BOOST_AUTO_TEST_CASE(modular_adaptor_number_mult_perf_test) {
    using Backend = cpp_int_modular_backend<256>;
    using standart_number = boost::multiprecision::number<Backend>;
    using params_safe_type = modular_params_rt<Backend>;
    using modular_backend = modular_adaptor<Backend, params_safe_type>;
    using modular_number = boost::multiprecision::number<modular_backend>;
    constexpr standart_number modulus = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f_cppui_modular256;
    constexpr standart_number x_value = 0xb5d724ce6f44c3c587867bbcb417e9eb6fa05e7e2ef029166568f14eb3161387_cppui_modular256;
    modular_number x(modular_backend(x_value.backend(), modulus.backend()));

    constexpr standart_number res_value = 0xad6e1fcc680392abfb075838eafa513811112f14c593e0efacb6e9d0d7770b4_cppui_modular256;
    modular_number res(modular_backend(res_value.backend(), modulus.backend()));
    std::chrono::time_point<std::chrono::high_resolution_clock> start(std::chrono::high_resolution_clock::now());

    int SAMPLES = 10000000;
    for (int i = 0; i < SAMPLES; ++i) {
        x *= res;
    }

    auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::high_resolution_clock::now() - start);
    std::cout << "Multiplication time: " << std::fixed << std::setprecision(3)
        << elapsed.count() / SAMPLES << " ns" << std::endl;

    // Print something so the whole computation is not optimized out.
    std::cout << x << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()

