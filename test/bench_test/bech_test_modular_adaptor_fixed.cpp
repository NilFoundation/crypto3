//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE modular_fixed_multiprecision_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>
#include <chrono>
#include <iostream>
#include <vector>

#include <nil/crypto3/multiprecision/number.hpp>
#include <nil/crypto3/multiprecision/modular/modular_functions_fixed.hpp>
#include <nil/crypto3/multiprecision/modular/modular_adaptor.hpp>
#include <nil/crypto3/multiprecision/modular/modular_params.hpp>
#include <nil/crypto3/multiprecision/inverse.hpp>

#include <nil/crypto3/multiprecision/cpp_int.hpp>
#include <nil/crypto3/multiprecision/cpp_int/literals.hpp>
#include <nil/crypto3/multiprecision/cpp_modular.hpp>

#include "../test.hpp"

#include <boost/type_traits/is_convertible.hpp>

using namespace nil::crypto3::multiprecision;

BOOST_AUTO_TEST_SUITE(runtime_tests)

// This directly calls montgomery_mul from modular_functions_fixed.hpp.
BOOST_AUTO_TEST_CASE(modular_adaptor_montgomery_mult_perf_test) {
    using Backend = cpp_int_backend<256, 256>;
    using standart_number = number<Backend>;
    using params_safe_type = nil::crypto3::multiprecision::backends::modular_params_rt<Backend>;
    using modular_number = number<modular_adaptor<Backend, params_safe_type>>;
    constexpr standart_number modulus = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f_cppui256;
    constexpr modular_number x(0xb5d724ce6f44c3c587867bbcb417e9eb6fa05e7e2ef029166568f14eb3161387_cppui256, modulus);
    auto x_modular = x.backend();

    constexpr modular_number res(0xad6e1fcc680392abfb075838eafa513811112f14c593e0efacb6e9d0d7770b4_cppui256, modulus);
    constexpr auto mod = x.mod();

    std::chrono::time_point<std::chrono::high_resolution_clock> start(std::chrono::high_resolution_clock::now());

    int SAMPLES = 10000000;
    auto mod_object = x_modular.mod_data().get_mod_obj();
    auto base_data = x_modular.base_data();
    for (int i = 0; i < SAMPLES; ++i) {
        mod_object.montgomery_mul(base_data, base_data);
    }

    auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::high_resolution_clock::now() - start);
    std::cout << "Multiplication time: " << std::fixed << std::setprecision(3)
        << elapsed.count() / SAMPLES << " ns" << std::endl;
}

// Averge subtraction time is 37 ns.
BOOST_AUTO_TEST_CASE(modular_adaptor_backend_sub_perf_test) {
    using Backend = cpp_int_backend<256, 256>;
    using standart_number = number<Backend>;
    using params_safe_type = nil::crypto3::multiprecision::backends::modular_params_rt<Backend>;
    using modular_number = number<modular_adaptor<Backend, params_safe_type>>;
    constexpr standart_number modulus = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f_cppui256;
    constexpr modular_number x(0xb5d724ce6f44c3c587867bbcb417e9eb6fa05e7e2ef029166568f14eb3161387_cppui256, modulus);
    auto x_modular = x.backend();

    constexpr modular_number res(0xad6e1fcc680392abfb075838eafa513811112f14c593e0efacb6e9d0d7770b4_cppui256, modulus);
    auto res_modular = res.backend();
    constexpr auto mod = x.mod();

    std::chrono::time_point<std::chrono::high_resolution_clock> start(std::chrono::high_resolution_clock::now());

    int SAMPLES = 10000000;
    for (int i = 0; i < SAMPLES; ++i) {
        eval_subtract(x_modular, res_modular);
    }

    auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::high_resolution_clock::now() - start);
    std::cout << "Substraction time: " << std::fixed << std::setprecision(3)
        << elapsed.count() / SAMPLES << " ns" << std::endl;
}

BOOST_AUTO_TEST_CASE(modular_adaptor_256_bit_number_sub_perf_test) {
    using Backend = cpp_int_backend<256, 256>;
    using standart_number = number<Backend>;

    // Average time per subtraction with this modulus is 37 ns.
    // constexpr static standart_number modulus = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f_cppui256;

    // Average time per subtraction with this modulus is 37 ns.
    constexpr static standart_number modulus = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001_cppui256;
    constexpr static nil::crypto3::multiprecision::modular_params<Backend> modular_params = modulus;

    using params_safe_type = nil::crypto3::multiprecision::backends::modular_params_ct<Backend, modular_params>;
    using modular_number = number<modular_adaptor<Backend, params_safe_type>>;
    modular_number x(0xb5d724ce6f44c3c587867bbcb417e9eb6fa05e7e2ef029166568f14eb3161387_cppui256, modulus);

    modular_number res(0xad6e1fcc680392abfb075838eafa513811112f14c593e0efacb6e9d0d7770b4_cppui256, modulus);
    auto mod = x.mod();

    std::chrono::time_point<std::chrono::high_resolution_clock> start(std::chrono::high_resolution_clock::now());

    int SAMPLES = 10000000;
    for (int i = 0; i < SAMPLES; ++i) {
        x -= res;
    }

    auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::high_resolution_clock::now() - start);
    std::cout << "Multiplication time: " << std::fixed << std::setprecision(3)
        << elapsed.count() / SAMPLES << " ns" << std::endl;
}

BOOST_AUTO_TEST_CASE(modular_adaptor_255_bit_number_sub_perf_test) {
    using Backend = cpp_int_backend<255, 255, nil::crypto3::multiprecision::unsigned_magnitude, nil::crypto3::multiprecision::unchecked, void>;
    using Backend_signed = cpp_int_backend<255, 255, nil::crypto3::multiprecision::signed_magnitude, nil::crypto3::multiprecision::unchecked, void>;
    // With this modulus average time is ~60 ns.
    // constexpr static const number<Backend> modulus = 0x4ffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f_cppui255;

    // With this modulus average time is ~94 ns
    constexpr static const number<Backend> modulus = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001_cppui255;
    constexpr static const nil::crypto3::multiprecision::modular_params<Backend_signed> modular_params = modulus;

    using params_safe_type = nil::crypto3::multiprecision::backends::modular_params_ct<Backend_signed, modular_params>;
    using modular_number = number<modular_adaptor<Backend_signed, params_safe_type>>;
    modular_number x(0x15d724ce6f44c3c587867bbcb417e9eb6fa05e7e2ef029166568f14eb3161387_cppui255, modulus);

    modular_number res(0x1d6e1fcc680392abfb075838eafa513811112f14c593e0efacb6e9d0d7770b4_cppui255, modulus);
    auto mod = x.mod();

    std::chrono::time_point<std::chrono::high_resolution_clock> start(std::chrono::high_resolution_clock::now());

    int SAMPLES = 10000000;
    for (int i = 0; i < SAMPLES; ++i) {
        res -= x;
    }

    auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::high_resolution_clock::now() - start);
    std::cout << "Subtraction time: " << std::fixed << std::setprecision(3)
        << elapsed.count() / SAMPLES << " ns" << std::endl;
}

// Averge multiplication time is 130 ns.
BOOST_AUTO_TEST_CASE(modular_adaptor_backend_mult_perf_test) {
    using Backend = cpp_int_backend<256, 256>;
    using standart_number = number<Backend>;
    using params_safe_type = nil::crypto3::multiprecision::backends::modular_params_rt<Backend>;
    using modular_number = number<modular_adaptor<Backend, params_safe_type>>;
    constexpr standart_number modulus = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f_cppui256;
    constexpr modular_number x(0xb5d724ce6f44c3c587867bbcb417e9eb6fa05e7e2ef029166568f14eb3161387_cppui256, modulus);
    auto x_modular = x.backend();

    constexpr modular_number res(0xad6e1fcc680392abfb075838eafa513811112f14c593e0efacb6e9d0d7770b4_cppui256, modulus);
    constexpr auto mod = x.mod();

    std::chrono::time_point<std::chrono::high_resolution_clock> start(std::chrono::high_resolution_clock::now());

    int SAMPLES = 10000000;
    for (int i = 0; i < SAMPLES; ++i) {
        eval_multiply(x_modular, x_modular);
    }

    auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::high_resolution_clock::now() - start);
    std::cout << "Multiplication time: " << std::fixed << std::setprecision(3)
        << elapsed.count() / SAMPLES << " ns" << std::endl;
}

// Averge multiplication time is 130 ns.
BOOST_AUTO_TEST_CASE(modular_adaptor_number_mult_perf_test) {
    using Backend = cpp_int_backend<256, 256>;
    using standart_number = number<Backend>;
    using params_safe_type = nil::crypto3::multiprecision::backends::modular_params_rt<Backend>;
    using modular_number = number<modular_adaptor<Backend, params_safe_type>>;
    constexpr standart_number modulus = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f_cppui256;
    modular_number x(0xb5d724ce6f44c3c587867bbcb417e9eb6fa05e7e2ef029166568f14eb3161387_cppui256, modulus);

    modular_number res(0xad6e1fcc680392abfb075838eafa513811112f14c593e0efacb6e9d0d7770b4_cppui256, modulus);
    auto mod = x.mod();

    std::chrono::time_point<std::chrono::high_resolution_clock> start(std::chrono::high_resolution_clock::now());

    int SAMPLES = 10000000;
    for (int i = 0; i < SAMPLES; ++i) {
        x *= x;
    }

    auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::high_resolution_clock::now() - start);
    std::cout << "Multiplication time: " << std::fixed << std::setprecision(3)
        << elapsed.count() / SAMPLES << " ns" << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()

