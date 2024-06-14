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
#include <iomanip>
#include <fstream>
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

BOOST_AUTO_TEST_CASE(batched_test)
{
    using Backend = cpp_int_modular_backend<256>;
    using standart_number = boost::multiprecision::number<Backend>;
    using params_safe_type = modular_params_rt<Backend>;
    using modular_backend = modular_adaptor<Backend, params_safe_type>;
    using modular_number = boost::multiprecision::number<modular_backend>;

    constexpr standart_number modulus = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f_cppui_modular256;
    constexpr standart_number x_value = 0xb5d724ce6f44c3c587867bbcb417e9eb6fa05e7e2ef029166568f14eb3161387_cppui_modular256;
    modular_number x(modular_backend(x_value.backend(), modulus.backend()));
    auto x_modular = x.backend();

    constexpr standart_number res_value = 0xad6e1fcc680392abfb075838eafa513811112f14c593e0efacb6e9d0d7770b4_cppui_modular256;
    modular_number res(modular_backend(
        res_value.backend(), modulus.backend()));
    auto res_modular = res.backend();

    using duration = std::chrono::duration<double, std::nano>;

    auto run_batched_test = [](
        std::string const& test_name,
        std::size_t BATCHES,
        std::size_t samples_per_batch,
        modular_number & x1,
        modular_number & y1,
        modular_number & z1,
        modular_number const& x2,
        modular_number const& y2,
        modular_number const& z2,
        void (*opfunc)(
            modular_number & x1,
            modular_number & y1,
            modular_number & z1,
            modular_number const& x2,
            modular_number const& y2,
            modular_number const& z2
            ) )
    {
        std::vector<duration> batch_duration;
        batch_duration.resize(BATCHES);

        for(size_t b = 0; b < BATCHES; ++b) {
            if (b % (BATCHES/10) == 0) std::cerr << "Batch " << b << std::endl;
            /* warm up 
            for(size_t i = 0; i < samples_per_batch; ++i) {
                opfunc(x1,y1,z1,x2,y2,z2);
            }*/
             auto start = std::chrono::high_resolution_clock::now();
            for(size_t i = 0; i < samples_per_batch; ++i) {
                opfunc(x1,y1,z1,x2,y2,z2);
            }
            volatile auto res = x1;

            auto finish = std::chrono::high_resolution_clock::now();
            batch_duration[b] = (finish - start) * 1.0 / samples_per_batch;
        }

        /* Filter 10% outliers */
//        sort(batch_duration.begin(), batch_duration.end());
        std::size_t margin = 0; // BATCHES/20;
        auto s = batch_duration[margin];
        for(size_t b = margin+1; b < batch_duration.size()-margin; ++b) {
            s += batch_duration[b];
        }

        s /= batch_duration.size() - margin*2;
        std::cout << test_name << ": " << std::fixed << std::setprecision(3) << s.count() << std::endl;

        return batch_duration;
    };

    std::size_t BATCHES = 1000;

#define EQ_OP 1

    auto madd_res = run_batched_test(
            "madd-2007-bl",
            BATCHES, 100000,
            x, x, x, res, res, res,
            [](
                modular_number & x1,
                modular_number & y1,
                modular_number & z1,
                modular_number const& x2,
                modular_number const& y2,
                modular_number const& z2
              )
            {
                // 1M + 0S:  Z1Z1 = Z1^2
#if EQ_OP
            modular_number Z1Z1( z1 );
            Z1Z1 *= z1;
#else
            const modular_number Z1Z1( z1*z1 );
#endif
#if 0
                modular_number z01( z1 * z1);
                modular_number z02( z01*z01);
                modular_number z03( z02*z01);
                modular_number z04( z03*z01);
                modular_number z05( z04*z01);
                modular_number z06( z05*z01);
                modular_number z07( z06*z01);
                modular_number z08( z07*z01);
                modular_number z09( z08*z01);
                modular_number z10( z09*z01);
#else
#define z10 Z1Z1
#endif

                // 2M + 0S: X2*Z1Z1
#if EQ_OP
                modular_number U2 (x2);
                U2 *= Z1Z1;
#else
                modular_number U2 (x2 * Z1Z1);
#endif
                // 4M + 0S: S2 = Y2 * Z1 * Z1Z1
#if EQ_OP
                modular_number S2 ( y2 * z1);
                S2 *= z10;
#else
                modular_number S2 ( y2 * z1 * z10);
#endif
                // 4M + 1S: H = U2-X1
#if EQ_OP
                modular_number H (U2);
                H -= x1;
#else
                modular_number H (U2 - x1);
#endif
                // 5M + 1S: HH = H^2
#if EQ_OP
                modular_number HH (H);
                HH *= H;
#else
                modular_number HH ( H*H);
#endif
                // 5M + 3S: I = 4*HH
#if EQ_OP
                modular_number I (HH);
                I += HH;
                I += I;
#else
                modular_number I (HH + HH + HH + HH);
#endif

                // 6M + 3S: J = H*I
#if EQ_OP
                modular_number J (H);
                J *= I;
#else
                const modular_number J (H * I);
#endif

                // 6M + 5S: r = 2*(S2-Y1)
#if EQ_OP
                modular_number r(S2);
                r -= y1;
                r += r;
#else
                modular_number r(S2 - y1);
                r += r;
#endif

                // 7M + 5S: V = X1*I
#if EQ_OP
                modular_number V ( x1);
                V *= I;
#else
                modular_number V ( x1 * I);
#endif
                                                                    
                // 8M + 8S:   X3 = r^2-J-2*V
#if EQ_OP
                x1 = r;
                x1 *= r;
                x1 -= J;
                x1 -= V;
                x1 -= V;
#else
                x1 = r * r - J - V - V;
#endif
                // 10M + 11S: Y3 = r*(V-X3)-2*Y1*J
#if EQ_OP
                modular_number tmp (y1);
                tmp *= J;
#else
                modular_number tmp (y1*J);
#endif
#if EQ_OP
                y1 = V;
                y1 -= x1;
                y1 *= r;
                y1 -= tmp;
                y1 -= tmp;
#else
                y1 = r * (V - x1) - tmp -tmp;
#endif

                // 11M + 14S: Z3 = (Z1+H)^2-Z1Z1-HH
#if EQ_OP
                z1 += H;
                z1 *= z1;
                z1 -= Z1Z1;
                z1 -= HH;
#else
                z1 = (z1+H)*z1 - Z1Z1 - HH;
#endif
            });

    auto mul_res = run_batched_test(
            "eval_multiply",
            BATCHES, 1000000,
            x, x, x, res, res, res,
            [](
                modular_number & x1,
                modular_number & y1,
                modular_number & z1,
                modular_number const& x2,
                modular_number const& y2,
                modular_number const& z2) {
            
                x1 *= y2;
            //    eval_multiply(x1.backend(), y1.backend());
            });

    auto add_res = run_batched_test(
            "eval_add",
            BATCHES, 10000000,
            x, x, x, res, res, res,
            [](
                modular_number & x1,
                modular_number & y1,
                modular_number & z1,
                modular_number const& x2,
                modular_number const& y2,
                modular_number const& z2) {
                x1 += y2;
//                eval_add(x1.backend(), y2.backend());
            });

    auto sub_res = run_batched_test(
            "eval_subtract",
            BATCHES, 10000000,
            x, x, x, res, res, res,
            [](
                modular_number & x1,
                modular_number & y1,
                modular_number & z1,
                modular_number const& x2,
                modular_number const& y2,
                modular_number const& z2) {
                x1 -= y2;
//                eval_subtract(x1.backend(), y2.backend());
            });

/*
    auto inv_res = run_batched_test(
            "eval_inverse_mod",
            BATCHES, 1000,
            x_modular, res_modular,
           [](modular_backend &result, modular_backend const& sample) { eval_inverse_mod(result, sample); });
*/
    std::ofstream f("modular-4.log", std::ofstream::out);
    f << "add,sub,mul,madd" << std::endl;
    std::size_t prec = 4;
    for(std::size_t i = 0; i < BATCHES; ++i) {
        f
            << std::fixed << std::setprecision(prec) << add_res[i].count() << ","
            << std::fixed << std::setprecision(prec) << sub_res[i].count() << ","
//            << std::fixed << std::setprecision(prec) << mul_res[i].count() << ","
//            << std::fixed << std::setprecision(prec) << inv_res[i].count()
            << std::fixed << std::setprecision(prec) << mul_res[i].count() << ","
            << std::fixed << std::setprecision(prec) << madd_res[i].count()
            << std::endl;
    }

}




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

