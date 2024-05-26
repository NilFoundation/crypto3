//---------------------------------------------------------------------------//
// Copyright (c) 2024 Iosif (x-mass) <x-mass@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE polynomial_dfs_benchmark_test

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <iostream>
#include <map>
#include <numeric>
#include <string>
#include <vector>

#include <boost/accumulators/accumulators.hpp>
#include <boost/accumulators/statistics.hpp>
#include <boost/accumulators/statistics/stats.hpp>
#include <boost/accumulators/statistics/extended_p_square_quantile.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/test/unit_test.hpp>
#include <boost/timer/progress_display.hpp>
#include <boost/timer/timer.hpp>

#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/math/polynomial/polynomial_dfs.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>


// Benchmark test cases integrated to Boost.Test framework, check the examples below
struct test_case_base {
    using MeanQuantileAccumulatorSet = boost::accumulators::accumulator_set<
        double,
        boost::accumulators::features<
            boost::accumulators::tag::mean,
            boost::accumulators::tag::extended_p_square_quantile
        >
    >;

    std::map<std::string, boost::timer::cpu_timer> timers;
    std::map<std::string, MeanQuantileAccumulatorSet> accumulators;
    std::vector<double> probs = {0.5, 0.9, 0.95, 0.99};

    void run_benchmark_iterations(
        int num_iterations,
        std::function<void()> benchmark_impl
    ) {
        boost::timer::progress_display progress_bar(num_iterations);
        for (int i = 0; i < num_iterations; ++i) {
            benchmark_impl();
            for (const auto& [flag, timer] : timers) {
                auto acc = accumulators.emplace(
                    std::piecewise_construct,
                    std::forward_as_tuple(flag),
                    std::forward_as_tuple(boost::accumulators::extended_p_square_probabilities = probs)
                );
                acc.first->second(timer.elapsed().wall * 1.0e-9);
            }
            timers.clear();
            ++progress_bar;
        }
    }

    void report_results() {
        using namespace boost::accumulators;
        for (const auto& acc : accumulators) {
            std::cout << "Results for " << acc.first << ":\n"
                << " Mean time: " << std::fixed << std::setprecision(3) << mean(acc.second) << " seconds\n"
                << " Percentiles:\n" << std::fixed;
            for (auto prob : probs) {
                std::cout << "  " << std::setprecision(0) << prob * 100 << "th: "
                    << std::setprecision(3) << quantile(acc.second, quantile_probability = prob) << " seconds\n";
            }
            std::cout << "\n";
        }
    }
};

#define BENCHMARK_FIXTURE_TEST_CASE(test_case_name, num_iterations, fixture) \
    struct test_case_name : public fixture, test_case_base {                 \
        void test_method();                                                  \
    };                                                                       \
    static void BOOST_AUTO_TC_INVOKER( test_case_name )()                    \
    {                                                                        \
        test_case_name t;                                                    \
        t.run_benchmark_iterations(                                          \
            num_iterations, [&]() { t.test_method(); });                     \
        t.report_results();                                                  \
    }                                                                        \
    struct BOOST_AUTO_TC_UNIQUE_ID( test_case_name ) {};                     \
    BOOST_AUTO_TU_REGISTRAR(test_case_name)(                                 \
        boost::unit_test::make_test_case(                                    \
            &BOOST_AUTO_TC_INVOKER( test_case_name ),                        \
            #test_case_name, __FILE__, __LINE__),                            \
        boost::unit_test::decorator::collector_t::instance()                 \
    );                                                                       \
    void test_case_name::test_method()

#define BENCHMARK_AUTO_TEST_CASE(test_case_name, num_iterations) \
    BENCHMARK_FIXTURE_TEST_CASE(test_case_name, num_iterations, BOOST_AUTO_TEST_CASE_FIXTURE)

#define START_TIMER(flag) timers[flag].resume();

#define STOP_TIMER(flag) timers[flag].stop();


using namespace nil::crypto3::math;

template <typename Field>
polynomial_dfs<typename Field::value_type> generate_random_polynomial(std::size_t size, nil::crypto3::random::algebraic_engine<Field>& engine) {
    std::vector<typename Field::value_type> random_field_values;
    random_field_values.reserve(size);
    for (std::size_t i = 0; i < size; ++i) {
        random_field_values.emplace_back(engine());
    }
    return polynomial_dfs<typename Field::value_type>(size - 1, std::move(random_field_values));
}

struct F {
    using FieldType = nil::crypto3::algebra::fields::bls12_fr<381>;
    const std::size_t SEED = 1337;
    F() : alg_rnd_engine(SEED), rnd_engine(SEED) {}
    nil::crypto3::random::algebraic_engine<FieldType> alg_rnd_engine;
    std::mt19937 rnd_engine;
};

BOOST_FIXTURE_TEST_SUITE(polynomial_dfs_benchmark_test_suite, F)

BENCHMARK_AUTO_TEST_CASE(dummy_test, 100) {
    std::size_t tmp = 1;
    START_TIMER("dummy")
    for (std::size_t i = 1; i < 10000000; ++i) tmp *= i;
    STOP_TIMER("dummy")
}

BENCHMARK_AUTO_TEST_CASE(polynomial_product_test, 20) {
    using Field = nil::crypto3::algebra::fields::bls12_fr<381>;

    std::vector<polynomial_dfs<typename Field::value_type>> random_polynomials;
    random_polynomials.reserve(8);
    Field::value_type a = alg_rnd_engine();
    std::vector<std::size_t> sizes = {23, 15, 21, 16, 22, 17, 18};
    for (auto size : sizes) {
        random_polynomials.emplace_back(
            generate_random_polynomial<Field>(
                1u << size,
                alg_rnd_engine
            )
        );
    }

    START_TIMER("polynomial_product")
    polynomial_product<Field>(std::move(random_polynomials));
    STOP_TIMER("polynomial_product")
}

BENCHMARK_AUTO_TEST_CASE(polynomial_sum_real_test, 20) {
    using Field = nil::crypto3::algebra::fields::bls12_fr<381>;

    std::vector<polynomial_dfs<typename Field::value_type>> random_polynomials;
    random_polynomials.reserve(8);
    Field::value_type a = alg_rnd_engine();
    std::vector<std::size_t> sizes = {23, 15, 21, 16, 22, 17, 18};
    for (auto size : sizes) {
        random_polynomials.emplace_back(
            generate_random_polynomial<Field>(
                1u << size,
                alg_rnd_engine
            )
        );
    }
    auto random_polynomials_copy = random_polynomials;

    START_TIMER("polynomial_naive")
    std::size_t max_size = 0;
    for (const auto& polynomial : random_polynomials_copy) {
        max_size = std::max(max_size, polynomial.size());
    }
    auto max_domain = make_evaluation_domain<FieldType>(max_size);
    for (auto& polynomial : random_polynomials_copy) {
        polynomial.resize(max_size, nullptr, max_domain);
    }
    polynomial_dfs<typename Field::value_type> naive_res(0, max_size);
    for (auto& polynomial : random_polynomials_copy) {
        naive_res += std::move(polynomial);
    }
    STOP_TIMER("polynomial_naive")

    START_TIMER("polynomial_sum")
    const auto res = polynomial_sum<Field>(std::move(random_polynomials));
    STOP_TIMER("polynomial_sum")
    BOOST_CHECK_EQUAL(naive_res, res);
}

BOOST_AUTO_TEST_SUITE_END()
