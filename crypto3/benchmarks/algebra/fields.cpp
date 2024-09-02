//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020-2021 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2024 Vasiliy Olekhov <vasiliy.olekhov@nil.foundation>
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

#define BOOST_TEST_MODULE algebra_fields_bench_test

#include <ostream>
#include <fstream>
#include <chrono>
#include <string>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <nil/crypto3/algebra/fields/pallas/base_field.hpp>
#include <nil/crypto3/algebra/fields/pallas/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/mnt4/base_field.hpp>
#include <nil/crypto3/algebra/fields/mnt4/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/mnt6/base_field.hpp>
#include <nil/crypto3/algebra/fields/mnt6/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/secp/secp_k1/base_field.hpp>
#include <nil/crypto3/algebra/fields/secp/secp_k1/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/secp/secp_r1/base_field.hpp>
#include <nil/crypto3/algebra/fields/secp/secp_r1/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/curve25519/base_field.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

using namespace nil::crypto3::algebra;

BOOST_AUTO_TEST_SUITE(fields_manual_tests)

template<class Field>
void run_perf_test(std::string const& field_name) {
    using namespace nil::crypto3;
    using namespace nil::crypto3::algebra;
    using namespace nil::crypto3::algebra::fields;

    typedef typename Field::value_type value_type;
    std::vector<value_type> points1;
    std::vector<value_type> points2;

    // size of arrays is 4 times larger than typical L1 data cache
    size_t SAMPLES_COUNT = 4*32*1024/sizeof(value_type);

    for (int i = 0; i < SAMPLES_COUNT; ++i) {
        points1.push_back(algebra::random_element<Field>());
        points2.push_back(algebra::random_element<Field>());
    }

    auto gather_stats = [&points1, &points2]
        (std::function<void(std::vector<value_type> & result, std::vector<value_type> const& samples, std::size_t sample)> operation,
        size_t samples_per_batch, const std::string& operation_name) {
            size_t BATCHES = 1000;

            using duration = std::chrono::duration<double, std::nano>;

            std::vector<duration> batch_duration;
            batch_duration.resize(BATCHES);
            auto save = points1[3];;

            for(size_t b = 0; b < BATCHES; ++b) {
                // if (b % (BATCHES/10) == 0) std::cerr << "Batch progress:" << b << std::endl;
                auto start = std::chrono::high_resolution_clock::now();
                auto points_index = 0;

                for(size_t i = 0; i < samples_per_batch; ++i) {
                    operation(points1, points2, i);
                    ++points_index;
                    if (points_index == 1000)
                        points_index = 0;
                }

                auto finish = std::chrono::high_resolution_clock::now();
                batch_duration[b] = (finish - start) * 1.0 / samples_per_batch;
            }

            // prevent value 'result' from optimizating out
            std::cerr << save << std::endl;

            auto s = batch_duration[0];
            for(size_t b = 1; b < batch_duration.size(); ++b) {
                s += batch_duration[b];
            }

            s /= batch_duration.size() - 2;
            std::cout << "Average time for operator " << operation_name << ": " << std::fixed << std::setprecision(3) << s.count() << std::endl;

            return batch_duration;
        };


    for(int mult = 1; mult <= 100; ++mult) {
        int MULTIPLICATOR = mult;
        std::cout << "MULT: " << MULTIPLICATOR << std::endl;

    auto plus_results = gather_stats(
        [&](std::vector<value_type> &result, std::vector<value_type> const& samples, std::size_t sample)
        {
            for(int m = 0; m < MULTIPLICATOR; m++)
                result[sample*(sample+m) % SAMPLES_COUNT] += samples[sample*(sample+m)*17 % SAMPLES_COUNT];
        }, 10000 / MULTIPLICATOR, "Addition");

    auto mul_results = gather_stats(
        [&](std::vector<value_type> &result, std::vector<value_type> const& samples, std::size_t sample)
        {
            for(int m = 0; m < MULTIPLICATOR; m++)
                result[sample*(sample+m) % SAMPLES_COUNT] *= samples[sample*(sample+m)*17 % SAMPLES_COUNT];
        }, 1000 / MULTIPLICATOR, "Multiplication");

    auto minus_results = gather_stats(
        [&](std::vector<value_type> &result, std::vector<value_type> const& samples, std::size_t sample)
        {
            for(int m = 0; m < MULTIPLICATOR; m++)
                result[sample*(sample+m) % SAMPLES_COUNT] -= samples[sample*(sample+m)*17 % SAMPLES_COUNT];
        }, 10000 / MULTIPLICATOR, "Subtraction");

    auto sqr_results = gather_stats(
        [&](std::vector<value_type> &result, std::vector<value_type> const& samples, std::size_t sample)
        {
            for(int m = 0; m < MULTIPLICATOR; m++)
                result[sample*(sample+m) % SAMPLES_COUNT].square_inplace();
        }, 1000 / MULTIPLICATOR, "Square In-Place");

    auto inv_results = gather_stats(
        [&](std::vector<value_type> &result, std::vector<value_type> const& samples, std::size_t sample)
        {
            for(int m = 0; m < MULTIPLICATOR; m++)
                result[sample*(sample+m) % SAMPLES_COUNT] = samples[sample*(sample+m)*17 % SAMPLES_COUNT].inversed();
        }, 100 / MULTIPLICATOR, "Inverse");
    char filename[200]= {0};
    sprintf(filename,"%s-stats-%03d.csv", field_name.c_str(), MULTIPLICATOR);

    std::ofstream f(filename, std::ofstream::out);
    f << "# " << typeid(Field).name() << std::endl;
    f << "sum,mul,sub,sqr,inv" << std::endl;

    for(size_t i = 0; i < plus_results.size(); ++i) {
        f << std::fixed << std::setprecision(3) << plus_results[i].count()  << ","
          << std::fixed << std::setprecision(3) << mul_results[i].count()   << ","
          << std::fixed << std::setprecision(3) << minus_results[i].count() << ","
          << std::fixed << std::setprecision(3) << sqr_results[i].count()   << ","
          << std::fixed << std::setprecision(3) << inv_results[i].count()
          << std::endl;
    }

    f.close();
    }
}

BOOST_AUTO_TEST_CASE(field_operation_perf_test_pallas) {
    run_perf_test<nil::crypto3::algebra::fields::pallas_base_field>("pallas");
}

BOOST_AUTO_TEST_CASE(field_operation_perf_test_mnt) {
    run_perf_test<nil::crypto3::algebra::fields::mnt4_base_field<298>>("mnt4_298");
    run_perf_test<nil::crypto3::algebra::fields::mnt6_base_field<298>>("mnt6_298");
}

BOOST_AUTO_TEST_CASE(field_operation_perf_test_ed25519) {
    run_perf_test<nil::crypto3::algebra::fields::ed25519>("ed25519");
}


BOOST_AUTO_TEST_CASE(field_operation_perf_test_bls12_381_base) {
    run_perf_test<nil::crypto3::algebra::fields::bls12_base_field<381u>>("bls12_381");
}

BOOST_AUTO_TEST_CASE(field_operation_perf_test_bls12_381_scalar) {
    run_perf_test<nil::crypto3::algebra::fields::bls12_scalar_field<381u>>("bls12_381_scalar");
}

BOOST_AUTO_TEST_SUITE_END()
