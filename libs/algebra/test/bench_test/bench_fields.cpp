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

#define BOOST_TEST_MODULE algebra_curves_bench_test

#include <ostream>
#include <fstream>
#include <chrono>
#include <cstdint>
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
    for (int i = 0; i < 1000; ++i) {
        points1.push_back(algebra::random_element<Field>());
    }
    points2 = points1;

    typedef void (*opfunc)(value_type & result, value_type const& sample);

    auto gather_stats = [&points1](opfunc operation, size_t samples_per_batch) {
        size_t BATCHES = 1000;

        using duration = std::chrono::duration<double, std::nano>;

        std::vector<duration> batch_duration;
        batch_duration.resize(BATCHES);
        auto save = points1[3];;

        for(size_t b = 0; b < BATCHES; ++b) {
            if (b % (BATCHES/10) == 0) std::cerr << "Batch progress:" << b << std::endl;
            auto start = std::chrono::high_resolution_clock::now();
            auto result = points1[0];
            auto sample = points1[1];

            for(size_t i = 0; i < samples_per_batch; ++i) {
                operation(result, sample);
            }

            auto finish = std::chrono::high_resolution_clock::now();
            save += result;
            batch_duration[b] = (finish - start) * 1.0 / samples_per_batch;
        }

        // prevent value 'result' from optimizating out
        std::cerr << save << std::endl;

        auto s = batch_duration[0];
        for(size_t b = 1; b < batch_duration.size(); ++b) {
            s += batch_duration[b];
        }

        s /= batch_duration.size() - 2;
        std::cout << "Average: " << std::fixed << std::setprecision(3) << s.count() << std::endl;

        return batch_duration;
    };

    auto plus_results = gather_stats( [](value_type &result, value_type const& sample) { result += sample; },       1000000);
    auto mul_results = gather_stats( [](value_type &result, value_type const& sample)  { result *= sample; },        100000);
    auto sqr_results = gather_stats( [](value_type &result, value_type const& sample)  { result.square_inplace(); }, 100000);
    auto inv_results = gather_stats( [](value_type &result, value_type const& sample)  { result = sample.inversed(); }, 100);

    std::ofstream f(field_name+"-stats.log", std::ofstream::out);
    f << "# " << typeid(Field).name() << std::endl;
    f << "sum,mul,sqr,inv" << std::endl;

    for(size_t i = 0; i < plus_results.size(); ++i) {
        f
            << std::fixed << std::setprecision(3) << plus_results[i].count() << ","
            << std::fixed << std::setprecision(3) << mul_results[i].count() << ","
            << std::fixed << std::setprecision(3) << sqr_results[i].count() << ","
            << std::fixed << std::setprecision(3) << inv_results[i].count()
            << std::endl;
    }

    f.close();
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
