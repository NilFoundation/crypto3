//---------------------------------------------------------------------------//
// Copyright (c) 2024 Martun Karapetyan <martun@nil.foundation>
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

#include <iostream>
#include <chrono>
#include <ratio>
#include <type_traits>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <boost/multiprecision/cpp_int.hpp>

#include <nil/crypto3/algebra/curves/detail/forms/short_weierstrass/coordinates.hpp>
#include <nil/crypto3/algebra/curves/detail/forms/twisted_edwards/coordinates.hpp>
#include <nil/crypto3/algebra/curves/forms.hpp>

#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/edwards.hpp>
#include <nil/crypto3/algebra/curves/jubjub.hpp>
#include <nil/crypto3/algebra/curves/babyjubjub.hpp>
#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/curves/mnt6.hpp>
#include <nil/crypto3/algebra/curves/secp_k1.hpp>
#include <nil/crypto3/algebra/curves/secp_r1.hpp>
#include <nil/crypto3/algebra/curves/ed25519.hpp>
#include <nil/crypto3/algebra/curves/curve25519.hpp>

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/fp2.hpp>
#include <nil/crypto3/algebra/fields/fp3.hpp>

#include <nil/crypto3/algebra/random_element.hpp>

using namespace nil::crypto3::algebra;

BOOST_AUTO_TEST_SUITE(curves_manual_tests)
/**/

template<typename CurveGroup, typename AffineCurveGroup>
void curve_operations_perf_test(std::string const& curve_name) {
    using namespace nil::crypto3;
    using namespace nil::crypto3::algebra;

    typedef typename AffineCurveGroup::value_type affine_value_type;
    typedef typename CurveGroup::value_type value_type;
    typedef typename CurveGroup::curve_type::scalar_field_type::value_type scalar_type;

    using integral_type = typename CurveGroup::field_type::integral_type;

    std::vector<value_type> points1;
    std::vector<affine_value_type> points2;
    std::vector<scalar_type> constants;

    size_t SAMPLE_POINTS = 10;
    for (int i = 0; i < SAMPLE_POINTS; ++i) {
        auto p1 = algebra::random_element<CurveGroup>();
        auto p1a = p1.to_affine();

        points1.push_back(value_type::from_affine(p1a));
        points2.push_back(algebra::random_element<AffineCurveGroup>());
        constants.push_back(algebra::random_element<typename CurveGroup::curve_type::scalar_field_type>());
    }

    using duration = std::chrono::duration<double, std::nano>;

    auto run_batched_test = [](
        std::string const& test_name,
        std::size_t BATCHES,
        std::size_t samples_per_batch,
        value_type & A,
        value_type const& B,
        std::function<void (value_type & A, value_type const& B)> opfunc)
    {
        std::vector<duration> batch_duration;
        batch_duration.resize(BATCHES);

        for(size_t b = 0; b < BATCHES; ++b) {
            if (b % (BATCHES/10) == 0) std::cerr << "Batch progress:" << b << std::endl;
            auto start = std::chrono::high_resolution_clock::now();
            for(size_t i = 0; i < samples_per_batch; ++i) {
                opfunc(A, B);
            }
            volatile auto res = A;

            auto finish = std::chrono::high_resolution_clock::now();
            batch_duration[b] = (finish - start) * 1.0 / samples_per_batch;
        }

        /* To filter 10% outliers, sort results and set margin to BATCHES/20 = 5% */
        // sort(batch_duration.begin(), batch_duration.end());
        std::size_t margin = 0; // BATCHES/20;
        auto s = batch_duration[margin];
        for(size_t b = margin+1; b < batch_duration.size()-margin; ++b) {
            s += batch_duration[b];
        }

        s /= batch_duration.size() - margin*2;
        std::cout << test_name << ": " << std::fixed << std::setprecision(3) << s.count() << std::endl;

        return batch_duration;
    };

    size_t SAMPLES_PER_BATCH = 10000;
    size_t BATCHES = 1000;

    auto madd_res = run_batched_test(
            "madd",
            BATCHES, SAMPLES_PER_BATCH,
            points1[0], points1[1],
            []( value_type & A, value_type const& B) { A.mixed_add(B); } );

    auto add_res = run_batched_test(
            "add",
            BATCHES, SAMPLES_PER_BATCH,
            points1[0], points1[1],
            []( value_type & A, value_type const& B) { A += B; } );

    auto dbl_res = run_batched_test(
            "dbl",
            BATCHES, SAMPLES_PER_BATCH,
            points1[0], points1[1],
            []( value_type & A, value_type const& B) { A.double_inplace(); } );

    auto smul_res = run_batched_test(
            "smul",
            BATCHES, SAMPLES_PER_BATCH / 256,
            points1[0], points1[1],
            [&]( value_type & A, value_type const& B) { A *= constants[0]; } );

    std::ofstream f(curve_name + "-stats.log", std::ofstream::out);
    f << "# " << typeid(CurveGroup).name() << std::endl;
    f << "madd,add,dbl,smul" << std::endl;
    std::size_t prec = 4;
    for(std::size_t i = 0; i < BATCHES; ++i) {
        f
            << std::fixed << std::setprecision(prec) << madd_res[i].count() << ","
            << std::fixed << std::setprecision(prec) << add_res[i].count() << ","
            << std::fixed << std::setprecision(prec) << dbl_res[i].count() << ","
            << std::fixed << std::setprecision(prec) << smul_res[i].count()
            << std::endl;
    }
}

BOOST_AUTO_TEST_CASE(perf_test_bls12_381_g1) {
    using policy_type = nil::crypto3::algebra::curves::bls12<381>::g1_type<
        nil::crypto3::algebra::curves::coordinates::jacobian_with_a4_0,
        nil::crypto3::algebra::curves::forms::short_weierstrass>;

    using affine_policy_type = nil::crypto3::algebra::curves::bls12<381>::g1_type<nil::crypto3::algebra::curves::coordinates::affine,
                                                           nil::crypto3::algebra::curves::forms::short_weierstrass>;

    curve_operations_perf_test<policy_type, affine_policy_type>("bls12-381-j0");
}

BOOST_AUTO_TEST_CASE(perf_test_pallas) {
    using policy_type = nil::crypto3::algebra::curves::pallas::g1_type<
        nil::crypto3::algebra::curves::coordinates::jacobian_with_a4_0, 
        nil::crypto3::algebra::curves::forms::short_weierstrass>;

    using affine_policy_type = nil::crypto3::algebra::curves::pallas::g1_type<nil::crypto3::algebra::curves::coordinates::affine,
                                                           nil::crypto3::algebra::curves::forms::short_weierstrass>;

    curve_operations_perf_test<policy_type, affine_policy_type>("pallas-j0");
}

BOOST_AUTO_TEST_CASE(perf_test_mnt4) {
    using policy_type = nil::crypto3::algebra::curves::mnt4<298>::g1_type<
        nil::crypto3::algebra::curves::coordinates::projective,
        nil::crypto3::algebra::curves::forms::short_weierstrass>;

    using affine_policy_type = nil::crypto3::algebra::curves::mnt4<298>::g1_type<
        nil::crypto3::algebra::curves::coordinates::affine,
        nil::crypto3::algebra::curves::forms::short_weierstrass>;

    curve_operations_perf_test<policy_type, affine_policy_type>("mnt4-p");
}

BOOST_AUTO_TEST_CASE(perf_test_mnt6) {
    using policy_type = nil::crypto3::algebra::curves::mnt6<298>::g1_type<
        nil::crypto3::algebra::curves::coordinates::projective,
        nil::crypto3::algebra::curves::forms::short_weierstrass>;

    using affine_policy_type = nil::crypto3::algebra::curves::mnt6<298>::g1_type<
        nil::crypto3::algebra::curves::coordinates::affine,
        nil::crypto3::algebra::curves::forms::short_weierstrass>;

    curve_operations_perf_test<policy_type, affine_policy_type>("mnt6-p");
}

BOOST_AUTO_TEST_CASE(perf_test_ed25519) {
    using policy_type = nil::crypto3::algebra::curves::ed25519::g1_type<
        nil::crypto3::algebra::curves::coordinates::extended_with_a_minus_1,
        nil::crypto3::algebra::curves::forms::twisted_edwards>;

    using affine_policy_type = nil::crypto3::algebra::curves::ed25519::g1_type<
        nil::crypto3::algebra::curves::coordinates::affine,
        nil::crypto3::algebra::curves::forms::twisted_edwards>;

    curve_operations_perf_test<policy_type, affine_policy_type>("ed25519-ex-1");
}


BOOST_AUTO_TEST_SUITE_END()
