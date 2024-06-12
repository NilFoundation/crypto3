//---------------------------------------------------------------------------//
// Copyright (c) 2024 Martun Karapetyan <martun@nil.foundation>
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
void curve_mixed_add_perf_test() {
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

    points1.push_back( value_type( {
        integral_type("134259237214329583859572659902079218325987377002085142995452804377364522466038358476049939515655792490847794794525"),
        integral_type("1809534154292907788172682460748792788554180452365596942941215464028404682438291049442742832837471944151906865833554")
                }));

    points1.push_back( value_type( {
        integral_type("2607267007883347124342512866089200338971754315737412002026691972321782832942488267664625960949017951416919909922006"),
        integral_type("3981354946063234465291394610773776476896996022527754048687201420910953491368502231624587677046665607818103081900111")
                }));

    points1.push_back( value_type( {
        integral_type("2768531198125823394096395795073120709798104974725544690117020537032512543084168194909941520331104556839346036427726"),
        integral_type("1754758978115289139414189505104210117716683061164960084683469377165597159992957437833991574831425252027886109201264")
                }));

    /*
    for (int i = 0; i < SAMPLE_POINTS; ++i) {
        points1.push_back(algebra::random_element<CurveGroup>());
        points2.push_back(algebra::random_element<AffineCurveGroup>());
        constants.push_back(algebra::random_element<typename CurveGroup::curve_type::scalar_field_type>());
    }
    */

    size_t SAMPLES_PER_BATCH = 100;
    size_t BATCHES = 100;
    using duration = std::chrono::duration<double, std::nano>;

    std::vector<duration> batch_duration;
    batch_duration.resize(BATCHES);


//    std::chrono::time_point<std::chrono::high_resolution_clock> start, finish;

    auto result = points1[0];

    for(std::size_t b = 0; b < BATCHES ; ++b) {

        auto start = std::chrono::high_resolution_clock::now();
        
        for (int i = 0; i < SAMPLES_PER_BATCH; ++i) {
            int index = i % points1.size();
            result.mixed_add(points1[index]);
        }

        auto finish = std::chrono::high_resolution_clock::now();

        batch_duration[b] = (finish - start) / SAMPLES_PER_BATCH;
    }

    duration min_dur, max_dur, avg_dur;
    min_dur = max_dur = avg_dur = batch_duration[0];
    for(std::size_t b = 1; b < BATCHES ; ++b) {
        avg_dur += batch_duration[b];
        if (batch_duration[b] > max_dur) {
            max_dur = batch_duration[b];
        }
        if (batch_duration[b] < min_dur) {
            min_dur = batch_duration[b];
        }
    }
    avg_dur /= BATCHES;
    std::cout << "Mixed Addition time: "
        << min_dur.count() << " ns (min) "
        << avg_dur.count() << " ns (avg) "
        << max_dur.count() << " ns (max)" << std::endl;
}

#if 0
template<typename CurveGroup>
void curve_operations_perf_test() {
    using namespace nil::crypto3;
    using namespace nil::crypto3::algebra;

    typedef typename CurveGroup::value_type value_type;
    typedef typename CurveGroup::curve_type::scalar_field_type::value_type scalar_type;

    std::vector<value_type> points1;
    std::vector<value_type> points2;
    std::vector<scalar_type> constants;

    for (int i = 0; i < 1000; ++i) {
        points1.push_back(algebra::random_element<CurveGroup>());
        constants.push_back(algebra::random_element<typename CurveGroup::curve_type::scalar_field_type>());
    }
    points2 = points1;

    std::chrono::time_point<std::chrono::high_resolution_clock> start(std::chrono::high_resolution_clock::now());

    size_t SAMPLES = 10000;
    for (int i = 0; i < SAMPLES; ++i) {
        int index = i % points1.size();
        points2[index] *= constants[index];
    }
    auto elapsed =
        std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "Scalar Multiplication time: " << std::fixed << std::setprecision(3) << elapsed.count() / SAMPLES
              << " ns" << std::endl;

    start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < SAMPLES; ++i) {
        int index = i % points1.size();
        points2[index] += points1[index];
    }
    elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "Addition time: " << std::fixed << std::setprecision(3) << elapsed.count() / SAMPLES << " ns"
              << std::endl;

    start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < SAMPLES; ++i) {
        int index = i % points1.size();
        points2[index] -= points1[index];
    }

    elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "Substraction time: " << std::fixed << std::setprecision(3) << elapsed.count() / SAMPLES << " ns"
              << std::endl;
}
#endif

#if 0
BOOST_AUTO_TEST_CASE(curve_operations_perf_test_bls12_381_g1_jacobian) {
    using policy_type = curves::bls12<381>::g1_type<nil::crypto3::algebra::curves::coordinates::jacobian_with_a4_0,
                                                    nil::crypto3::algebra::curves::forms::short_weierstrass>;

    curve_operations_perf_test<policy_type>();
}

BOOST_AUTO_TEST_CASE(curve_operations_perf_test_bls12_381_g2_jacobian) {
    using policy_type = curves::bls12<381>::g2_type<nil::crypto3::algebra::curves::coordinates::jacobian_with_a4_0,
                                                    nil::crypto3::algebra::curves::forms::short_weierstrass>;

    curve_operations_perf_test<policy_type>();
}

BOOST_AUTO_TEST_CASE(curve_operations_perf_test_bls12_381_g1_projective) {
    using policy_type = curves::bls12<381>::g1_type<nil::crypto3::algebra::curves::coordinates::projective,
                                                    nil::crypto3::algebra::curves::forms::short_weierstrass>;

    curve_operations_perf_test<policy_type>();
}
#endif

// Performance for mixed addition.
BOOST_AUTO_TEST_CASE(mixed_addition_perf_test_bls12_381_g1) {
    using policy_type = curves::bls12<381>::g1_type<
        nil::crypto3::algebra::curves::coordinates::jacobian_with_a4_0, 
        nil::crypto3::algebra::curves::forms::short_weierstrass>;

    using affine_policy_type = curves::bls12<381>::g1_type<nil::crypto3::algebra::curves::coordinates::affine,
                                                           nil::crypto3::algebra::curves::forms::short_weierstrass>;

    curve_mixed_add_perf_test<policy_type, affine_policy_type>();
}

BOOST_AUTO_TEST_SUITE_END()
