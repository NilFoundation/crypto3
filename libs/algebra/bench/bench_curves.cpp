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

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <boost/test/execution_monitor.hpp>

#include <boost/mpl/list.hpp>

#include <iostream>

#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>
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
#include <nil/crypto3/algebra/type_traits.hpp>
#include <nil/crypto3/bench/benchmark.hpp>

using namespace nil::crypto3::algebra;
using namespace nil::crypto3::bench;

template <typename curve_type>
void benchmark_curve_operations(std::string const& curve_name)
{
    using g1_type = typename curve_type::template g1_type<>;
    using base_field = typename curve_type::base_field_type;
    using scalar_field = typename curve_type::scalar_field_type;

    run_benchmark<base_field, base_field>(
            curve_name + " Fp addition",
            [](typename base_field::value_type& A, typename base_field::value_type const& B) {
            return A += B;
            });
    run_benchmark<base_field, base_field>(
            curve_name + " Fp multiplication",
            [](typename base_field::value_type& A, typename base_field::value_type const& B) {
            return A *= B;
            });
    run_benchmark<base_field>(
            curve_name + " Fp inverse",
            [](typename base_field::value_type& A) {
            return A.inversed();
            });
    run_benchmark<scalar_field, scalar_field>(
            curve_name + " Fq addition",
            [](typename scalar_field::value_type& A, typename scalar_field::value_type const& B) {
            return A += B;
            });
    run_benchmark<scalar_field, scalar_field>(
            curve_name + " Fq multiplication",
            [](typename scalar_field::value_type& A, typename scalar_field::value_type const& B) {
            return A *= B;
            });
    run_benchmark<scalar_field>(
            curve_name + " Fq inverse",
            [](typename scalar_field::value_type& A) {
            return A.inversed();
            });
    run_benchmark<g1_type, g1_type>(
            curve_name + " G1 addition",
            [](typename g1_type::value_type& A, typename g1_type::value_type const& B) {
            return A += B;
            });
    run_benchmark<g1_type>(
            curve_name + " G1 doubling",
            [](typename g1_type::value_type& A) {
            A.double_inplace();// += A;
            return A;
            });
    run_benchmark<g1_type, scalar_field>(
            curve_name + " G1 scalar multiplication",
            [](typename g1_type::value_type& A, typename scalar_field::value_type const& B) {
            return A *= B;
            });

    if constexpr (has_template_g2_type<curve_type>::value) {
        using g2_type = typename curve_type::template g2_type<>;
        run_benchmark<g2_type, g2_type>(
                curve_name + " G2 addition",
                [](typename g2_type::value_type& A, typename g2_type::value_type const& B) {
                return A += B;
                });
        run_benchmark<g2_type>(
                curve_name + " G2 doubling",
                [](typename g2_type::value_type& A) {
                A.double_inplace();
                return A;
                //return A += A;
                });
        run_benchmark<g2_type, scalar_field>(
                curve_name + " G2 scalar multiplication",
                [](typename g2_type::value_type& A, typename scalar_field::value_type const& B) {
                return A *= B;
                });
    } else {
        std::cout << "Curve " << curve_name << " does not have G2, skipping benchmarks" << std::endl;
    }
}

BOOST_AUTO_TEST_SUITE(curves_benchmark)

BOOST_AUTO_TEST_CASE(pallas)
{
    benchmark_curve_operations<nil::crypto3::algebra::curves::pallas>("Pallas");
}

BOOST_AUTO_TEST_CASE(vesta)
{
    benchmark_curve_operations<nil::crypto3::algebra::curves::vesta>("Vesta");
}

BOOST_AUTO_TEST_CASE(bls12_381)
{
    benchmark_curve_operations<nil::crypto3::algebra::curves::bls12<381>>("BLS12-381");
}

BOOST_AUTO_TEST_CASE(mnt4_298)
{
    benchmark_curve_operations<nil::crypto3::algebra::curves::mnt4<298>>("MNT4-298");
}

BOOST_AUTO_TEST_CASE(mnt6_298)
{
    benchmark_curve_operations<nil::crypto3::algebra::curves::mnt6<298>>("MNT6-298");
}


BOOST_AUTO_TEST_SUITE_END()
