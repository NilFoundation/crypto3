//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#define BOOST_TEST_MODULE weierstrass_precomputation_components_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/curves/mnt6.hpp>

#include <nil/crypto3/zk/components/algebra/pairing/detail/mnt4.hpp>
#include <nil/crypto3/zk/components/algebra/pairing/detail/mnt6.hpp>

#include <nil/crypto3/zk/components/algebra/pairing/weierstrass/precomputation.hpp>

#include <nil/crypto3/algebra/random_element.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::zk;
using namespace nil::crypto3::algebra;

template<typename CurveType>
void test_element_g1_precomp() {
    components::blueprint<typename CurveType::scalar_field_type> bp;
    typename CurveType::pairing::pair_curve_type::g1_type::value_type g_val =
        algebra::random_element<typename CurveType::pairing::pair_curve_type::scalar_field_type>() *
        CurveType::pairing::pair_curve_type::g1_type::value_type::one();

    element_g1<CurveType> g(bp);
    g1_precomputation<CurveType> precomp;
    precompute_G1_component<CurveType> do_precomp(bp, g, precomp);
    do_precomp.generate_r1cs_constraints();

    g.generate_r1cs_witness(g_val);
    do_precomp.generate_r1cs_witness();
    BOOST_CHECK(bp.is_satisfied());

    typename CurveType::pairing::g1_precomp const_precomp(bp, g_val);

    typename CurveType::pairing::pair_curve_type::pairing::affine_ate_g1_precomp native_precomp =
        CurveType::pairing::pair_curve_type::affine_ate_precompute_g1(g_val);
    BOOST_CHECK(precomp.PY_twist_squared->get_element() == native_precomp.PY_twist_squared);
    BOOST_CHECK(const_precomp.PY_twist_squared->get_element() == native_precomp.PY_twist_squared);
}

template<typename CurveType>
void test_element_g2_precomp() {
    components::blueprint<typename CurveType::scalar_field_type> bp;
    typename CurveType::pairing::pair_curve_type::g2_type::value_type g_val =
        algebra::random_element<typename CurveType::pairing::pair_curve_type::scalar_field_type>() *
        CurveType::pairing::pair_curve_type::g2_type::value_type::one();

    element_g2<CurveType> g(bp);
    g2_precomputation<CurveType> precomp;
    precompute_G2_component<CurveType> do_precomp(bp, g, precomp);
    do_precomp.generate_r1cs_constraints();

    g.generate_r1cs_witness(g_val);
    do_precomp.generate_r1cs_witness();
    BOOST_CHECK(bp.is_satisfied());

    typename CurveType::pairing::pair_curve_type::pairing::affine_ate_g2_precomp native_precomp =
        CurveType::pairing::pair_curve_type::affine_ate_precompute_g2(g_val);

    BOOST_CHECK(precomp.coeffs.size() - 1 ==
                native_precomp.coeffs.size());    // the last precomp is unused, but remains for convenient programming
    for (std::size_t i = 0; i < native_precomp.coeffs.size(); ++i) {
        BOOST_CHECK(precomp.coeffs[i]->RX->get_element() == native_precomp.coeffs[i].old_RX);
        BOOST_CHECK(precomp.coeffs[i]->RY->get_element() == native_precomp.coeffs[i].old_RY);
        BOOST_CHECK(precomp.coeffs[i]->gamma->get_element() == native_precomp.coeffs[i].gamma);
        BOOST_CHECK(precomp.coeffs[i]->gamma_X->get_element() == native_precomp.coeffs[i].gamma_X);
    }

    std::cout << "number of constraints for G2 precomp: " << bp.num_constraints() << std::endl;
}

BOOST_AUTO_TEST_SUITE(weierstrass_precomputation_components_test_suite)

BOOST_AUTO_TEST_CASE(weierstrass_precomputation_components_test) {

    test_all_set_commitment_components<curves::mnt4<298>>();
    test_all_set_commitment_components<curves::mnt6<298>>();
}

BOOST_AUTO_TEST_SUITE_END()
