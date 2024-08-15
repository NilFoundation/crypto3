/** @file
 *****************************************************************************

 Implementation of interfaces for components for Miller loops.

 See weierstrass_miller_loop.hpp .

 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_WEIERSTRASS_MILLER_LOOP_TEST_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_WEIERSTRASS_MILLER_LOOP_TEST_HPP

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/algorithms/pair.hpp>


#include <nil/blueprint/components/algebra/curves/weierstrass/element_g1.hpp>
#include <nil/blueprint/components/algebra/curves/weierstrass/element_g2.hpp>

#include <nil/blueprint/components/algebra/pairing/weierstrass/precomputation.hpp>
#include <nil/blueprint/components/algebra/pairing/weierstrass/miller_loop.hpp>

#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/algebra/algorithms/pair.hpp>

using namespace nil::crypto3::zk;
using namespace nil::crypto3::algebra;

template<typename CurveType>
void test_mnt_miller_loop() {

    using curve_type = CurveType;
    using pair_curve_type = typename curve_type::pairing::pair_curve_type;
    using curve_pairing_policy = typename curve_type::pairing;
    using other_curve_pairing_policy = typename pair_curve_type::pairing;

    using component_policy = components::detail::basic_pairing_component_policy<CurveType>;

    blueprint<typename curve_type::scalar_field_type> bp;
    typename pair_curve_type::template g1_type<>::value_type P_val =
        random_element<typename pair_curve_type::scalar_field_type>() * pair_curve_type::template g1_type<>::value_type::one();
    typename pair_curve_type::template g2_type<>::value_type Q_val =
        random_element<typename pair_curve_type::scalar_field_type>() * pair_curve_type::template g2_type<>::value_type::one();

    components::element_g1<curve_type> P(bp);
    components::element_g2<curve_type> Q(bp);

    components::g1_precomputation<curve_type> prec_P;
    components::g2_precomputation<curve_type> prec_Q;

    components::precompute_G1_component<curve_type> compute_prec_P(bp, P, prec_P);
    components::precompute_G2_component<curve_type> compute_prec_Q(bp, Q, prec_Q);

    typename component_policy::Fqk_variable_type result(bp);
    components::mnt_miller_loop_component<curve_type> miller(bp, prec_P, prec_Q, result);

    compute_prec_P.generate_gates();

    compute_prec_Q.generate_gates();

    miller.generate_gates();

    P.generate_assignments(P_val);
    compute_prec_P.generate_assignments();
    Q.generate_assignments(Q_val);
    compute_prec_Q.generate_assignments();
    miller.generate_assignments();
    BOOST_CHECK(bp.is_satisfied());

    typename other_curve_pairing_policy::affine_ate_g1_precomp native_prec_P =
        affine_ate_precompute_g1<pair_curve_type>(P_val);
    typename other_curve_pairing_policy::affine_ate_g2_precomp native_prec_Q =
        affine_ate_precompute_g2<pair_curve_type>(Q_val);
    typename other_curve_pairing_policy::fqk_type::value_type native_result =
        affine_ate_miller_loop<pair_curve_type>(native_prec_P, native_prec_Q);

    BOOST_CHECK(result.get_element() == native_result);
    std::cout << "number of constraints for Miller loop" << bp.num_constraints() << std::endl;
}

template<typename CurveType>
void test_mnt_e_over_e_miller_loop() {

    using curve_type = CurveType;
    using pair_curve_type = typename curve_type::pairing::pair_curve_type;
    using curve_pairing_policy = typename curve_type::pairing;
    using other_curve_pairing_policy = typename pair_curve_type::pairing;

    using component_policy = components::detail::basic_pairing_component_policy<CurveType>;

    blueprint<typename curve_type::scalar_field_type> bp;
    typename pair_curve_type::template g1_type<>::value_type P1_val =
        random_element<typename pair_curve_type::scalar_field_type>() * pair_curve_type::template g1_type<>::value_type::one();
    typename pair_curve_type::template g2_type<>::value_type Q1_val =
        random_element<typename pair_curve_type::scalar_field_type>() * pair_curve_type::template g2_type<>::value_type::one();

    typename pair_curve_type::template g1_type<>::value_type P2_val =
        random_element<typename pair_curve_type::scalar_field_type>() * pair_curve_type::template g1_type<>::value_type::one();
    typename pair_curve_type::template g2_type<>::value_type Q2_val =
        random_element<typename pair_curve_type::scalar_field_type>() * pair_curve_type::template g2_type<>::value_type::one();

    components::element_g1<curve_type> P1(bp);
    components::element_g2<curve_type> Q1(bp);
    components::element_g1<curve_type> P2(bp);
    components::element_g2<curve_type> Q2(bp);

    components::g1_precomputation<curve_type> prec_P1;
    components::precompute_G1_component<curve_type> compute_prec_P1(bp, P1, prec_P1);
    components::g1_precomputation<curve_type> prec_P2;
    components::precompute_G1_component<curve_type> compute_prec_P2(bp, P2, prec_P2);
    components::g2_precomputation<curve_type> prec_Q1;
    components::precompute_G2_component<curve_type> compute_prec_Q1(bp, Q1, prec_Q1);
    components::g2_precomputation<curve_type> prec_Q2;
    components::precompute_G2_component<curve_type> compute_prec_Q2(bp, Q2, prec_Q2);

    typename component_policy::Fqk_variable_type result(bp);
    components::mnt_e_over_e_miller_loop_component<curve_type> miller(bp, prec_P1, prec_Q1, prec_P2, prec_Q2, result);

    compute_prec_P1.generate_gates();
    compute_prec_P2.generate_gates();

    compute_prec_Q1.generate_gates();
    compute_prec_Q2.generate_gates();

    miller.generate_gates();

    P1.generate_assignments(P1_val);
    compute_prec_P1.generate_assignments();
    Q1.generate_assignments(Q1_val);
    compute_prec_Q1.generate_assignments();
    P2.generate_assignments(P2_val);
    compute_prec_P2.generate_assignments();
    Q2.generate_assignments(Q2_val);
    compute_prec_Q2.generate_assignments();
    miller.generate_assignments();
    BOOST_CHECK(bp.is_satisfied());

    typename other_curve_pairing_policy::affine_ate_g1_precomp native_prec_P1 =
        affine_ate_precompute_g1<pair_curve_type>(P1_val);
    typename other_curve_pairing_policy::affine_ate_g2_precomp native_prec_Q1 =
        affine_ate_precompute_g2<pair_curve_type>(Q1_val);
    typename other_curve_pairing_policy::affine_ate_g1_precomp native_prec_P2 =
        affine_ate_precompute_g1<pair_curve_type>(P2_val);
    typename other_curve_pairing_policy::affine_ate_g2_precomp native_prec_Q2 =
        affine_ate_precompute_g2<pair_curve_type>(Q2_val);
    typename other_curve_pairing_policy::fqk_type::value_type native_result =
        (affine_ate_miller_loop<pair_curve_type>(native_prec_P1, native_prec_Q1) *
         affine_ate_miller_loop<pair_curve_type>(native_prec_P2, native_prec_Q2).inversed());

    BOOST_CHECK(result.get_element() == native_result);
    std::cout << "number of constraints for e over e Miller loop " << bp.num_constraints() << std::endl;
}

template<typename CurveType>
void test_mnt_e_times_e_over_e_miller_loop() {

    using curve_type = CurveType;
    using pair_curve_type = typename curve_type::pairing::pair_curve_type;
    using curve_pairing_policy = typename curve_type::pairing;
    using other_curve_pairing_policy = typename pair_curve_type::pairing;

    using component_policy = components::detail::basic_pairing_component_policy<CurveType>;

    blueprint<typename curve_type::scalar_field_type> bp;
    typename pair_curve_type::template g1_type<>::value_type P1_val =
        random_element<typename pair_curve_type::scalar_field_type>() * pair_curve_type::template g1_type<>::value_type::one();
    typename pair_curve_type::template g2_type<>::value_type Q1_val =
        random_element<typename pair_curve_type::scalar_field_type>() * pair_curve_type::template g2_type<>::value_type::one();

    typename pair_curve_type::template g1_type<>::value_type P2_val =
        random_element<typename pair_curve_type::scalar_field_type>() * pair_curve_type::template g1_type<>::value_type::one();
    typename pair_curve_type::template g2_type<>::value_type Q2_val =
        random_element<typename pair_curve_type::scalar_field_type>() * pair_curve_type::template g2_type<>::value_type::one();

    typename pair_curve_type::template g1_type<>::value_type P3_val =
        random_element<typename pair_curve_type::scalar_field_type>() * pair_curve_type::template g1_type<>::value_type::one();
    typename pair_curve_type::template g2_type<>::value_type Q3_val =
        random_element<typename pair_curve_type::scalar_field_type>() * pair_curve_type::template g2_type<>::value_type::one();

    components::element_g1<curve_type> P1(bp);
    components::element_g2<curve_type> Q1(bp);
    components::element_g1<curve_type> P2(bp);
    components::element_g2<curve_type> Q2(bp);
    components::element_g1<curve_type> P3(bp);
    components::element_g2<curve_type> Q3(bp);

    components::g1_precomputation<curve_type> prec_P1;
    components::precompute_G1_component<curve_type> compute_prec_P1(bp, P1, prec_P1);
    components::g1_precomputation<curve_type> prec_P2;
    components::precompute_G1_component<curve_type> compute_prec_P2(bp, P2, prec_P2);
    components::g1_precomputation<curve_type> prec_P3;
    components::precompute_G1_component<curve_type> compute_prec_P3(bp, P3, prec_P3);
    components::g2_precomputation<curve_type> prec_Q1;
    components::precompute_G2_component<curve_type> compute_prec_Q1(bp, Q1, prec_Q1);
    components::g2_precomputation<curve_type> prec_Q2;
    components::precompute_G2_component<curve_type> compute_prec_Q2(bp, Q2, prec_Q2);
    components::g2_precomputation<curve_type> prec_Q3;
    components::precompute_G2_component<curve_type> compute_prec_Q3(bp, Q3, prec_Q3);

    typename component_policy::Fqk_variable_type result(bp);
    components::mnt_e_times_e_over_e_miller_loop_component<curve_type> miller(bp, prec_P1, prec_Q1, prec_P2, prec_Q2,
                                                                              prec_P3, prec_Q3, result);

    compute_prec_P1.generate_gates();
    compute_prec_P2.generate_gates();
    compute_prec_P3.generate_gates();

    compute_prec_Q1.generate_gates();
    compute_prec_Q2.generate_gates();
    compute_prec_Q3.generate_gates();

    miller.generate_gates();

    P1.generate_assignments(P1_val);
    compute_prec_P1.generate_assignments();
    Q1.generate_assignments(Q1_val);
    compute_prec_Q1.generate_assignments();
    P2.generate_assignments(P2_val);
    compute_prec_P2.generate_assignments();
    Q2.generate_assignments(Q2_val);
    compute_prec_Q2.generate_assignments();
    P3.generate_assignments(P3_val);
    compute_prec_P3.generate_assignments();
    Q3.generate_assignments(Q3_val);
    compute_prec_Q3.generate_assignments();
    miller.generate_assignments();
    BOOST_CHECK(bp.is_satisfied());

    typename other_curve_pairing_policy::affine_ate_g1_precomp native_prec_P1 =
        affine_ate_precompute_g1<pair_curve_type>(P1_val);
    typename other_curve_pairing_policy::affine_ate_g2_precomp native_prec_Q1 =
        affine_ate_precompute_g2<pair_curve_type>(Q1_val);
    typename other_curve_pairing_policy::affine_ate_g1_precomp native_prec_P2 =
        affine_ate_precompute_g1<pair_curve_type>(P2_val);
    typename other_curve_pairing_policy::affine_ate_g2_precomp native_prec_Q2 =
        affine_ate_precompute_g2<pair_curve_type>(Q2_val);
    typename other_curve_pairing_policy::affine_ate_g1_precomp native_prec_P3 =
        affine_ate_precompute_g1<pair_curve_type>(P3_val);
    typename other_curve_pairing_policy::affine_ate_g2_precomp native_prec_Q3 =
        affine_ate_precompute_g2<pair_curve_type>(Q3_val);
    typename other_curve_pairing_policy::fqk_type::value_type native_result =
        (affine_ate_miller_loop<pair_curve_type>(native_prec_P1, native_prec_Q1) *
         affine_ate_miller_loop<pair_curve_type>(native_prec_P2, native_prec_Q2) *
         affine_ate_miller_loop<pair_curve_type>(native_prec_P3, native_prec_Q3).inversed());

    BOOST_CHECK(result.get_element() == native_result);
    std::cout << "number of constraints for e times e over e Miller loop " << bp.num_constraints() << std::endl;
}

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_WEIERSTRASS_MILLER_LOOP_TEST_HPP
