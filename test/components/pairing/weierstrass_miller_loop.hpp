/** @file
 *****************************************************************************

 Implementation of interfaces for gadgets for Miller loops.

 See weierstrass_miller_loop.hpp .

 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef CRYPTO3_BLUEPRINT_WEIERSTRASS_MILLER_LOOP_TEST_HPP
#define CRYPTO3_BLUEPRINT_WEIERSTRASS_MILLER_LOOP_TEST_HPP

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/curves/mnt6.hpp>

#include <nil/crypto3/zk/snark/components/basic_components.hpp>
#include <nil/crypto3/zk/snark/components/pairing/params/mnt4.hpp>
#include <nil/crypto3/zk/snark/components/pairing/params/mnt6.hpp>
#include <nil/crypto3/zk/snark/components/pairing/pairing_params.hpp>

#include <nil/crypto3/algebra/random_element.hpp>

using namespace nil::crypto3::zk::snark;
using namespace nil::crypto3::algebra;

template<typename ppT>
void test_mnt_miller_loop(){

    blueprint<algebra::Fr<ppT>> bp;
    other_curve<ppT>::g1_type::value_type P_val = random_element<algebra::Fr<other_curve<ppT>>>() * 
        other_curve<ppT>::g1_type::value_type::one();
    other_curve<ppT>::g2_type::value_type Q_val = random_element<algebra::Fr<other_curve<ppT>>>() * 
        other_curve<ppT>::g2_type::value_type::one();

    G1_variable<ppT> P(bp);
    G2_variable<ppT> Q(bp);

    G1_precomputation<ppT> prec_P;
    G2_precomputation<ppT> prec_Q;

    precompute_G1_gadget<ppT> compute_prec_P(bp, P, prec_P);
    precompute_G2_gadget<ppT> compute_prec_Q(bp, Q, prec_Q);

    Fqk_variable<ppT> result(bp);
    mnt_miller_loop_gadget<ppT> miller(bp, prec_P, prec_Q, result);

    PROFILE_CONSTRAINTS(bp){
        compute_prec_P.generate_r1cs_constraints();
    }
    PROFILE_CONSTRAINTS(bp){
        compute_prec_Q.generate_r1cs_constraints();
    }
    PROFILE_CONSTRAINTS(bp){
        miller.generate_r1cs_constraints();
    }
    PRINT_CONSTRAINT_PROFILING();

    P.generate_r1cs_witness(P_val);
    compute_prec_P.generate_r1cs_witness();
    Q.generate_r1cs_witness(Q_val);
    compute_prec_Q.generate_r1cs_witness();
    miller.generate_r1cs_witness();
    BOOST_CHECK(bp.is_satisfied());

    algebra::affine_ate_G1_precomp<other_curve<ppT>> native_prec_P = other_curve<ppT>::affine_ate_precompute_G1(P_val);
    algebra::affine_ate_G2_precomp<other_curve<ppT>> native_prec_Q = other_curve<ppT>::affine_ate_precompute_G2(Q_val);
    algebra::Fqk<other_curve<ppT>> native_result = other_curve<ppT>::affine_ate_miller_loop(native_prec_P, native_prec_Q);

    BOOST_CHECK(result.get_element() == native_result);
    std::cout << "number of constraints for Miller loop" << bp.num_constraints() << std::endl;
}

template<typename ppT>
void test_mnt_e_over_e_miller_loop(){

    blueprint<algebra::Fr<ppT>> bp;
    other_curve<ppT>::g1_type::value_type P1_val = random_element<algebra::Fr<other_curve<ppT>>>() * 
        other_curve<ppT>::g1_type::value_type::one();
    other_curve<ppT>::g2_type::value_type Q1_val = random_element<algebra::Fr<other_curve<ppT>>>() * 
        other_curve<ppT>::g2_type::value_type::one();

    other_curve<ppT>::g1_type::value_type P2_val = random_element<algebra::Fr<other_curve<ppT>>>() * 
        other_curve<ppT>::g1_type::value_type::one();
    other_curve<ppT>::g2_type::value_type Q2_val = random_element<algebra::Fr<other_curve<ppT>>>() * 
        other_curve<ppT>::g2_type::value_type::one();

    G1_variable<ppT> P1(bp);
    G2_variable<ppT> Q1(bp);
    G1_variable<ppT> P2(bp);
    G2_variable<ppT> Q2(bp);

    G1_precomputation<ppT> prec_P1;
    precompute_G1_gadget<ppT> compute_prec_P1(bp, P1, prec_P1);
    G1_precomputation<ppT> prec_P2;
    precompute_G1_gadget<ppT> compute_prec_P2(bp, P2, prec_P2);
    G2_precomputation<ppT> prec_Q1;
    precompute_G2_gadget<ppT> compute_prec_Q1(bp, Q1, prec_Q1);
    G2_precomputation<ppT> prec_Q2;
    precompute_G2_gadget<ppT> compute_prec_Q2(bp, Q2, prec_Q2);

    Fqk_variable<ppT> result(bp);
    mnt_e_over_e_miller_loop_gadget<ppT> miller(bp, prec_P1, prec_Q1, prec_P2, prec_Q2, result);

    PROFILE_CONSTRAINTS(bp){
        compute_prec_P1.generate_r1cs_constraints();
        compute_prec_P2.generate_r1cs_constraints();
    }
    PROFILE_CONSTRAINTS(bp){
        compute_prec_Q1.generate_r1cs_constraints();
        compute_prec_Q2.generate_r1cs_constraints();
    }
    PROFILE_CONSTRAINTS(bp){
        miller.generate_r1cs_constraints();
    }
    PRINT_CONSTRAINT_PROFILING();

    P1.generate_r1cs_witness(P1_val);
    compute_prec_P1.generate_r1cs_witness();
    Q1.generate_r1cs_witness(Q1_val);
    compute_prec_Q1.generate_r1cs_witness();
    P2.generate_r1cs_witness(P2_val);
    compute_prec_P2.generate_r1cs_witness();
    Q2.generate_r1cs_witness(Q2_val);
    compute_prec_Q2.generate_r1cs_witness();
    miller.generate_r1cs_witness();
    BOOST_CHECK(bp.is_satisfied());

    algebra::affine_ate_G1_precomp<other_curve<ppT>> native_prec_P1 = 
        other_curve<ppT>::affine_ate_precompute_G1(P1_val);
    algebra::affine_ate_G2_precomp<other_curve<ppT>> native_prec_Q1 = 
        other_curve<ppT>::affine_ate_precompute_G2(Q1_val);
    algebra::affine_ate_G1_precomp<other_curve<ppT>> native_prec_P2 = 
        other_curve<ppT>::affine_ate_precompute_G1(P2_val);
    algebra::affine_ate_G2_precomp<other_curve<ppT>> native_prec_Q2 = 
        other_curve<ppT>::affine_ate_precompute_G2(Q2_val);
    algebra::Fqk<other_curve<ppT>> native_result = 
        (other_curve<ppT>::affine_ate_miller_loop(native_prec_P1, native_prec_Q1) *
            other_curve<ppT>::affine_ate_miller_loop(native_prec_P2, native_prec_Q2).inverse());

    BOOST_CHECK(result.get_element() == native_result);
    std::cout << "number of constraints for e over e Miller loop " << bp.num_constraints() << std::endl;
}

template<typename ppT>
void test_mnt_e_times_e_over_e_miller_loop(){

    blueprint<algebra::Fr<ppT>> bp;
    other_curve<ppT>::g1_type::value_type P1_val = random_element<algebra::Fr<other_curve<ppT>>>() * 
        other_curve<ppT>::g1_type::value_type::one();
    other_curve<ppT>::g2_type::value_type Q1_val = random_element<algebra::Fr<other_curve<ppT>>>() * 
        other_curve<ppT>::g2_type::value_type::one();

    other_curve<ppT>::g1_type::value_type P2_val = random_element<algebra::Fr<other_curve<ppT>>>() * 
        other_curve<ppT>::g1_type::value_type::one();
    other_curve<ppT>::g2_type::value_type Q2_val = random_element<algebra::Fr<other_curve<ppT>>>() * 
        other_curve<ppT>::g2_type::value_type::one();

    other_curve<ppT>::g1_type::value_type P3_val = random_element<algebra::Fr<other_curve<ppT>>>() * 
        other_curve<ppT>::g1_type::value_type::one();
    other_curve<ppT>::g2_type::value_type Q3_val = random_element<algebra::Fr<other_curve<ppT>>>() * 
        other_curve<ppT>::g2_type::value_type::one();

    G1_variable<ppT> P1(bp);
    G2_variable<ppT> Q1(bp);
    G1_variable<ppT> P2(bp);
    G2_variable<ppT> Q2(bp);
    G1_variable<ppT> P3(bp);
    G2_variable<ppT> Q3(bp);

    G1_precomputation<ppT> prec_P1;
    precompute_G1_gadget<ppT> compute_prec_P1(bp, P1, prec_P1);
    G1_precomputation<ppT> prec_P2;
    precompute_G1_gadget<ppT> compute_prec_P2(bp, P2, prec_P2);
    G1_precomputation<ppT> prec_P3;
    precompute_G1_gadget<ppT> compute_prec_P3(bp, P3, prec_P3);
    G2_precomputation<ppT> prec_Q1;
    precompute_G2_gadget<ppT> compute_prec_Q1(bp, Q1, prec_Q1);
    G2_precomputation<ppT> prec_Q2;
    precompute_G2_gadget<ppT> compute_prec_Q2(bp, Q2, prec_Q2);
    G2_precomputation<ppT> prec_Q3;
    precompute_G2_gadget<ppT> compute_prec_Q3(bp, Q3, prec_Q3);

    Fqk_variable<ppT> result(bp);
    mnt_e_times_e_over_e_miller_loop_gadget<ppT> miller(bp, prec_P1, prec_Q1, 
                                                        prec_P2, prec_Q2, prec_P3, 
                                                        prec_Q3, result);

    PROFILE_CONSTRAINTS(bp){
        compute_prec_P1.generate_r1cs_constraints();
        compute_prec_P2.generate_r1cs_constraints();
        compute_prec_P3.generate_r1cs_constraints();
    }
    PROFILE_CONSTRAINTS(bp){
        compute_prec_Q1.generate_r1cs_constraints();
        compute_prec_Q2.generate_r1cs_constraints();
        compute_prec_Q3.generate_r1cs_constraints();
    }
    PROFILE_CONSTRAINTS(bp){
        miller.generate_r1cs_constraints();
    }
    PRINT_CONSTRAINT_PROFILING();

    P1.generate_r1cs_witness(P1_val);
    compute_prec_P1.generate_r1cs_witness();
    Q1.generate_r1cs_witness(Q1_val);
    compute_prec_Q1.generate_r1cs_witness();
    P2.generate_r1cs_witness(P2_val);
    compute_prec_P2.generate_r1cs_witness();
    Q2.generate_r1cs_witness(Q2_val);
    compute_prec_Q2.generate_r1cs_witness();
    P3.generate_r1cs_witness(P3_val);
    compute_prec_P3.generate_r1cs_witness();
    Q3.generate_r1cs_witness(Q3_val);
    compute_prec_Q3.generate_r1cs_witness();
    miller.generate_r1cs_witness();
    BOOST_CHECK(bp.is_satisfied());

    algebra::affine_ate_G1_precomp<other_curve<ppT>> native_prec_P1 = other_curve<ppT>::affine_ate_precompute_G1(P1_val);
    algebra::affine_ate_G2_precomp<other_curve<ppT>> native_prec_Q1 = other_curve<ppT>::affine_ate_precompute_G2(Q1_val);
    algebra::affine_ate_G1_precomp<other_curve<ppT>> native_prec_P2 = other_curve<ppT>::affine_ate_precompute_G1(P2_val);
    algebra::affine_ate_G2_precomp<other_curve<ppT>> native_prec_Q2 = other_curve<ppT>::affine_ate_precompute_G2(Q2_val);
    algebra::affine_ate_G1_precomp<other_curve<ppT>> native_prec_P3 = other_curve<ppT>::affine_ate_precompute_G1(P3_val);
    algebra::affine_ate_G2_precomp<other_curve<ppT>> native_prec_Q3 = other_curve<ppT>::affine_ate_precompute_G2(Q3_val);
    algebra::Fqk<other_curve<ppT>> native_result = (other_curve<ppT>::affine_ate_miller_loop(native_prec_P1, native_prec_Q1) *
                                            other_curve<ppT>::affine_ate_miller_loop(native_prec_P2, native_prec_Q2) *
                                            other_curve<ppT>::affine_ate_miller_loop(native_prec_P3, native_prec_Q3).inverse());

    BOOST_CHECK(result.get_element() == native_result);
    std::cout << "number of constraints for e times e over e Miller loop " << bp.num_constraints() << std::endl;
}

BOOST_AUTO_TEST_SUITE(weierstrass_miller_loop_component_test_suite)

BOOST_AUTO_TEST_CASE(weierstrass_miller_loop_component_test) {
    
    test_all_set_commitment_components<curves::mnt4<298>>();
    test_all_set_commitment_components<curves::mnt6<298>>();

}

BOOST_AUTO_TEST_SUITE_END()

#endif    // CRYPTO3_BLUEPRINT_WEIERSTRASS_MILLER_LOOP_TEST_HPP