//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE bilinearity_algebra_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/algebra/curves/edwards.hpp>
#include <nil/algebra/curves/bn128.hpp>
#include <nil/algebra/curves/alt_bn128.hpp>
#include <nil/algebra/curves/mnt4.hpp>
#include <nil/algebra/curves/mnt6.hpp>

using namespace nil::algebra;

template<typename CurveType>
void pairing_test() {
    GT<CurveType> GT_one = GT<CurveType>::one();

    printf("Running bilinearity tests:\n");
    G1<CurveType> P = (Fr<CurveType>::random_element()) * G1<CurveType>::one();
    // G1<CurveType> P = Fr<CurveType>("2") * G1<CurveType>::one();
    G2<CurveType> Q = (Fr<CurveType>::random_element()) * G2<CurveType>::one();
    // G2<CurveType> Q = Fr<CurveType>("3") * G2<CurveType>::one();

    printf("P:\n");
    P.print();
    P.print_coordinates();
    printf("Q:\n");
    Q.print();
    Q.print_coordinates();
    printf("\n\n");

    Fr<CurveType> s = Fr<CurveType>::random_element();
    // Fr<CurveType> s = Fr<CurveType>("2");
    G1<CurveType> sP = s * P;
    G2<CurveType> sQ = s * Q;

    printf("Pairing bilinearity tests (three must match):\n");
    GT<CurveType> ans1 = CurveType::reduced_pairing(sP, Q);
    GT<CurveType> ans2 = CurveType::reduced_pairing(P, sQ);
    GT<CurveType> ans3 = CurveType::reduced_pairing(P, Q) ^ s;
    ans1.print();
    ans2.print();
    ans3.print();
    assert(ans1 == ans2);
    assert(ans2 == ans3);

    assert(ans1 != GT_one);
    assert((ans1 ^ Fr<CurveType>::field_char()) == GT_one);
    printf("\n\n");
}

template<typename CurveType>
void double_miller_loop_test() {
    const G1<CurveType> P1 = (Fr<CurveType>::random_element()) * G1<CurveType>::one();
    const G1<CurveType> P2 = (Fr<CurveType>::random_element()) * G1<CurveType>::one();
    const G2<CurveType> Q1 = (Fr<CurveType>::random_element()) * G2<CurveType>::one();
    const G2<CurveType> Q2 = (Fr<CurveType>::random_element()) * G2<CurveType>::one();

    const G1_precomp<CurveType> prec_P1 = CurveType::precompute_G1(P1);
    const G1_precomp<CurveType> prec_P2 = CurveType::precompute_G1(P2);
    const G2_precomp<CurveType> prec_Q1 = CurveType::precompute_G2(Q1);
    const G2_precomp<CurveType> prec_Q2 = CurveType::precompute_G2(Q2);

    const Fqk<CurveType> ans_1 = CurveType::miller_loop(prec_P1, prec_Q1);
    const Fqk<CurveType> ans_2 = CurveType::miller_loop(prec_P2, prec_Q2);
    const Fqk<CurveType> ans_12 = CurveType::double_miller_loop(prec_P1, prec_Q1, prec_P2, prec_Q2);
    assert(ans_1 * ans_2 == ans_12);
}

template<typename CurveType>
void affine_pairing_test() {
    GT<CurveType> GT_one = GT<CurveType>::one();

    printf("Running bilinearity tests:\n");
    G1<CurveType> P = (Fr<CurveType>::random_element()) * G1<CurveType>::one();
    G2<CurveType> Q = (Fr<CurveType>::random_element()) * G2<CurveType>::one();

    printf("P:\n");
    P.print();
    printf("Q:\n");
    Q.print();
    printf("\n\n");

    Fr<CurveType> s = Fr<CurveType>::random_element();
    G1<CurveType> sP = s * P;
    G2<CurveType> sQ = s * Q;

    printf("Pairing bilinearity tests (three must match):\n");
    GT<CurveType> ans1 = CurveType::affine_reduced_pairing(sP, Q);
    GT<CurveType> ans2 = CurveType::affine_reduced_pairing(P, sQ);
    GT<CurveType> ans3 = CurveType::affine_reduced_pairing(P, Q) ^ s;
    ans1.print();
    ans2.print();
    ans3.print();
    assert(ans1 == ans2);
    assert(ans2 == ans3);

    assert(ans1 != GT_one);
    assert((ans1 ^ Fr<CurveType>::field_char()) == GT_one);
    printf("\n\n");
}

int main(void) {
    pairing_test<edwards_pp>();
    double_miller_loop_test<edwards_pp>();

    pairing_test<mnt6_pp>();
    double_miller_loop_test<mnt6_pp>();
    affine_pairing_test<mnt6_pp>();

    pairing_test<mnt4_pp>();
    double_miller_loop_test<mnt4_pp>();
    affine_pairing_test<mnt4_pp>();

    pairing_test<alt_bn128_pp>();
    double_miller_loop_test<alt_bn128_pp>();

    pairing_test<bn128_pp>();
    double_miller_loop_test<bn128_pp>();
}
