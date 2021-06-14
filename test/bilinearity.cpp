//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
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

#define BOOST_TEST_MODULE bilinearity_algebra_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/curves/edwards.hpp>
#include <nil/crypto3/algebra/curves/bn128.hpp>
#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/curves/mnt6.hpp>

using namespace nil::crypto3::algebra;

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
    GT<CurveType> ans1 = CurveType::pair_reduced(sP, Q);
    GT<CurveType> ans2 = CurveType::pair_reduced(P, sQ);
    GT<CurveType> ans3 = CurveType::pair_reduced(P, Q) ^ s;
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

    const typename CurveType::pairing::g1_precomp prec_P1 = CurveType::precompute_G1(P1);
    const typename CurveType::pairing::g1_precomp prec_P2 = CurveType::precompute_G1(P2);
    const typename CurveType::pairing::g2_precomp prec_Q1 = CurveType::precompute_G2(Q1);
    const typename CurveType::pairing::g2_precomp prec_Q2 = CurveType::precompute_G2(Q2);

    const typename CurveType::pairing::fqk_type ans_1 = CurveType::miller_loop(prec_P1, prec_Q1);
    const typename CurveType::pairing::fqk_type ans_2 = CurveType::miller_loop(prec_P2, prec_Q2);
    const typename CurveType::pairing::fqk_type ans_12 =
        CurveType::double_miller_loop(prec_P1, prec_Q1, prec_P2, prec_Q2);
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
    GT<CurveType> ans1 = CurveType::affine_pair_reduced(sP, Q);
    GT<CurveType> ans2 = CurveType::affine_pair_reduced(P, sQ);
    GT<CurveType> ans3 = CurveType::affine_pair_reduced(P, Q) ^ s;
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
