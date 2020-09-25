//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#include <iostream>

#include <nil/crypto3/algebra/curves/bls12.hpp>

using namespace nil::crypto3::algebra::pairing;

template<typename FpCurveGroup>
void print_fp_curve_group_element(const FpCurveGroup &e) {
    std::cout << e.X.data << " " << e.Y.data << " " << e.Z.data << std::endl;
}

template<typename Fp2CurveGroup>
void print_fp2_curve_group_element(const Fp2CurveGroup &e) {
    std::cout << "(" << e.X.data[0].data << " " << e.X.data[1].data << ") (" << e.Y.data[0].data << " "
              << e.Y.data[1].data << ") (" << e.Z.data[0].data << " " << e.Z.data[1].data << ")" << std::endl;
}

template<typename Fp3CurveGroup>
void print_fp3_curve_group_element(const Fp3CurveGroup &e) {
    std::cout << "(" << e.X.data[0].data << " " << e.X.data[1].data << e.X.data[2].data << ") ("
              << e.Y.data[0].data << " " << e.Y.data[1].data << e.Y.data[2].data << ") ("
              << e.Z.data[0].data << " " << e.Z.data[1].data << e.Z.data[2].data << ")" << std::endl;
}

template<typename Fp12_2_3_2CurveGroup>
void print_fp12_2_3_2_curve_group_element(const Fp12_2_3_2CurveGroup &e) {
    std::cout << "[[[" << e.data[0].data[0].data[0].data << " , " << e.data[0].data[0].data[1].data << "],[" << e.data[0].data[1].data[0].data << " , " << e.data[0].data[1].data[1].data << "],[" << e.data[0].data[2].data[0].data << " , " << e.data[0].data[2].data[1].data << "]],[["
              << e.data[1].data[0].data[0].data << " , " << e.data[1].data[0].data[1].data << "],[" << e.data[1].data[1].data[0].data << " , " << e.data[1].data[1].data[1].data << "],[" << e.data[1].data[2].data[0].data << " , " << e.data[1].data[2].data[1].data << "]]]" << std::endl;
}

void print_fpt_curve_group_element(const typename curves::bls12<381, CHAR_BIT>::pairing_policy::GT_type &e){
    print_fp12_2_3_2_curve_group_element(e);
}

void print_ate_g1_precomp_element(const typename curves::bls12<381, CHAR_BIT>::pairing_policy::G1_precomp &e) {
    std::cout << e.PX.data << " " << e.PY.data << std::endl;
}

void print_ate_g2_precomp_element(const typename curves::bls12<381, CHAR_BIT>::pairing_policy::G2_precomp &e){
    std::cout << "\"coordinates\": [[" << e.QX.data[0].data << " , " << e.QX.data[1].data << "] , ["
              << e.QY.data[0].data << " , " << e.QY.data[1].data << "]]" << std::endl;
    auto print_coeff = [](const auto &c){
        std::cout << "\"ell_0\": [" << c.ell_0.data[0].data << "," << c.ell_0.data[1].data << "],"
                  << "\"ell_VW\": [" << c.ell_VW.data[0].data << "," << c.ell_VW.data[1].data << "],"
                  << "\"ell_VV\": [" << c.ell_VV.data[0].data << "," << c.ell_VV.data[1].data << "]";
    };
    std::cout << "coefficients: [";
    for (auto &c : e.coeffs) {
        std::cout << "{";
        print_coeff(c);
        std::cout << "},";
    }
    std::cout << "]" << std::endl;
}

template<typename PairingT>
void pairing_example(){
    using g1_value_type = typename PairingT::G1_type::underlying_field_type_value;
    using g2_value_type = typename PairingT::G2_type::underlying_field_type_value;

    g1_value_type g1_X1(123), g1_Y1(234), g1_Z1(345);

    typename PairingT::G1_type g1_el1(g1_X1, g1_Y1, g1_Z1);
    std::cout << "g1_el1: "; print_fp_curve_group_element(g1_el1);
    typename PairingT::G1_precomp g1_precomp_el1 = PairingT::precompute_g1(g1_el1);
    std::cout << "g1_precomp_el1: "; print_ate_g1_precomp_element(g1_precomp_el1);
    typename PairingT::G1_type g1_el2 = PairingT::G1_type::zero();
    std::cout << "g1_el2: "; print_fp_curve_group_element(g1_el2);
    typename PairingT::G1_precomp g1_precomp_el2 = PairingT::precompute_g1(g1_el2);
    std::cout << "g1_precomp_el2: "; print_ate_g1_precomp_element(g1_precomp_el2);

    typename PairingT::G2_type g2_el1 = PairingT::G2_type::one();
    std::cout << "g2_el1: "; print_fp2_curve_group_element(g2_el1);
    typename PairingT::G2_precomp g2_precomp_el1 = PairingT::precompute_g2(g2_el1);
    std::cout << "g2_precomp_el1: "; print_ate_g2_precomp_element(g2_precomp_el1);
    typename PairingT::G2_type g2_el2 = PairingT::G2_type::zero();
    std::cout << "g2_el2: "; print_fp2_curve_group_element(g2_el2);
    typename PairingT::G2_precomp g2_precomp_el2 = PairingT::precompute_g2(g2_el2);
    std::cout << "g2_precomp_el2: "; print_ate_g2_precomp_element(g2_precomp_el2);

    typename PairingT::GT_type gt_el1 = PairingT::reduced_pairing(g1_el1, g2_el1);
    std::cout << "gt_el1: "; print_fpt_curve_group_element(gt_el1);

    typename PairingT::GT_type gt_el2 = PairingT::pairing(g1_el1, g2_el1);
    std::cout << "gt_el2: "; print_fpt_curve_group_element(gt_el2);

    typename PairingT::GT_type gt_el3 = PairingT::miller_loop(g1_precomp_el1, g2_precomp_el1);
    std::cout << "gt_el3: "; print_fpt_curve_group_element(gt_el3);

    typename PairingT::GT_type gt_el4 = PairingT::double_miller_loop(g1_precomp_el1, g2_precomp_el1,
                                                                     g1_precomp_el2, g2_precomp_el2);
    std::cout << "gt_el4: "; print_fpt_curve_group_element(gt_el4);

    typename PairingT::GT_type gt_el5 = PairingT::final_exponentiation(gt_el1);
    std::cout << "gt_el5: "; print_fpt_curve_group_element(gt_el5);
}

int main() {
    pairing_example<curves::bls12<381, CHAR_BIT>::pairing_policy>();
}

