//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#include <iostream>

#include <nil/crypto3/algebra/pairing/bls12.hpp>

using namespace nil::crypto3::algebra::pairing;

template<typename PairingT>
void pairing_example(){
    typename PairingT::G1_type g1_el1 = PairingT::G1_type::one();
    typename PairingT::G1_precomp g1_precomp_el1 = PairingT::precompute_g1(g1_el1);
    typename PairingT::G1_type g1_el2 = PairingT::G1_type::zero();
    typename PairingT::G1_precomp g1_precomp_el2 = PairingT::precompute_g1(g1_el2);

    typename PairingT::G1_type g2_el1 = PairingT::G2_type::one();
    typename PairingT::G1_precomp g2_precomp_el1 = PairingT::precompute_g2(g2_el1);
    typename PairingT::G1_type g2_el2 = PairingT::G2_type::zero();
    typename PairingT::G1_precomp g2_precomp_el2 = PairingT::precompute_g2(g2_el2);

    typename PairingT::GT_type gt_el1 = PairingT::reduced_pairing(g1_el1, g2_el1);

    typename PairingT::GT_type gt_el2 = PairingT::pairing(g1_el1, g2_el1);

    typename PairingT::GT_type gt_el3 = PairingT::miller_loop(g1_precomp_el1, g2_precomp_el1);


    typename PairingT::GT_type gt_el4 = PairingT::double_miller_loop(g1_precomp_el1, g2_precomp_el1,
                                                                     g1_precomp_el2, g2_precomp_el2);

    typename PairingT::GT_type gt_el5 = PairingT::final_exponentiation(gt_el1);
}

int main() {
    pairing_example<pairing_policy<curves::bls12<381, CHAR_BIT>>>();
}

