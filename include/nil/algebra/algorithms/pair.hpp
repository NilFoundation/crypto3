//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ALGEBRA_PAIR_HPP
#define CRYPTO3_ALGEBRA_PAIR_HPP

#include <nil/algebra/pairing/policy.hpp>

namespace nil {
    namespace algebra {
        template<typename PairingCurveType>
        typename PairingCurveType::gt_type pair(typename PairingCurveType::g1_type &v1,
                                                typename PairingCurveType::g2_type &v2) {
            return pairing::pairing_policy<PairingCurveType>::pairing(v1, v2);
        }

        template<typename PairingCurveType>
        typename PairingCurveType::gt_type reduced_pair(typename PairingCurveType::g1_type &v1,
                                                        typename PairingCurveType::g2_type &v2) {
            return pairing::pairing_policy<PairingCurveType>::reduced_pairing(v1, v2);
        }

        template<typename PairingCurveType>
        typename PairingCurveType::gt_type final_exp(typename PairingCurveType::gt_type &elt) {
            return pairing::pairing_policy<PairingCurveType>::final_exponentiation(elt);
        }

    }    // namespace algebra
}    // namespace nil

#endif    // CRYPTO3_PAIR_HPP
