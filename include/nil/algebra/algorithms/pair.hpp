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

namespace nil {
    namespace algebra {

        template<typename PairingCurveType>
        typename PairingCurveType::gt_type pair(typename PairingCurveType::g1_type::value_type &v1,
                                                typename PairingCurveType::g2_type::value_type &v2) {
        }
    }    // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PAIR_HPP
