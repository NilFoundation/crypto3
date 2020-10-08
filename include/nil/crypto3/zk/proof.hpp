//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_PROOF_HPP
#define CRYPTO3_ZK_PROOF_HPP

namespace nil {
    namespace crypto3 {
        namespace zk {
            template<typename ZkScheme>
            struct proof {
                typedef ZkScheme scheme_type;

                typedef typename scheme_type::curve_type curve_type;

                constexpr static const std::size_t g1_bits = curve_type::g1_bits;
                typedef typename curve_type::g1_type g1_type;

                constexpr static const std::size_t g2_bits = curve_type::g2_bits;
                typedef typename curve_type::g2_type g2_type;
            };
        }
    }
}


