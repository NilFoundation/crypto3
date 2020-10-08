//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_VERIFICATION_KEY_HPP
#define CRYPTO3_ZK_VERIFICATION_KEY_HPP

namespace nil {
    namespace crypto3 {
        namespace zk {
            template<typename ZkScheme>
            struct verification_key {
                typedef ZkScheme scheme_type;

                typedef typename scheme_type::curve_type curve_type;
            };
        }
    }
}

