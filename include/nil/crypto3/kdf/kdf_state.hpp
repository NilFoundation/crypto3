//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_KDF_STATE_HPP
#define CRYPTO3_KDF_STATE_HPP

#include <boost/accumulators/framework/accumulator_set.hpp>
#include <boost/accumulators/framework/features.hpp>

#include <nil/crypto3/hash/accumulators/hash.hpp>
#include <nil/crypto3/kdf/accumulators/kdf.hpp>

namespace nil {
    namespace crypto3 {
        namespace kdf {
            template<typename MessageAuthenticationCode>
            using accumulator_set = boost::accumulators::accumulator_set<
                digest<MessageAuthenticationCode::input_block_bits>,
                boost::accumulators::features<accumulators::tag::hash<typename MessageAuthenticationCode::hash_type>,
                                              accumulators::tag::kdf<MessageAuthenticationCode>>>;
        }    // namespace kdf
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MAC_STATE_HPP
