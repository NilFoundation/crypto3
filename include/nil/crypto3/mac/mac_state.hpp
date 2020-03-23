//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_MAC_STATE_HPP
#define CRYPTO3_MAC_STATE_HPP

#include <boost/accumulators/framework/accumulator_set.hpp>
#include <boost/accumulators/framework/features.hpp>

#include <nil/crypto3/mac/accumulators/mac.hpp>

namespace nil {
    namespace crypto3 {
        namespace mac {
            template<typename MessageAuthenticationCode>
            using accumulator_set = boost::accumulators::accumulator_set<
                static_digest<MessageAuthenticationCode::input_block_bits>,
                boost::accumulators::features<accumulators::tag::mac<MessageAuthenticationCode>>>;
        }    // namespace mac
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MAC_STATE_HPP
