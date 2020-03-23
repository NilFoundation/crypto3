//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------///

#ifndef CRYPTO3_CBC_MAC_STATE_HPP
#define CRYPTO3_CBC_MAC_STATE_HPP

namespace nil {
    namespace crypto3 {
        namespace mac {
            template<typename BlockCipher>
            struct cbc_mac;

            template<typename MessageAuthenticationCode>
            using mac_accumulator;

            template<typename BlockCipher>
            using mac_accumulator<cbc_mac<BlockCipher>> = boost::accumulators::accumulator_set<
                mac::digest<MessageAuthenticationCode::input_block_bits>,
                boost::accumulators::features<accumulators::tag::mac<MessageAuthenticationCode>>>;
        }    // namespace mac
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_CBC_MAC_STATE_HPP
