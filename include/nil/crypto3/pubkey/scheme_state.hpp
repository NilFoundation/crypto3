//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_CIPHER_STATE_HPP
#define CRYPTO3_PUBKEY_CIPHER_STATE_HPP

#include <boost/accumulators/framework/accumulator_set.hpp>
#include <boost/accumulators/framework/features.hpp>

#include <nil/crypto3/pubkey/accumulators/scheme.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            /*!
             * @brief Accumulator set with pre-defined block cipher accumulator params.
             *
             * Meets the requirements of AccumulatorSet
             *
             * @ingroup block
             *
             * @tparam Mode Cipher state preprocessing mode type (e.g. isomorphic_encryption_mode<aes128>)
             * @tparam Endian
             * @tparam ValueBits
             * @tparam LengthBits
             */
            template<typename ProcessingMode>
            using accumulator_set = boost::accumulators::accumulator_set<
                digest<ProcessingMode::input_block_bits>,
                boost::accumulators::features<accumulators::tag::scheme<ProcessingMode>>>;
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLOCK_CIPHER_STATE_HPP
