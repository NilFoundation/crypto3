//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLOCK_CIPHER_STATE_HPP
#define CRYPTO3_BLOCK_CIPHER_STATE_HPP

#include <boost/accumulators/framework/accumulator_set.hpp>
#include <boost/accumulators/framework/features.hpp>

#include <nil/crypto3/block/accumulators/block.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            /*!
             * @brief Accumulator set with pre-defined block cipher accumulator params.
             *
             * Meets the requirements of AccumulatorSet
             *
             * @addtogroup block
             *
             * @tparam Mode Cipher state preprocessing mode type (e.g. isomorphic_encryption_mode<aes128>)
             * @tparam Endian
             * @tparam ValueBits
             * @tparam LengthBits
             */
            template<typename ProcessingMode>
            using accumulator_set = boost::accumulators::accumulator_set<
                digest<ProcessingMode::input_block_bits>,
                boost::accumulators::features<accumulators::tag::block<ProcessingMode>>>;
        }    // namespace block
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLOCK_CIPHER_STATE_HPP
