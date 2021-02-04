//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_CIPHER_STATE_HPP
#define CRYPTO3_PUBKEY_CIPHER_STATE_HPP

#include <boost/accumulators/framework/accumulator_set.hpp>
#include <boost/accumulators/framework/features.hpp>

#include <nil/crypto3/pubkey/accumulators/private_key.hpp>
#include <nil/crypto3/pubkey/accumulators/public_key.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            /*!
             * @brief Accumulator set with pre-defined private key accumulator params.
             *
             * Meets the requirements of AccumulatorSet
             *
             * @ingroup pubkey
             *
             * @tparam Mode Scheme processing mode type (e.g. isomorphic_signing_policy<bls, nop_padding>)
             */
            template<typename Mode>
            using private_key_accumulator_set = boost::accumulators::accumulator_set<
                typename Mode::result_type,
                boost::accumulators::features<accumulators::tag::private_key<Mode>>>;

            /*!
             * @brief Accumulator set with pre-defined public key accumulator params.
             *
             * Meets the requirements of AccumulatorSet
             *
             * @ingroup pubkey
             *
             * @tparam Mode Scheme processing mode type (e.g. isomorphic_signing_policy<bls, nop_padding>)
             */
            template<typename Mode>
            using public_key_accumulator_set = boost::accumulators::accumulator_set<
                typename Mode::result_type,
                boost::accumulators::features<accumulators::tag::public_key<Mode>>>;
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLOCK_CIPHER_STATE_HPP
