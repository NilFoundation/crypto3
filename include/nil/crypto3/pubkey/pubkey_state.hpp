//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_PUBKEY_STATE_HPP
#define CRYPTO3_PUBKEY_STATE_HPP

#include <boost/accumulators/framework/accumulator_set.hpp>
#include <boost/accumulators/framework/features.hpp>

#include <nil/crypto3/pubkey/accumulators/pubkey.hpp>
#include <nil/crypto3/pubkey/accumulators/sign.hpp>
#include <nil/crypto3/pubkey/accumulators/verify.hpp>
#include <nil/crypto3/pubkey/accumulators/aggregate.hpp>
#include <nil/crypto3/pubkey/accumulators/aggregate_verify.hpp>
#include <nil/crypto3/pubkey/accumulators/aggregate_verify_single_msg.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename ProcessingMode>
            using pubkey_accumulator_set = boost::accumulators::accumulator_set<
                typename ProcessingMode::result_type,
                boost::accumulators::features<accumulators::tag::pubkey<ProcessingMode>>>;

            /*!
             * @brief Accumulator set with pre-defined signing accumulator params.
             *
             * Meets the requirements of AccumulatorSet
             *
             * @ingroup pubkey
             *
             * @tparam ProcessingMode a policy representing a work mode of the scheme
             */
            template<typename ProcessingMode>
            using signing_accumulator_set = boost::accumulators::accumulator_set<
                typename ProcessingMode::result_type,
                boost::accumulators::features<accumulators::tag::sign<ProcessingMode>>>;

            /*!
             * @brief Accumulator set with pre-defined verification accumulator params.
             *
             * Meets the requirements of AccumulatorSet
             *
             * @ingroup pubkey
             *
             * @tparam ProcessingMode a policy representing a work mode of the scheme
             */
            template<typename ProcessingMode>
            using verification_accumulator_set = boost::accumulators::accumulator_set<
                typename ProcessingMode::result_type,
                boost::accumulators::features<accumulators::tag::verify<ProcessingMode>>>;

            /*!
             * @brief Accumulator set with pre-defined aggregation accumulator params.
             *
             * Meets the requirements of AccumulatorSet
             *
             * @ingroup pubkey
             *
             * @tparam ProcessingMode a policy representing a work mode of the scheme
             */
            template<typename ProcessingMode>
            using aggregation_accumulator_set = boost::accumulators::accumulator_set<
                typename ProcessingMode::result_type,
                boost::accumulators::features<accumulators::tag::aggregate<ProcessingMode>>>;

            /*!
             * @brief Accumulator set with pre-defined aggregate verification accumulator params.
             *
             * Meets the requirements of AccumulatorSet
             *
             * @ingroup pubkey
             *
             * @tparam ProcessingMode a policy representing a work mode of the scheme
             */
            template<typename ProcessingMode>
            using aggregate_verification_accumulator_set = boost::accumulators::accumulator_set<
                typename ProcessingMode::result_type,
                boost::accumulators::features<accumulators::tag::aggregate_verify<ProcessingMode>>>;

            /*!
             * @brief Accumulator set with pre-defined single message aggregate verification accumulator params.
             *
             * Meets the requirements of AccumulatorSet
             *
             * @ingroup pubkey
             *
             * @tparam ProcessingMode a policy representing a work mode of the scheme
             */
            template<typename ProcessingMode>
            using single_msg_aggregate_verification_accumulator_set = boost::accumulators::accumulator_set<
                typename ProcessingMode::result_type,
                boost::accumulators::features<accumulators::tag::aggregate_verify_single_msg<ProcessingMode>>>;
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_STATE_HPP
