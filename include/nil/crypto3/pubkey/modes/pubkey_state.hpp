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

#ifndef CRYPTO3_PUBKEY_THRESHOLD_SCHEME_STATE_HPP
#define CRYPTO3_PUBKEY_THRESHOLD_SCHEME_STATE_HPP

#include <boost/accumulators/framework/accumulator_set.hpp>
#include <boost/accumulators/framework/features.hpp>

#include <nil/crypto3/pubkey/modes/accumulators/part_verify.hpp>
#include <nil/crypto3/pubkey/modes/accumulators/sign_weighted.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename ProcessingMode>
            using part_verification_accumulator_set = boost::accumulators::accumulator_set<
                typename ProcessingMode::result_type,
                boost::accumulators::features<accumulators::tag::part_verify<ProcessingMode>>>;

            template<typename ProcessingMode>
            using weighted_signing_accumulator_set = boost::accumulators::accumulator_set<
                typename ProcessingMode::result_type,
                boost::accumulators::features<accumulators::tag::sign_weighted<ProcessingMode>>>;
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLOCK_CIPHER_STATE_HPP
