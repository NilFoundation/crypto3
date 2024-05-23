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

#ifndef CRYPTO3_PASSHASH_STATE_HPP
#define CRYPTO3_PASSHASH_STATE_HPP

#include <boost/accumulators/framework/accumulator_set.hpp>
#include <boost/accumulators/framework/features.hpp>

#include <nil/crypto3/passhash/accumulators/passhash.hpp>

namespace nil {
    namespace crypto3 {
        namespace passhash {
            /*!
             * @brief
             * @tparam Passhash
             * @ingroup passhash
             */
            template<typename Passhash>
            using accumulator_set = boost::accumulators::accumulator_set<
                static_digest<Passhash::input_block_bits>,
                boost::accumulators::features<accumulators::tag::passhash<Passhash>>>;
        }    // namespace passhash
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MAC_STATE_HPP
