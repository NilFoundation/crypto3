//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2019 Aleksey Moskvin <zerg1996@yandex.ru>
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

#ifndef CRYPTO3_CODEC_STATE_HPP
#define CRYPTO3_CODEC_STATE_HPP

#include <boost/accumulators/framework/accumulator_set.hpp>
#include <boost/accumulators/framework/features.hpp>

#include <nil/crypto3/codec/accumulators/codec.hpp>

namespace nil {
    namespace crypto3 {
        namespace codec {
            struct nop_finalizer {
                nop_finalizer(std::size_t = 0) {
                }

                template<typename T>
                void operator()(T &) {
                }
            };

            struct nop_preprocessor {
                nop_preprocessor(std::size_t = 0) {
                }

                template<typename T>
                void operator()(T &) {
                }
            };

            /*!
             * @brief Accumulator set with codec accumulator predefined params.
             *
             * Meets the requirements of AccumulatorSet
             *
             * @ingroup codec
             *
             * @tparam ProcessingMode Codec state preprocessing mode type (e.g. isomorphic_encoding_mode<base64>)
             */
            template<typename ProcessingMode>
            using accumulator_set = boost::accumulators::accumulator_set<
                digest<ProcessingMode::output_block_bits>,
                boost::accumulators::features<accumulators::tag::codec<ProcessingMode>>, std::size_t>;
        }    // namespace codec
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_CODEC_STATE_HPP
