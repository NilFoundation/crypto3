//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2019 Aleksey Moskvin <zerg1996@yandex.ru>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
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
