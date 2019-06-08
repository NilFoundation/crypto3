//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_CODEC_STATE_HPP
#define CRYPTO3_CODEC_STATE_HPP

#include <boost/accumulators/framework/accumulator_set.hpp>

#include <nil/crypto3/codec/accumulators/codec.hpp>

namespace nil {
    namespace crypto3 {
        namespace codec {
            struct nop_finalizer {
                nop_finalizer(std::size_t v = 0) {
                }

                template<typename T>
                void operator()(T &) {
                }
            };

            /*!
             * @brief Codec state managing container
             *
             * Meets the requirements of CodecStateContainer, CachedConceptContainer, ConceptContainer,
             * SequenceContainer, Container
             *
             * @tparam Mode Codec state preprocessing mode type (e.g. isomorphic_encoding_mode<base64>)
             */
            template<typename ProcessingMode>
            struct codec_accumulator {
                typedef boost::accumulators::accumulator_set<codec::digest<ProcessingMode::output_block_bits>,
                                                             boost::accumulators::features<
                                                                     accumulators::tag::codec<ProcessingMode>>> type;

                typedef ProcessingMode mode_type;
            };
        }
    }
} // namespace nil

#endif // CRYPTO3_CODEC_STATE_HPP