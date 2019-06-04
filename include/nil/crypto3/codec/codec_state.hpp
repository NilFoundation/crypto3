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

#include <array>
#include <iterator>

#include <boost/integer.hpp>
#include <boost/static_assert.hpp>
#include <boost/utility/enable_if.hpp>

#include <boost/range/algorithm/copy.hpp>

#include <boost/accumulators/accumulators.hpp>

#include <nil/concept_container/concept_container.hpp>
#include <nil/concept_container/accumulators/bit_count.hpp>

#include <nil/crypto3/codec/detail/pack.hpp>
#include <nil/crypto3/codec/detail/digest.hpp>
#include <nil/crypto3/codec/detail/static_digest.hpp>
#include <nil/crypto3/codec/detail/type_traits.hpp>

#include <nil/crypto3/codec/algorithm/move.hpp>

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
            template<typename ProcessingMode,
                     typename SequenceContainer = digest<ProcessingMode::input_block_bits>,
                     typename CacheContainer = static_digest<ProcessingMode::input_block_bits>, template<typename>
                     class IntegralPreprocessor = ProcessingMode::encoder_type::template stream_processor<
                             ProcessingMode,
                             basic_stats_container<CacheContainer,
                                 boost::accumulators::accumulator_set<typename CacheContainer::value_type,
                                     boost::accumulators::features<
                                         accumulators::tag::bit_count
                                     >
                                 >
                             >
                      >::template type>
            class codec_state : public basic_integral_cache_sequence<
                    basic_stats_container<SequenceContainer,
                        boost::accumulators::accumulator_set<typename SequenceContainer::value_type,
                            boost::accumulators::features<
                                accumulators::tag::bit_count
                            >
                        >
                    >,
                    basic_stats_container<CacheContainer,
                        boost::accumulators::accumulator_set<typename CacheContainer::value_type,
                            boost::accumulators::features<
                                accumulators::tag::bit_count
                            >
                        >
                    >, IntegralPreprocessor> {
            public:
                typedef ProcessingMode mode_type;
            };
        }
    }
} // namespace nil

#endif // CRYPTO3_CODEC_STATE_HPP