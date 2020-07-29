//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_CODED_HPP
#define CRYPTO3_CODED_HPP

#include <boost/range/concepts.hpp>
#include <boost/range/adaptor/argument_fwd.hpp>

#include <nil/crypto3/codec/codec_value.hpp>
#include <nil/crypto3/codec/codec_state.hpp>

namespace nil {
    namespace crypto3 {
        namespace codec {
            namespace detail {
                template<typename CodecAccumulator, typename SinglePassRange>
                inline detail::range_codec_impl<detail::value_codec_impl<CodecAccumulator>>
                    operator|(SinglePassRange &r, const detail::value_codec_impl<CodecAccumulator> &f) {
                    BOOST_CONCEPT_ASSERT((boost::SinglePassRangeConcept<SinglePassRange>));

                    typedef detail::value_codec_impl<CodecAccumulator> StreamCodecImpl;
                    typedef detail::range_codec_impl<StreamCodecImpl> CodecImpl;

                    return CodecImpl(r, CodecAccumulator());
                }

                template<typename CodecAccumulator, typename SinglePassRange>
                inline detail::range_codec_impl<detail::value_codec_impl<CodecAccumulator>>
                    operator|(const SinglePassRange &r, const detail::value_codec_impl<CodecAccumulator> &f) {
                    BOOST_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange>));

                    typedef detail::value_codec_impl<CodecAccumulator> StreamCodecImpl;
                    typedef detail::range_codec_impl<StreamCodecImpl> CodecImpl;

                    return CodecImpl(r, CodecAccumulator());
                }
            }    // namespace detail
        }        // namespace codec

        namespace adaptors {
            namespace {
                template<typename Codec,
                         typename CodecAccumulator = codec::accumulator_set<typename Codec::stream_encoder_type>>
                const codec::detail::value_codec_impl<CodecAccumulator>
                    encoded = codec::detail::value_codec_impl<CodecAccumulator>(CodecAccumulator());
            }
            namespace {
                template<typename Codec,
                         typename CodecAccumulator = codec::accumulator_set<typename Codec::stream_decoder_type>>
                const codec::detail::value_codec_impl<CodecAccumulator>
                    decoded = codec::detail::value_codec_impl<CodecAccumulator>(CodecAccumulator());
            }
        }    // namespace adaptors
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_CODED_HPP
