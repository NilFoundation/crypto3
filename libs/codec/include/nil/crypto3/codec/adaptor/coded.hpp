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
