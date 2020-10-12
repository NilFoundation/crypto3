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

#ifndef CRYPTO3_ENCODE_HPP
#define CRYPTO3_ENCODE_HPP

#include <nil/crypto3/codec/algorithm/codec.hpp>

#include <nil/crypto3/codec/codec_value.hpp>
#include <nil/crypto3/codec/codec_state.hpp>

#include <nil/crypto3/detail/type_traits.hpp>

namespace nil {
    namespace crypto3 {
        /*!
         * @brief Encodes the elements with particular codec defined with Encoder
         * in the range, defined by [first, last), and inserts the result to
         * another range beginning at out.
         *
         * @ingroup codec_algorithms
         *
         * @tparam Encoder Must meet the requirements of Codec which determines the
         * particular algorithm to be used with range given.
         * @tparam InputIterator Must meet the requirements of InputIterator.
         * @tparam OutputIterator Must meet the requirements of OutputIterator.
         *
         * @param first Iterator defines the beginning of the range to be encoded.
         * @param last Iterator defines the end of the range to be encoded.
         * @param out Iterator defines the beginning of the destination range.
         *
         * @return Output iterator to the element in the destination range, one past the last element inserted.
         */
        template<typename Encoder, typename InputIterator, typename OutputIterator>
        typename std::enable_if<detail::is_iterator<OutputIterator>::value, OutputIterator>::type
            encode(InputIterator first, InputIterator last, OutputIterator out) {

            typedef typename Encoder::stream_encoder_type EncodingMode;
            typedef typename codec::accumulator_set<EncodingMode> CodecAccumulator;

            typedef codec::detail::value_codec_impl<CodecAccumulator> EncoderStateImpl;
            typedef codec::detail::itr_codec_impl<EncoderStateImpl, OutputIterator> EncoderImpl;

            return EncoderImpl(first, last, std::move(out), CodecAccumulator());
        }

        /*!
         * @brief Encodes the elements with particular codec defined with Encoder
         * in the range, defined by [first, last) and returns the result with any
         * type convertible to the type satisfying SequenceContainer with the value
         * type satisfying Integral concept requirements.
         *
         * @ingroup codec_algorithms
         *
         * @tparam Encoder Must meet the requirements of Codec which determines the
         * particular algorithm to be used with range given.
         * @tparam InputIterator Must meet the requirements of InputIterator.
         * @tparam CodecAccumulator Must meet the requirements of AccumulatorSet.
         *
         * @param first Iterator defines the beginning of the range to be encoded.
         * @param last Iterator defines the end of the range to be encoded.
         *
         * @return Encoded data emplaced in any type convertible to the type
         * satisfying SequenceContainer with the value type satisfying Integral
         * concept requirements.
         */
        template<typename Encoder,
                 typename InputIterator,
                 typename CodecAccumulator = typename codec::accumulator_set<typename Encoder::stream_encoder_type>>
        codec::detail::range_codec_impl<codec::detail::value_codec_impl<CodecAccumulator>> encode(InputIterator first,
                                                                                                  InputIterator last) {
            typedef codec::detail::value_codec_impl<CodecAccumulator> EncoderStateImpl;
            typedef codec::detail::range_codec_impl<EncoderStateImpl> EncoderImpl;

            return EncoderImpl(first, last, CodecAccumulator());
        }

        /*!
         * @brief Encodes the elements with particular codec defined with Encoder
         * in the range, defined by [first, last) and returns the result with type
         * satisfying AccumulatorSet requirements.
         *
         * @ingroup codec_algorithms
         *
         * @tparam Encoder Must meet the requirements of Codec which determines the
         * particular algorithm to be used with range given.
         * @tparam InputIterator Must meet the requirements of InputIterator.
         * @tparam CodecAccumulator Must meet the requirements of AccumulatorSet.
         *
         * @param first Iterator defines the beginning of the range to be encoded.
         * @param last Iterator defines the end of the range to be encoded.
         * @param acc AccumulatorSet defines the place encoded data would be stored.
         *
         * @return CodecAccumulator AccumulatorSet non-const reference equal to acc.
         */
        template<typename Encoder,
                 typename InputIterator,
                 typename CodecAccumulator = typename codec::accumulator_set<typename Encoder::stream_encoder_type>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<CodecAccumulator>::value,
                                CodecAccumulator>::type &
            encode(InputIterator first, InputIterator last, CodecAccumulator &acc) {

            typedef codec::detail::ref_codec_impl<CodecAccumulator> EncoderStateImpl;
            typedef codec::detail::range_codec_impl<EncoderStateImpl> EncoderImpl;

            return EncoderImpl(first, last, std::forward<CodecAccumulator>(acc));
        }

        /*!
         * @brief Encodes the elements with particular codec defined with Encoder
         * in the range, defined by rng and inserts the result to destination
         * range beginning at out.
         *
         * @ingroup codec_algorithms
         *
         * @tparam Encoder Must meet the requirements of Codec which determines the
         * particular algorithm to be used with range given.
         * @tparam SinglePassRange Must meet the requirements of SinglePassRange
         * @tparam OutputIterator Must meet the requirements of OutputIterator.
         *
         * @param rng Defines the range to be processed by encoder.
         * @param out Defines the beginning of destination range.
         *
         * @return Output iterator to the element in the destination range, one past the last element inserted.
         */
        template<typename Encoder, typename SinglePassRange, typename OutputIterator>
        typename std::enable_if<detail::is_iterator<OutputIterator>::value, OutputIterator>::type
            encode(const SinglePassRange &rng, OutputIterator out) {

            typedef typename Encoder::stream_encoder_type EncodingMode;
            typedef typename codec::accumulator_set<EncodingMode> CodecAccumulator;

            typedef codec::detail::value_codec_impl<CodecAccumulator> EncoderStateImpl;
            typedef codec::detail::itr_codec_impl<EncoderStateImpl, OutputIterator> EncoderImpl;

            return EncoderImpl(rng, std::move(out), CodecAccumulator());
        }

        /*!
         * @brief Encodes the elements with particular codec defined with Encoder
         * in the range, defined by rng and inserts the result to destination
         * range beginning at out.
         *
         * @ingroup codec_algorithms
         *
         * @tparam Encoder Must meet the requirements of Codec which determines the
         * particular algorithm to be used with range given.
         * @tparam SinglePassRange Must meet the requirements of SinglePassRange
         * @tparam CodecAccumulator Must meet the requirements of AccumulatorSet.
         *
         * @param rng Defines the range to be processed by encoder.
         * @param acc AccumulatorSet defines the destination encoded data would be stored.
         * @return CodecAccumulator AccumulatorSet non-const reference equal to acc.
         */
        template<typename Encoder,
                 typename SinglePassRange,
                 typename CodecAccumulator = typename codec::accumulator_set<typename Encoder::stream_encoder_type>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<CodecAccumulator>::value,
                                CodecAccumulator>::type &
            encode(const SinglePassRange &rng, CodecAccumulator &acc) {

            typedef codec::detail::ref_codec_impl<CodecAccumulator> EncoderStateImpl;
            typedef codec::detail::range_codec_impl<EncoderStateImpl> EncoderImpl;

            return EncoderImpl(rng, std::forward<CodecAccumulator>(acc));
        }

        /*!
         * @brief Encodes the elements with particular codec defined with Encoder
         * in the range, defined by rng and returns the result with any
         * type convertible to the type satisfying SequenceContainer with the value
         * type satisfying Integral concept requirements.
         *
         * @ingroup codec_algorithms
         *
         * @tparam Encoder Must meet the requirements of Codec which determines the
         * particular algorithm to be used with range given.
         * @tparam SinglePassRange Must meet the requirements of SinglePassRange
         *
         * @param r Defines the range to be processed by encoder.
         *
         * @return Encoded data emplaced in any type convertible to the type
         * satisfying SequenceContainer with the value type satisfying Integral
         * concept requirements.
         */
        template<typename Encoder,
                 typename SinglePassRange,
                 typename CodecAccumulator = typename codec::accumulator_set<typename Encoder::stream_encoder_type>>
        codec::detail::range_codec_impl<codec::detail::value_codec_impl<CodecAccumulator>>
            encode(const SinglePassRange &r) {

            typedef codec::detail::value_codec_impl<CodecAccumulator> EncoderStateImpl;
            typedef codec::detail::range_codec_impl<EncoderStateImpl> EncoderImpl;

            return EncoderImpl(r, CodecAccumulator());
        }
    }    // namespace crypto3
}    // namespace nil

#endif
