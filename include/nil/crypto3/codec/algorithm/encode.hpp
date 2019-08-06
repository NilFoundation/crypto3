//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ENCODE_HPP
#define CRYPTO3_ENCODE_HPP

#include <nil/crypto3/codec/codec_value.hpp>
#include <nil/crypto3/codec/codec_state.hpp>

#include <nil/crypto3/codec/detail/type_traits.hpp>

namespace nil {
    namespace crypto3 {
        namespace codec {
            /*!
             * @defgroup codec Encoding & Decoding
             *
             * @defgroup codec_algorithms Algorithms
             * @ingroup codec
             * @brief Encoding algorithms are meant to provide encoding interface similar to STL algorithms' one.
             */
        }

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
        typename std::enable_if<codec::detail::is_iterator<OutputIterator>::value, OutputIterator>::type
            encode(InputIterator first, InputIterator last, OutputIterator out) {
            typedef typename Encoder::stream_encoder_type EncodingMode;
            typedef typename codec::codec_accumulator<EncodingMode> EncoderAccumulator;

            typedef codec::detail::value_codec_impl<EncoderAccumulator> EncoderStateImpl;
            typedef codec::detail::itr_codec_impl<EncoderStateImpl, OutputIterator> EncoderImpl;

            return EncoderImpl(first, last, std::move(out), EncoderAccumulator());
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
         * @tparam EncoderAccumulator Must meet the requirements of AccumulatorSet.
         *
         * @param first Iterator defines the beginning of the range to be encoded.
         * @param last Iterator defines the end of the range to be encoded.
         *
         * @return Encoded data emplaced in any type convertible to the type
         * satisfying SequenceContainer with the value type satisfying Integral
         * concept requirements.
         */
        template<typename Encoder, typename InputIterator,
                 typename EncoderAccumulator = typename codec::codec_accumulator<typename Encoder::stream_encoder_type>>
        codec::detail::range_codec_impl<codec::detail::value_codec_impl<EncoderAccumulator>>
            encode(InputIterator first, InputIterator last) {
            typedef codec::detail::value_codec_impl<EncoderAccumulator> EncoderStateImpl;
            typedef codec::detail::range_codec_impl<EncoderStateImpl> EncoderImpl;

            return EncoderImpl(first, last, EncoderAccumulator());
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
        template<typename Encoder, typename InputIterator,
                 typename CodecAccumulator = typename codec::codec_accumulator<typename Encoder::stream_encoder_type>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<CodecAccumulator>::value,
                                CodecAccumulator>::type &
            encode(InputIterator first, InputIterator last, CodecAccumulator &acc) {
            typedef typename Encoder::stream_encoder_type EncodingMode;
            typedef typename codec::codec_accumulator<EncodingMode> EncoderAccumulator;

            typedef codec::detail::ref_codec_impl<EncoderAccumulator> EncoderStateImpl;
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
         * @tparam InputRange Must meet the requirements of InputRange
         * @tparam OutputIterator Must meet the requirements of OutputIterator.
         *
         * @param rng Defines the range to be processed by encoder.
         * @param out Defines the beginning of destination range.
         *
         * @return Output iterator to the element in the destination range, one past the last element inserted.
         */
        template<typename Encoder, typename InputRange, typename OutputIterator>
        typename std::enable_if<codec::detail::is_iterator<OutputIterator>::value, OutputIterator>::type
            encode(const InputRange &rng, OutputIterator out) {
            typedef typename Encoder::stream_encoder_type EncodingMode;
            typedef typename codec::codec_accumulator<EncodingMode> EncoderAccumulator;

            typedef codec::detail::value_codec_impl<EncoderAccumulator> EncoderStateImpl;
            typedef codec::detail::itr_codec_impl<EncoderStateImpl, OutputIterator> EncoderImpl;

            return EncoderImpl(rng, std::move(out), EncoderAccumulator());
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
         * @tparam InputRange Must meet the requirements of InputRange
         * @tparam CodecAccumulator Must meet the requirements of AccumulatorSet.
         *
         * @param rng Defines the range to be processed by encoder.
         * @param acc AccumulatorSet defines the destination encoded data would be stored.
         * @return CodecAccumulator AccumulatorSet non-const reference equal to acc.
         */
        template<typename Encoder, typename InputRange,
                 typename CodecAccumulator = typename codec::codec_accumulator<typename Encoder::stream_encoder_type>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<CodecAccumulator>::value,
                                CodecAccumulator>::type &
            encode(const InputRange &rng, CodecAccumulator &acc) {
            typedef typename Encoder::stream_encoder_type EncodingMode;
            typedef typename codec::codec_accumulator<EncodingMode> EncoderAccumulator;

            typedef codec::detail::ref_codec_impl<EncoderAccumulator> EncoderStateImpl;
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
         * @tparam InputRange Must meet the requirements of InputRange
         *
         * @param r Defines the range to be processed by encoder.
         *
         * @return Encoded data emplaced in any type convertible to the type
         * satisfying SequenceContainer with the value type satisfying Integral
         * concept requirements.
         */
        template<typename Encoder, typename InputRange,
                 typename CodecAccumulator = typename codec::codec_accumulator<typename Encoder::stream_encoder_type>>
        codec::detail::range_codec_impl<codec::detail::value_codec_impl<CodecAccumulator>> encode(const InputRange &r) {

            typedef codec::detail::value_codec_impl<CodecAccumulator> EncoderStateImpl;
            typedef codec::detail::range_codec_impl<EncoderStateImpl> EncoderImpl;

            return EncoderImpl(r, CodecAccumulator());
        }
    }    // namespace crypto3
}    // namespace nil

#endif
