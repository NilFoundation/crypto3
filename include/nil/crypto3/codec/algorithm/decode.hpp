//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_DECODE_HPP
#define CRYPTO3_DECODE_HPP

#include <nil/crypto3/codec/codec_value.hpp>
#include <nil/crypto3/codec/codec_state.hpp>

#include <nil/crypto3/detail/type_traits.hpp>

namespace nil {
    namespace crypto3 {
        namespace codec {
            /*!
             * @defgroup codec Encoding & Decoding
             *
             * @defgroup codec_algorithms Algorithms
             * @ingroup codec
             * @brief Algorithms are meant to provide decoding interface similar to STL algorithms' one.
             */
        }

        /*!
         * @brief Decodes the elements with particular codec defined with Decoder
         * in the range, defined by [first, last), and inserts the result to
         * another range beginning at out.
         *
         * @ingroup codec_algorithms
         *
         * @tparam Decoder Must meet the requirements of Codec which determines the
         * particular algorithm to be used with range given.
         * @tparam InputIterator Must meet the requirements of InputIterator.
         * @tparam OutputIterator Must meet the requirements of OutputIterator.
         *
         * @param first Iterator defines the beginning of the range to be decoded.
         * @param last Iterator defines the end of the range to be decoded.
         * @param out Iterator defines the beginning of the destination range.
         *
         * @return Output iterator to the element in the destination range, one past the last element inserted.
         */
        template<typename Decoder, typename InputIterator, typename OutputIterator>
        typename std::enable_if<detail::is_iterator<OutputIterator>::value, OutputIterator>::type
            decode(InputIterator first, InputIterator last, OutputIterator out) {
            typedef typename Decoder::stream_decoder_type DecodingMode;
            typedef typename codec::codec_accumulator<DecodingMode> CodecAccumulator;

            typedef codec::detail::value_codec_impl<CodecAccumulator> DecoderStateImpl;
            typedef codec::detail::itr_codec_impl<DecoderStateImpl, OutputIterator> DecoderImpl;

            return DecoderImpl(first, last, std::move(out), CodecAccumulator());
        }

        /*!
         * @brief Decodes the elements with particular codec defined with Decoder
         * in the range, defined by [first, last) and returns the result with any
         * type convertible to the type satisfying SequenceContainer with the value
         * type satisfying Integral concept requirements.
         *
         * @ingroup codec_algorithms
         *
         * @tparam Decoder Must meet the requirements of Codec which determines the
         * particular algorithm to be used with range given.
         * @tparam InputIterator Must meet the requirements of InputIterator.
         * @tparam CodecAccumulator Must meet the requirements of AccumulatorSet.
         *
         * @param first Iterator defines the beginning of the range to be decoded.
         * @param last Iterator defines the end of the range to be decoded.
         *
         * @return Decoded data emplaced in any type convertible to the type
         * satisfying SequenceContainer with the value type satisfying Integral
         * concept requirements.
         */
        template<typename Decoder,
                 typename InputIterator,
                 typename CodecAccumulator = typename codec::codec_accumulator<typename Decoder::stream_decoder_type>>
        codec::detail::range_codec_impl<codec::detail::value_codec_impl<CodecAccumulator>> decode(InputIterator first,
                                                                                                  InputIterator last) {
            typedef codec::detail::value_codec_impl<CodecAccumulator> DecoderStateImpl;
            typedef codec::detail::range_codec_impl<DecoderStateImpl> DecoderImpl;

            return DecoderImpl(first, last, CodecAccumulator());
        }

        /*!
         * @brief Decodes the elements with particular codec defined with Decoder
         * in the range, defined by rng and inserts the result to destination
         * range beginning at out.
         *
         * @ingroup codec_algorithms
         *
         * @tparam Decoder Must meet the requirements of Codec which determines the
         * particular algorithm to be used with range given.
         * @tparam SinglePassRange Must meet the requirements of SinglePassRange
         * @tparam OutputIterator Must meet the requirements of OutputIterator.
         *
         * @param rng Defines the range to be processed by decoder.
         * @param acc AccumulatorSet defines the destination decoded data would be stored.
         *
         * @return Output iterator to the element in the destination range, one past the last element inserted.
         */
        template<typename Decoder,
                 typename InputIterator,
                 typename CodecAccumulator = typename codec::codec_accumulator<typename Decoder::stream_decoder_type>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<CodecAccumulator>::value,
                                CodecAccumulator>::type &
            decode(InputIterator first, InputIterator last, CodecAccumulator &acc) {
            typedef codec::detail::ref_codec_impl<CodecAccumulator> DecoderStateImpl;
            typedef codec::detail::range_codec_impl<DecoderStateImpl> DecoderImpl;

            return DecoderImpl(first, last, std::forward<CodecAccumulator>(acc));
        }

        /*!
         * @brief Decodes the elements with particular codec defined with Decoder
         * in the range, defined by rng and inserts the result to destination
         * range beginning at out.
         *
         * @ingroup codec_algorithms
         *
         * @tparam Decoder Must meet the requirements of Codec which determines the
         * particular algorithm to be used with range given.
         * @tparam SinglePassRange Must meet the requirements of SinglePassRange
         * @tparam CodecAccumulator Must meet the requirements of AccumulatorSet.
         *
         * @param rng Defines the range to be processed by decoder.
         * @param out Defines the beginning of destination range.
         * @return CodecAccumulator AccumulatorSet non-const reference equal to acc.
         */
        template<typename Decoder, typename SinglePassRange, typename OutputIterator>
        typename std::enable_if<detail::is_iterator<OutputIterator>::value, OutputIterator>::type
            decode(const SinglePassRange &rng, OutputIterator out) {
            typedef typename Decoder::stream_decoder_type DecodingMode;
            typedef typename codec::codec_accumulator<DecodingMode> CodecAccumulator;

            typedef codec::detail::value_codec_impl<CodecAccumulator> DecoderStateImpl;
            typedef codec::detail::itr_codec_impl<DecoderStateImpl, OutputIterator> DecoderImpl;

            return DecoderImpl(rng, std::move(out), CodecAccumulator());
        }

        /*!
         * @brief Decodes the elements with particular codec defined with Decoder
         * in the range, defined by rng and inserts the result to destination
         * range beginning at out.
         *
         * @ingroup codec_algorithms
         *
         * @tparam Decoder Must meet the requirements of Codec which determines the
         * particular algorithm to be used with range given.
         * @tparam SinglePassRange Must meet the requirements of SinglePassRange
         * @tparam CodecAccumulator Must meet the requirements of AccumulatorSet.
         *
         * @param rng Defines the range to be processed by decoder.
         * @param acc AccumulatorSet defines the destination decoded data would be stored.
         * @return CodecAccumulator AccumulatorSet non-const reference equal to acc.
         */
        template<typename Decoder,
                 typename SinglePassRange,
                 typename CodecAccumulator = typename codec::codec_accumulator<typename Decoder::stream_decoder_type>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<CodecAccumulator>::value,
                                CodecAccumulator>::type &
            decode(const SinglePassRange &rng, CodecAccumulator &acc) {
            typedef codec::detail::value_codec_impl<CodecAccumulator> DecoderStateImpl;
            typedef codec::detail::range_codec_impl<DecoderStateImpl> DecoderImpl;

            return DecoderImpl(rng, std::forward<CodecAccumulator>(acc));
        }

        /*!
         * @brief Decodes the elements with particular codec defined with Decoder
         * in the range, defined by rng and returns the result with any
         * type convertible to the type satisfying SequenceContainer with the value
         * type satisfying Integral concept requirements.
         *
         * @ingroup codec_algorithms
         *
         * @tparam Decoder Must meet the requirements of Codec which determines the
         * particular algorithm to be used with range given.
         * @tparam SinglePassRange Must meet the requirements of SinglePassRange
         *
         * @param r Defines the range to be processed by decoder.
         *
         * @return Decoded data emplaced in any type convertible to the type
         * satisfying SequenceContainer with the value type satisfying Integral
         * concept requirements.
         */
        template<typename Decoder,
                 typename SinglePassRange,
                 typename CodecAccumulator = typename codec::codec_accumulator<typename Decoder::stream_decoder_type>>
        codec::detail::range_codec_impl<codec::detail::value_codec_impl<CodecAccumulator>>
            decode(const SinglePassRange &r) {

            typedef codec::detail::value_codec_impl<CodecAccumulator> DecoderStateImpl;
            typedef codec::detail::range_codec_impl<DecoderStateImpl> DecoderImpl;

            return DecoderImpl(r, CodecAccumulator());
        }
    }    // namespace crypto3
}    // namespace nil

#endif    // include guard
