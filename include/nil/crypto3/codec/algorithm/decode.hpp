//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_DECODE_HPP
#define CRYPTO3_DECODE_HPP

#include <nil/crypto3/codec/codec_value.hpp>
#include <nil/crypto3/codec/codec_state.hpp>

#include <nil/crypto3/codec/detail/type_traits.hpp>

namespace nil {
    namespace crypto3 {
        namespace codec {
            /*!
             * @defgroup codec_algorithms Algorithms
             * @ingroup codec
             * @brief Algorithms are meant to provide decoding interface similar to STL algorithms' one.
             */
        }

        /*!
         * @brief
         *
         * @ingroup codec_algorithms
         *
         * @tparam Decoder
         * @tparam InputIterator
         * @tparam OutputIterator
         * @tparam DecoderState
         *
         * @param first
         * @param last
         * @param out
         *
         * @return
         */
        template<typename Decoder, typename InputIterator, typename OutputIterator>
        typename std::enable_if<codec::detail::is_iterator<OutputIterator>::value, OutputIterator>::type
            decode(InputIterator first, InputIterator last, OutputIterator out) {
            typedef typename Decoder::stream_decoder_type DecodingMode;
            typedef typename codec::codec_accumulator<DecodingMode> DecoderAccumulator;

            typedef codec::detail::value_codec_impl<DecoderAccumulator> DecoderStateImpl;
            typedef codec::detail::itr_codec_impl<DecoderStateImpl, OutputIterator> DecoderImpl;

            return DecoderImpl(first, last, std::move(out), DecoderAccumulator());
        }

        /*!
         * @brief
         *
         * @ingroup codec_algorithms
         *
         * @tparam Decoder
         * @tparam InputIterator
         * @tparam CodecAccumulator
         * @param first
         * @param last
         * @return
         */
        template<typename Decoder, typename InputIterator,
                 typename CodecAccumulator = typename codec::codec_accumulator<typename Decoder::stream_decoder_type>>
        codec::detail::range_codec_impl<codec::detail::value_codec_impl<CodecAccumulator>> decode(InputIterator first,
                                                                                                  InputIterator last) {
            typedef codec::detail::value_codec_impl<CodecAccumulator> DecoderStateImpl;
            typedef codec::detail::range_codec_impl<DecoderStateImpl> DecoderImpl;

            return DecoderImpl(first, last, CodecAccumulator());
        }

        /*!
         * @brief
         *
         * @ingroup codec_algorithms
         *
         * @tparam Decoder
         * @tparam InputIterator
         * @tparam OutputAccuulator
         * @tparam DecoderState
         *
         * @param first
         * @param last
         * @param out
         *
         * @return
         */
        template<typename Decoder, typename InputIterator,
                 typename CodecAccumulator = typename codec::codec_accumulator<typename Decoder::stream_decoder_type>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<CodecAccumulator>::value,
                                CodecAccumulator>::type &
            decode(InputIterator first, InputIterator last, CodecAccumulator &acc) {
            typedef typename Decoder::stream_decoder_type DecodingMode;
            typedef typename codec::codec_accumulator<DecodingMode> DecoderAccumulator;

            typedef codec::detail::ref_codec_impl<DecoderAccumulator> DecoderStateImpl;
            typedef codec::detail::range_codec_impl<DecoderStateImpl> DecoderImpl;

            return DecoderImpl(first, last, std::forward<CodecAccumulator>(acc));
        }

        /*!
         * @brief
         *
         * @ingroup codec_algorithms
         *
         * @tparam Decoder
         * @tparam SinglePassRange
         * @tparam OutputIterator
         * @param rng
         * @param out
         * @return
         */
        template<typename Decoder, typename SinglePassRange, typename OutputIterator>
        typename std::enable_if<codec::detail::is_iterator<OutputIterator>::value, OutputIterator>::type
            decode(const SinglePassRange &rng, OutputIterator out) {
            typedef typename Decoder::stream_decoder_type DecodingMode;
            typedef typename codec::codec_accumulator<DecodingMode> DecoderAccumulator;

            typedef codec::detail::value_codec_impl<DecoderAccumulator> DecoderStateImpl;
            typedef codec::detail::itr_codec_impl<DecoderStateImpl, OutputIterator> DecoderImpl;

            return DecoderImpl(rng, std::move(out), DecoderAccumulator());
        }

        /*!
         * @brief
         *
         * @ingroup codec_algorithms
         *
         * @tparam Decoder
         * @tparam SinglePassRange
         * @tparam OutputIterator
         * @param rng
         * @param out
         * @return
         */
        template<typename Decoder, typename SinglePassRange,
                 typename CodecAccumulator = typename codec::codec_accumulator<typename Decoder::stream_decoder_type>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<CodecAccumulator>::value,
                                CodecAccumulator>::type &
            decode(const SinglePassRange &rng, CodecAccumulator &out) {
            typedef typename Decoder::stream_decoder_type DecodingMode;
            typedef typename codec::codec_accumulator<DecodingMode> DecoderAccumulator;

            typedef codec::detail::value_codec_impl<DecoderAccumulator> DecoderStateImpl;
            typedef codec::detail::range_codec_impl<DecoderStateImpl> DecoderImpl;

            return DecoderImpl(rng, std::forward<CodecAccumulator>(out));
        }

        /*!
         * @brief
         *
         * @ingroup codec_algorithms
         *
         * @tparam Decoder
         * @tparam SinglePassRange
         * @tparam DecoderState
         * @param r
         * @return
         */
        template<typename Decoder, typename SinglePassRange,
                 typename DecoderAccumuator = typename codec::codec_accumulator<typename Decoder::stream_decoder_type>>
        codec::detail::range_codec_impl<codec::detail::value_codec_impl<DecoderAccumuator>>
            decode(const SinglePassRange &r) {

            typedef codec::detail::value_codec_impl<DecoderAccumuator> DecoderStateImpl;
            typedef codec::detail::range_codec_impl<DecoderStateImpl> DecoderImpl;

            return DecoderImpl(r, DecoderAccumuator());
        }
    }    // namespace crypto3
}    // namespace nil

#endif    // include guard
