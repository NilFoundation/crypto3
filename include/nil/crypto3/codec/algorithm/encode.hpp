//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
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
             * @defgroup codec_algorithms Algorithms
             * @ingroup codec
             * @brief Algorithms are meant to provide encoding interface similar to STL algorithms' one.
             */
        }

        /*!
         * @brief
         *
         * @ingroup codec_algorithms
         *
         * @tparam Encoder
         * @tparam InputIterator
         * @tparam OutputIterator
         * @tparam EncoderState
         *
         * @param first
         * @param last
         * @param out
         *
         * @return
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
         * @brief
         *
         * @ingroup codec_algorithms
         *
         * @tparam Encoder
         * @tparam InputIterator
         * @tparam EncoderAccumuator
         * @param first
         * @param last
         * @return
         */
        template<typename Encoder, typename InputIterator,
                 typename EncoderAccumuator = typename codec::codec_accumulator<typename Encoder::stream_encoder_type>>
        codec::detail::range_codec_impl<codec::detail::value_codec_impl<EncoderAccumuator>> encode(InputIterator first,
                                                                                                   InputIterator last) {
            typedef codec::detail::value_codec_impl<EncoderAccumuator> EncoderStateImpl;
            typedef codec::detail::range_codec_impl<EncoderStateImpl> EncoderImpl;

            return EncoderImpl(first, last, EncoderAccumuator());
        }

        /*!
         * @brief
         *
         * @ingroup codec_algorithms
         *
         * @tparam Encoder
         * @tparam InputIterator
         * @tparam OutputAccuulator
         * @tparam EncoderState
         *
         * @param first
         * @param last
         * @param out
         *
         * @return
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
         * @brief
         *
         * @ingroup codec_algorithms
         *
         * @tparam Encoder
         * @tparam SinglePassRange
         * @tparam OutputIterator
         * @param rng
         * @param out
         * @return
         */
        template<typename Encoder, typename SinglePassRange, typename OutputIterator>
        typename std::enable_if<codec::detail::is_iterator<OutputIterator>::value, OutputIterator>::type
            encode(const SinglePassRange &rng, OutputIterator out) {
            typedef typename Encoder::stream_encoder_type EncodingMode;
            typedef typename codec::codec_accumulator<EncodingMode> EncoderAccumulator;

            typedef codec::detail::value_codec_impl<EncoderAccumulator> EncoderStateImpl;
            typedef codec::detail::itr_codec_impl<EncoderStateImpl, OutputIterator> EncoderImpl;

            return EncoderImpl(rng, std::move(out), EncoderAccumulator());
        }

        /*!
         * @brief
         *
         * @ingroup codec_algorithms
         *
         * @tparam Encoder
         * @tparam SinglePassRange
         * @tparam OutputIterator
         * @param rng
         * @param out
         * @return
         */
        template<typename Encoder, typename SinglePassRange,
                 typename CodecAccumulator = typename codec::codec_accumulator<typename Encoder::stream_encoder_type>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<CodecAccumulator>::value,
                                CodecAccumulator>::type &
            encode(const SinglePassRange &rng, CodecAccumulator &out) {
            typedef typename Encoder::stream_encoder_type EncodingMode;
            typedef typename codec::codec_accumulator<EncodingMode> EncoderAccumulator;

            typedef codec::detail::ref_codec_impl<EncoderAccumulator> EncoderStateImpl;
            typedef codec::detail::range_codec_impl<EncoderStateImpl> EncoderImpl;

            return EncoderImpl(rng, std::forward<CodecAccumulator>(out));
        }

        /*!
         * @brief
         *
         * @ingroup codec_algorithms
         *
         * @tparam Encoder
         * @tparam SinglePassRange
         * @tparam EncoderState
         * @param r
         * @return
         */
        template<typename Encoder, typename SinglePassRange,
                 typename CodecAccumuator = typename codec::codec_accumulator<typename Encoder::stream_encoder_type>>
        codec::detail::range_codec_impl<codec::detail::value_codec_impl<CodecAccumuator>>
            encode(const SinglePassRange &r) {

            typedef codec::detail::value_codec_impl<CodecAccumuator> EncoderStateImpl;
            typedef codec::detail::range_codec_impl<EncoderStateImpl> EncoderImpl;

            return EncoderImpl(r, CodecAccumuator());
        }
    }    // namespace crypto3
}    // namespace nil

#endif
