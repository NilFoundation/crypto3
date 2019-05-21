//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_DECODE_HPP
#define CRYPTO3_DECODE_HPP

#include <nil/crypto3/codec/detail/codec_value.hpp>

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
         * @tparam Decoder
         * @tparam InputIterator
         * @tparam OutputIterator
         * @tparam StreamDecoder
         *
         * @param first
         * @param last
         * @param out
         *
         * @return
         */
        template<typename Decoder, typename InputIterator, typename OutputIterator>
        OutputIterator decode(InputIterator first, InputIterator last, OutputIterator out) {
            typedef typename Decoder::stream_decoder_type DecodingMode;
            typedef typename codec::itr_stream_codec_traits<DecodingMode, InputIterator>::type StreamDecoder;

            typedef codec::detail::value_codec_impl<StreamDecoder> StreamDecoderImpl;
            typedef codec::detail::itr_codec_impl<StreamDecoderImpl, OutputIterator> DecoderImpl;

            return DecoderImpl(first, last, std::move(out), StreamDecoder());
        }

        /*!
         * @brief
         *
         * @ingroup codec_algorithms
         *
         * @tparam Decoder
         * @tparam InputIterator
         * @tparam StreamDecoder
         * @param first
         * @param last
         * @return
         */
        template<typename Decoder,
                 typename InputIterator,
                 typename StreamDecoder = typename codec::itr_stream_codec_traits<typename Decoder::stream_decoder_type,
                                                                                  InputIterator>::type>
        codec::detail::range_codec_impl<codec::detail::value_codec_impl<StreamDecoder>> decode(InputIterator first,
                                                                                               InputIterator last) {
            typedef codec::detail::value_codec_impl<StreamDecoder> StreamDecoderImpl;
            typedef codec::detail::range_codec_impl<StreamDecoderImpl> DecoderImpl;

            return DecoderImpl(first, last, StreamDecoder());
        }

        /*!
         * @brief
         *
         * @ingroup codec_algorithms
         *
         * @tparam Decoder
         * @tparam SinglePassRange
         * @tparam OutputIterator
         * @tparam StreamDecoder
         * @param rng
         * @param out
         * @return
         */
        template<typename Decoder, typename SinglePassRange, typename OutputIterator>
        OutputIterator decode(const SinglePassRange &rng, OutputIterator out) {
            typedef typename Decoder::stream_decoder_type DecodingMode;
            typedef typename codec::range_stream_codec_traits<typename Decoder::stream_decoder_type,
                                                              SinglePassRange>::type StreamDecoder;

            typedef codec::detail::value_codec_impl<StreamDecoder> StreamDecoderImpl;
            typedef codec::detail::itr_codec_impl<StreamDecoderImpl, OutputIterator> DecoderImpl;

            return DecoderImpl(rng, std::move(out), StreamDecoder());
        }

        /*!
         * @brief
         *
         * @ingroup codec_algorithms
         *
         * @tparam Decoder
         * @tparam SinglePassRange
         * @tparam StreamDecoder
         * @param r
         * @return
         */
        template<typename Decoder,
                 typename SinglePassRange,
                 typename StreamDecoder = typename codec::range_stream_codec_traits<
                         typename Decoder::stream_decoder_type, SinglePassRange>::type>
        codec::detail::range_codec_impl<codec::detail::value_codec_impl<StreamDecoder>> decode(
                const SinglePassRange &r) {

            typedef codec::detail::value_codec_impl<StreamDecoder> StreamDecoderImpl;
            typedef codec::detail::range_codec_impl<StreamDecoderImpl> DecoderImpl;

            return DecoderImpl(r, StreamDecoder());
        }
    } // namespace crypto3
} // namespace nil

#endif // include guard
