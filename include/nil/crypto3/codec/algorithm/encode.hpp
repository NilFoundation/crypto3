//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
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
        OutputIterator encode(InputIterator first, InputIterator last, OutputIterator out) {
            typedef typename Encoder::stream_encoder_type EncodingMode;
            typedef typename codec::codec_state<EncodingMode> EncoderState;

            typedef codec::detail::value_codec_impl<EncoderState> EncoderStateImpl;
            typedef codec::detail::itr_codec_impl<EncoderStateImpl, OutputIterator> EncoderImpl;

            return EncoderImpl(first, last, std::move(out), EncoderState());
        }

        /*!
         * @brief
         *
         * @ingroup codec_algorithms
         *
         * @tparam Encoder
         * @tparam InputIterator
         * @tparam EncoderState
         * @param first
         * @param last
         * @return
         */
        template<typename Encoder,
                 typename InputIterator,
                 typename EncoderState = typename codec::codec_state<typename Encoder::stream_encoder_type>>
        codec::detail::range_codec_impl<codec::detail::value_codec_impl<EncoderState>> encode(InputIterator first,
                                                                                              InputIterator last) {
            typedef codec::detail::value_codec_impl<EncoderState> EncoderStateImpl;
            typedef codec::detail::range_codec_impl<EncoderStateImpl> EncoderImpl;

            return EncoderImpl(first, last, EncoderState());
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
        OutputIterator encode(const SinglePassRange &rng, OutputIterator out) {
            typedef typename Encoder::stream_encoder_type EncodingMode;
            typedef typename codec::codec_state<EncodingMode> EncoderState;

            typedef codec::detail::value_codec_impl<EncoderState> EncoderStateImpl;
            typedef codec::detail::itr_codec_impl<EncoderStateImpl, OutputIterator> EncoderImpl;

            return EncoderImpl(rng, std::move(out), EncoderState());
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
        template<typename Encoder,
                 typename SinglePassRange,
                 typename EncoderState = typename codec::codec_state<typename Encoder::stream_encoder_type>>
        codec::detail::range_codec_impl<codec::detail::value_codec_impl<EncoderState>> encode(
                const SinglePassRange &r) {

            typedef codec::detail::value_codec_impl<EncoderState> EncoderStateImpl;
            typedef codec::detail::range_codec_impl<EncoderStateImpl> EncoderImpl;

            return EncoderImpl(r, EncoderState());
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
        template<typename Encoder,
                 typename EncoderState,
                 typename = typename std::enable_if<codec::detail::is_codec_state<EncoderState>::value>::type>
        codec::detail::range_codec_impl<codec::detail::value_codec_impl<EncoderState>> encode(const EncoderState &r) {

            typedef codec::detail::value_codec_impl<EncoderState> EncoderStateImpl;
            typedef codec::detail::range_codec_impl<EncoderStateImpl> EncoderImpl;

            return EncoderImpl(r, r);
        }
    } // namespace crypto3
} // namespace nil

#endif
