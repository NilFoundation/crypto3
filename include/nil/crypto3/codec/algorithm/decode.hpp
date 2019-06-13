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
        OutputIterator decode(InputIterator first, InputIterator last, OutputIterator out) {
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
         * @tparam DecoderAccumuator
         * @param first
         * @param last
         * @return
         */
        template<typename Decoder,
                 typename InputIterator,
                 typename DecoderAccumuator = typename codec::codec_accumulator<typename Decoder::stream_decoder_type>>
        codec::detail::range_codec_impl<codec::detail::value_codec_impl<DecoderAccumuator>> decode(InputIterator first,
                                                                                                   InputIterator last) {
            typedef codec::detail::value_codec_impl<DecoderAccumuator> DecoderStateImpl;
            typedef codec::detail::range_codec_impl<DecoderStateImpl> DecoderImpl;

            return DecoderImpl(first, last, DecoderAccumuator());
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
        template<typename Decoder,
                 typename InputIterator,
                 typename OutputAccumulator = typename codec::codec_accumulator<typename Decoder::stream_decoder_type>>
        OutputAccumulator &decode(InputIterator first, InputIterator last, OutputAccumulator &acc) {
            typedef typename Decoder::stream_decoder_type DecodingMode;
            typedef typename codec::codec_accumulator<DecodingMode> DecoderAccumulator;

            typedef codec::detail::ref_codec_impl<DecoderAccumulator> DecoderStateImpl;
            typedef codec::detail::range_codec_impl<DecoderStateImpl> DecoderImpl;

            return DecoderImpl(first, last, acc);
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
        OutputIterator decode(const SinglePassRange &rng, OutputIterator out) {
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
        template<typename Decoder,
                 typename SinglePassRange,
                 typename OutputAccumulator = typename codec::codec_accumulator<typename Decoder::stream_decoder_type>>
        OutputAccumulator &decode(const SinglePassRange &rng, OutputAccumulator &out) {
            typedef typename Decoder::stream_decoder_type DecodingMode;
            typedef typename codec::codec_accumulator<DecodingMode> DecoderAccumulator;

            typedef codec::detail::value_codec_impl<DecoderAccumulator> DecoderStateImpl;
            typedef codec::detail::range_codec_impl<DecoderStateImpl> DecoderImpl;

            return DecoderImpl(rng, out);
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
        template<typename Decoder,
                 typename SinglePassRange,
                 typename DecoderAccumuator = typename codec::codec_accumulator<typename Decoder::stream_decoder_type>>
        codec::detail::range_codec_impl<codec::detail::value_codec_impl<DecoderAccumuator>> decode(
                const SinglePassRange &r) {

            typedef codec::detail::value_codec_impl<DecoderAccumuator> DecoderStateImpl;
            typedef codec::detail::range_codec_impl<DecoderStateImpl> DecoderImpl;

            return DecoderImpl(r, DecoderAccumuator());
        }
    } // namespace crypto3
} // namespace nil

#endif // include guard
