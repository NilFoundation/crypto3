//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2019 Aleksey Moskvin <zerg1996@yandex.ru>
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

#ifndef CRYPTO3_PREPROCESSING_MODES_HPP
#define CRYPTO3_PREPROCESSING_MODES_HPP

namespace nil {
    namespace crypto3 {
        namespace codec {
            namespace detail {
                template<typename Codec>
                struct stream_processor_mode {
                    typedef Codec codec_type;

                    typedef typename codec_type::encoded_value_type encoded_value_type;
                    typedef typename codec_type::encoded_block_type encoded_block_type;

                    typedef typename codec_type::decoded_value_type decoded_value_type;
                    typedef typename codec_type::decoded_block_type decoded_block_type;
                };

                template<typename Codec>
                struct isomorphic_encoding_mode : public stream_processor_mode<Codec> {
                    typedef typename stream_processor_mode<Codec>::codec_type codec_type;

                    constexpr static const std::size_t input_value_bits = codec_type::decoded_value_bits;
                    typedef typename stream_processor_mode<Codec>::decoded_value_type input_value_type;

                    constexpr static const std::size_t input_block_bits = codec_type::decoded_block_bits;
                    constexpr static const std::size_t input_block_values = codec_type::decoded_block_values;
                    typedef typename stream_processor_mode<Codec>::decoded_block_type input_block_type;

                    constexpr static const std::size_t output_value_bits = codec_type::encoded_value_bits;
                    typedef typename stream_processor_mode<Codec>::encoded_value_type output_value_type;

                    constexpr static const std::size_t output_block_bits = codec_type::encoded_block_bits;
                    constexpr static const std::size_t output_block_values = codec_type::encoded_block_values;
                    typedef typename stream_processor_mode<Codec>::encoded_block_type output_block_type;

                    typedef typename codec_type::encoding_finalizer_type finalizer_type;
                    typedef typename codec_type::encoding_preprocessor_type preprocessor_type;

                    static inline output_block_type process_block(const input_block_type &plaintext) {
                        return codec_type::encode(plaintext);
                    }
                };

                template<typename Codec>
                struct isomorphic_decoding_mode : public stream_processor_mode<Codec> {
                    typedef typename stream_processor_mode<Codec>::codec_type codec_type;

                    constexpr static const std::size_t input_value_bits = codec_type::encoded_value_bits;
                    typedef typename stream_processor_mode<Codec>::encoded_value_type input_value_type;

                    typedef typename stream_processor_mode<Codec>::encoded_block_type input_block_type;
                    constexpr static const std::size_t input_block_bits = codec_type::encoded_block_bits;
                    constexpr static const std::size_t input_block_values = codec_type::encoded_block_values;

                    constexpr static const std::size_t output_value_bits = codec_type::decoded_value_bits;
                    typedef typename stream_processor_mode<Codec>::decoded_value_type output_value_type;

                    typedef typename stream_processor_mode<Codec>::decoded_block_type output_block_type;
                    constexpr static const std::size_t output_block_bits = codec_type::decoded_block_bits;
                    constexpr static const std::size_t output_block_values = codec_type::decoded_block_values;

                    typedef typename codec_type::decoding_finalizer_type finalizer_type;
                    typedef typename codec_type::decoding_preprocessor_type preprocessor_type;

                    static inline output_block_type process_block(const input_block_type &plaintext) {
                        return codec_type::decode(plaintext);
                    }
                };
            }    // namespace detail
        }        // namespace codec
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PREPROCESSING_MODES_HPP
