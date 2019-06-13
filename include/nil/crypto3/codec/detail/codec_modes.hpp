//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
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
                    typedef typename stream_processor_mode<Codec>::decoded_block_type input_block_type;

                    constexpr static const std::size_t output_value_bits = codec_type::encoded_value_bits;
                    typedef typename stream_processor_mode<Codec>::encoded_value_type output_value_type;

                    constexpr static const std::size_t output_block_bits = codec_type::encoded_block_bits;
                    typedef typename stream_processor_mode<Codec>::encoded_block_type output_block_type;

                    typedef typename codec_type::encoding_finalizer_type finalizer_type;

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

                    constexpr static const std::size_t output_value_bits = codec_type::decoded_value_bits;
                    typedef typename stream_processor_mode<Codec>::decoded_value_type output_value_type;

                    typedef typename stream_processor_mode<Codec>::decoded_block_type output_block_type;
                    constexpr static const std::size_t output_block_bits = codec_type::decoded_block_bits;

                    typedef typename codec_type::decoding_finalizer_type finalizer_type;

                    static inline output_block_type process_block(const input_block_type &plaintext) {
                        return codec_type::decode(plaintext);
                    }
                };
            }
        }
    }
}

#endif //CRYPTO3_PREPROCESSING_MODES_HPP
