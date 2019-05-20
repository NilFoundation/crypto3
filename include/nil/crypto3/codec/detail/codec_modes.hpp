//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
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
                template<typename Encoder>
                struct stream_processor_mode {
                    typedef Encoder encoder_type;

                    typedef typename encoder_type::encoded_block_type encoded_block_type;
                    typedef typename encoder_type::decoded_block_type decoded_block_type;
                };

                template<typename Encoder>
                struct isomorphic_encoding_mode : public stream_processor_mode<Encoder> {
                    typedef typename stream_processor_mode<Encoder>::encoder_type encoder_type;

                    typedef typename stream_processor_mode<Encoder>::decoded_block_type input_block_type;
                    constexpr static const std::size_t input_block_bits = encoder_type::decoded_block_bits;

                    typedef typename stream_processor_mode<Encoder>::encoded_block_type output_block_type;
                    constexpr static const std::size_t output_block_bits = encoder_type::encoded_block_bits;

                    typedef typename stream_processor_mode<
                            Encoder>::encoder_type::encoding_finalizer_type finalizer_type;

                    static inline output_block_type process_block(const input_block_type &plaintext) {
                        return encoder_type::encode(plaintext);
                    }
                };

                template<typename Encoder>
                struct isomorphic_decoding_mode : public stream_processor_mode<Encoder> {
                    typedef typename stream_processor_mode<Encoder>::encoder_type encoder_type;

                    typedef typename stream_processor_mode<Encoder>::encoded_block_type input_block_type;
                    constexpr static const std::size_t input_block_bits = encoder_type::encoded_block_bits;

                    typedef typename stream_processor_mode<Encoder>::decoded_block_type output_block_type;
                    constexpr static const std::size_t output_block_bits = encoder_type::decoded_block_bits;

                    typedef typename stream_processor_mode<
                            Encoder>::encoder_type::decoding_finalizer_type finalizer_type;

                    static inline output_block_type process_block(const input_block_type &plaintext) {
                        return encoder_type::decode(plaintext);
                    }
                };
            }
        }
    }
}

#endif //CRYPTO3_PREPROCESSING_MODES_HPP
