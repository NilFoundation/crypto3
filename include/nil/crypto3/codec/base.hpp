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

#ifndef CRYPTO3_CODEC_BASE_HPP
#define CRYPTO3_CODEC_BASE_HPP

#include <iterator>
#include <string>

#include <nil/crypto3/codec/detail/base_policy.hpp>
#include <nil/crypto3/codec/detail/codec_modes.hpp>
#include <nil/crypto3/codec/detail/fixed_block_stream_processor.hpp>
#include <nil/crypto3/codec/detail/varlength_block_stream_processor.hpp>

#include <nil/crypto3/codec/codec_state.hpp>

#include <boost/range/begin.hpp>
#include <boost/range/end.hpp>

#include <boost/exception/exception.hpp>
#include <boost/exception/info.hpp>
#include <boost/throw_exception.hpp>

namespace nil {
    namespace crypto3 {
        namespace codec {
            namespace detail {
                template<bool>
                struct static_range;
            }

            /*!
             * @brief Base encoder preprocessor functor
             * @ingroup codec
             * @tparam Version Base encoder version selector. Available values are: 32, 58, 64
             *
             * @note This particular implementation gets selected with Version == 58.
             */
            template<std::size_t Version, typename = detail::static_range<true>>
            struct base_encode_preprocessor {
                typedef detail::base_policy<Version> policy_type;

                /*!
                 * @brief Constructs base encoder preprocessor
                 * @param leading_zeros Leading zeros amount to be processed
                 */
                base_encode_preprocessor(std::size_t leading_zeros = 0) : leading_zeros(leading_zeros) {}

                template<typename T>
                void operator()(const T &block) {
                    typename T::const_iterator itr = block.cbegin();
                    while (*itr == '\0' && itr != block.cend()) {
                        ++itr;
                    }
                    leading_zeros = std::distance(block.begin(), itr);
                }

                std::size_t leading_zeros;
            };

            /*!
             * @brief Base encoder finalizer functor
             * @ingroup codec
             * @tparam Version Base encoder version selector. Available values are: 32, 58, 64
             *
             * @note This particular implementation gets selected with Version == 58.
             */
            template<std::size_t Version, typename = detail::static_range<true>>
            struct base_encode_finalizer {
                typedef detail::base_policy<Version> policy_type;

                /*!
                 * @brief Constructs the base encoder finalizer
                 * @param leading_zeros Leading zeros amount to be processed
                 */
                base_encode_finalizer(std::size_t leading_zeros = 0) : leading_zeros(leading_zeros) {
                }

                /*!
                 * @brief Base encoding padding function. Fills remaining empty bits with '0'.
                 * @tparam T Input container type. Assumed to meet the requirements of Container,
                 * AllocatorAwareContainer and SequenceContainer concepts.
                 * @param t Input container
                 */
                template<typename T>
                void operator()(T &t) {
                    while (leading_zeros) {
                        t.push_back(policy_type::constants()[0]);
                        leading_zeros--;
                    }
                }

                std::size_t leading_zeros;
            };

            /*!
             * @brief Base encoder preprocessor functor
             * @ingroup codec
             * @tparam Version Base encoder version selector. Available values are: 32, 58, 64
             *
             * @note This particular implementation gets selected with Version != 58.
             */
            template<std::size_t Version>
            struct base_encode_preprocessor<Version, detail::static_range<!(Version % 32)>> {
                typedef detail::base_policy<Version> policy_type;

                base_encode_preprocessor()  {}

                template<typename T>
                void operator()(T &t) {}
            };

            /*!
             * @brief
             * @ingroup codec
             * @tparam Version
             */
            template<std::size_t Version>
            struct base_encode_finalizer<Version, detail::static_range<!(Version % 32)>> {
                typedef detail::base_policy<Version> policy_type;

                /*!
                 * @param input_remaining_bits Bits remaining unprocessed in block
                 */
                base_encode_finalizer(std::size_t input_remaining_bits = 0) : remaining_bits(input_remaining_bits) {
                }

                /*!
                 * @brief Base encoding padding function. Fills remaining empty bits with '='.
                 * @tparam T Input container type. Assumed to meet the requirements of Container,
                 * AllocatorAwareContainer and SequenceContainer concepts.
                 * @param t
                 */
                template<typename T>
                void operator()(T &t) {
                    for (typename T::iterator out = t.end() - 1; remaining_bits >= policy_type::padding_bits;
                         remaining_bits -= policy_type::padding_block_bits) {
                        *out-- = '=';
                    }
                }

                std::size_t remaining_bits;    ///< Bits remaining unprocessed in block
            };

            /*!
             * @brief
             * @ingroup codec
             * @tparam Version
             */
            template<std::size_t Version, typename = detail::static_range<true>>
            struct base_decode_preprocessor {
                typedef detail::base_policy<Version> policy_type;

                /*!
                 * @brief
                 * @param leading_zeros
                 */
                base_decode_preprocessor(std::size_t leading_zeros = 0) : leading_zeros(leading_zeros) {}

                template<typename T>
                void operator()(const T &block) {
                    typename T::const_iterator itr = block.cbegin();
                    while (*itr == '1') {
                        ++itr;
                    }
                    leading_zeros = std::distance(block.begin(), itr);
                }

                std::size_t leading_zeros;
            };

            template<std::size_t Version>
            struct base_decode_preprocessor<Version, detail::static_range<!(Version % 32)>> {
                typedef detail::base_policy<Version> policy_type;

                base_decode_preprocessor() { }

                template<typename T>
                void operator()(T &t) { }
            };

            /*!
             * @brief Base decoder finalizer functor
             * @ingroup codec
             * @tparam Version Base encoder version selector. Available values are: 32, 58, 64
             *
             * Base decoder finalizer
             *
             * @note Finalizer is implemented under assumption it gets applied to the byte storage
             */
            template<std::size_t Version, typename = detail::static_range<true>>
            struct base_decode_finalizer {
                typedef detail::base_policy<Version> policy_type;

                /*!
                 * @brief Constructs base decoder finalizer
                 * @param leading_zeros Defines data stream leading zeros
                 */
                base_decode_finalizer(std::size_t leading_zeros) : leading_zeros(leading_zeros) {
                }

                /*!
                 * @brief Base decoder padding function. Fills remaining empty bits with '='.
                 * @tparam T Input container type. Assumed to meet the requirements of Container,
                 * AllocatorAwareContainer and SequenceContainer concepts.
                 * @param t
                 */
                template<typename T>
                void operator()(T &t) {
                    while (leading_zeros) {
                        t.push_back(policy_type::inverted_constants()['1']);
                        leading_zeros--;
                    }
                }

                std::size_t leading_zeros;
            };

            template<std::size_t Version>
            struct base_decode_finalizer<Version, detail::static_range<!(Version % 32)>> {
                typedef detail::base_policy<Version> policy_type;

                /*!
                 * @param input_remaining_bits
                 */
                base_decode_finalizer(std::size_t input_remaining_bits = 0) : remaining_bits(input_remaining_bits) {
                }

                /*!
                 * @brief Base decoder padding function. Fills remaining empty bits with '='.
                 * @tparam T Input container type. Assumed to meet the requirements of Container,
                 * AllocatorAwareContainer and SequenceContainer concepts.
                 * @param t
                 */
                template<typename T>
                void operator()(T &t) {
                    int new_size = t.size();
                    for (typename T::iterator out = t.end() - 1; *out == '\0'; --out, --new_size) {}
                    t.resize(new_size);
                }

                std::size_t remaining_bits;
            };

            /*!
             * @brief Base codec implements Base-family encoding. Meets the requirements of Codec.
             * @ingroup codec
             * @tparam Version Base encoder version selector. Available values are: 32, 58, 64
             * @note This particular implementation gets resolved for base58
             */
            template<std::size_t Version, typename = detail::static_range<true>>
            class base {
                typedef typename detail::base_policy<Version> policy_type;

            public:
                typedef base_encode_finalizer<Version> encoding_finalizer_type;
                typedef base_decode_finalizer<Version> decoding_finalizer_type;
                typedef base_encode_preprocessor<Version> encoding_preprocessor_type;
                typedef base_decode_preprocessor<Version> decoding_preprocessor_type;

                typedef typename detail::isomorphic_encoding_mode<base<Version>> stream_encoder_type;
                typedef typename detail::isomorphic_decoding_mode<base<Version>> stream_decoder_type;

                constexpr static const std::size_t encoded_value_bits = policy_type::encoded_value_bits;
                typedef typename policy_type::encoded_value_type encoded_value_type;

                constexpr static const std::size_t decoded_value_bits = policy_type::decoded_value_bits;
                typedef typename policy_type::decoded_value_type decoded_value_type;

                constexpr static const std::size_t encoded_block_values = policy_type::encoded_block_values;
                constexpr static const std::size_t encoded_block_bits = policy_type::encoded_block_bits;
                typedef typename policy_type::encoded_block_type encoded_block_type;

                constexpr static const std::size_t decoded_block_values = policy_type::decoded_block_values;
                constexpr static const std::size_t decoded_block_bits = policy_type::decoded_block_bits;
                typedef typename policy_type::decoded_block_type decoded_block_type;

                /*!
                 * @brief Encodes single atomic data block.
                 * @param plaintext Input plaintext.
                 * @return encoded atomic data block.
                 */
                inline static encoded_block_type encode(const decoded_block_type &plaintext) {
                    return policy_type::encode_block(plaintext);
                }

                /*!
                 * @brief Decodes single atomic data block.
                 * @param plaintext Input plaintext.
                 * @return decoded atomic data block.
                 */
                inline static decoded_block_type decode(const encoded_block_type &encoded) {
                    return policy_type::decode_block(encoded);
                }

                template<typename ProcessingMode>
                using accumulator_mode_type = accumulators::postprocessing_accumulator_mode<ProcessingMode>;

                template<typename ProcessingMode, typename StateAccumulator, std::size_t ValueBits>
                struct stream_processor {
                    struct params_type {
                        typedef typename stream_endian::little_octet_big_bit endian_type;

                        constexpr static const std::size_t value_bits = ValueBits;
                        constexpr static const std::size_t length_bits = ProcessingMode::input_block_bits;
                    };

                    typedef varlength_block_stream_processor<ProcessingMode, StateAccumulator, params_type> type;
                };
            };

            /*!
             * @brief Base codec implements Base-family encoding. Meets the requirements of Codec.
             * @ingroup codec
             * @tparam Version Base encoder version selector. Available values are: 32, 58, 64.
             * @note This particular implementation is defined for base32 and base64
             */
            template<std::size_t Version>
            class base<Version, detail::static_range<!(Version % 32)>> {
                typedef typename detail::base_policy<Version> policy_type;

            public:
                typedef base_encode_finalizer<Version> encoding_finalizer_type;
                typedef base_decode_finalizer<Version> decoding_finalizer_type;
                typedef base_encode_preprocessor<Version> encoding_preprocessor_type;
                typedef base_decode_preprocessor<Version> decoding_preprocessor_type;

                typedef typename detail::isomorphic_encoding_mode<base<Version>> stream_encoder_type;
                typedef typename detail::isomorphic_decoding_mode<base<Version>> stream_decoder_type;

                constexpr static const std::size_t encoded_value_bits = policy_type::encoded_value_bits;
                typedef typename policy_type::encoded_value_type encoded_value_type;

                constexpr static const std::size_t decoded_value_bits = policy_type::decoded_value_bits;
                typedef typename policy_type::decoded_value_type decoded_value_type;

                constexpr static const std::size_t encoded_block_values = policy_type::encoded_block_values;
                constexpr static const std::size_t encoded_block_bits = policy_type::encoded_block_bits;
                typedef typename policy_type::encoded_block_type encoded_block_type;

                constexpr static const std::size_t decoded_block_values = policy_type::decoded_block_values;
                constexpr static const std::size_t decoded_block_bits = policy_type::decoded_block_bits;
                typedef typename policy_type::decoded_block_type decoded_block_type;

                /*!
                 * @brief Encodes single atomic data block.
                 * @param plaintext Input plaintext.
                 * @return encoded atomic data block.
                 */
                inline static encoded_block_type encode(const decoded_block_type &plaintext) {
                    return policy_type::encode_block(plaintext);
                }

                /*!
                 * @brief Decodes single atomic data block.
                 * @param plaintext Input plaintext.
                 * @return decoded atomic data block.
                 */
                inline static decoded_block_type decode(const encoded_block_type &encoded) {
                    return policy_type::decode_block(encoded);
                }

                template<typename ProcessingMode>
                using accumulator_mode_type = accumulators::preprocessing_accumulator_mode<ProcessingMode>;

                template<typename ProcessingMode, typename StateAccumulator, std::size_t ValueBits>
                struct stream_processor {
                    struct params_type {
                        typedef typename stream_endian::little_octet_big_bit endian_type;

                        constexpr static const std::size_t value_bits = ValueBits;
                        constexpr static const std::size_t length_bits = ProcessingMode::input_block_bits;
                    };

                    typedef fixed_block_stream_processor<ProcessingMode, StateAccumulator, params_type> type;
                };
            };

            /*!
             * @brief Type alias for base<32>
             * @ingroup codec
             */
            typedef base<32> base32;

            /*!
             * @brief Type alias for base<58>
             * @ingroup codec
             */
            typedef base<58> base58;

            /*!
             * @brief Type alias for base<64>
             * @ingroup codec
             */
            typedef base<64> base64;
        }    // namespace codec
    }        // namespace crypto3
}    // namespace nil

#endif
