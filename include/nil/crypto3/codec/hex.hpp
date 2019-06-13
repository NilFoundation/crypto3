//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HEX_CODEC_H_
#define CRYPTO3_HEX_CODEC_H_

#include <iterator>
#include <stdexcept>
#include <type_traits>

#include <nil/crypto3/codec/detail/hex_policy.hpp>
#include <nil/crypto3/codec/detail/codec_modes.hpp>
#include <nil/crypto3/codec/detail/block_state_preprocessor.hpp>

#include <nil/crypto3/codec/codec_state.hpp>

#include <boost/range/begin.hpp>
#include <boost/range/end.hpp>

#include <boost/exception/exception.hpp>
#include <boost/exception/info.hpp>
#include <boost/throw_exception.hpp>

namespace nil {
    namespace crypto3 {
        namespace codec {

            /*!
             * @struct hex_decode_error
             * @brief  Base exception class for all hex decoding errors
             */
            struct hex_decode_error : virtual boost::exception, virtual std::exception {
            };

            /*!
             * @struct not_enough_input
             * @brief  Thrown when the input sequence unexpectedly ends
             * */
            struct not_enough_input : virtual hex_decode_error {
            };

            /*!
             * @struct non_hex_input
             * @brief  Thrown when a non-hex value (0-9, A-F) encountered when decoding.
             * Contains the offending character
             */
            struct non_hex_input : virtual hex_decode_error {

            };
            typedef boost::error_info<struct bad_char_, char> bad_char;

            namespace detail {
                /*!
                 * @brief Own detail::hex_iterator_traits class allows to get inside of some kinds of output iterator and get the
                 * type to write in a hacky way.
                 * @tparam Iterator
                 */
                template<typename Iterator>
                struct hex_iterator_traits {
                    typedef typename std::iterator_traits<Iterator>::value_type value_type;
                };

                template<typename Container>
                struct hex_iterator_traits<std::back_insert_iterator<Container> > {
                    typedef typename Container::value_type value_type;
                };

                template<typename Container>
                struct hex_iterator_traits<std::front_insert_iterator<Container> > {
                    typedef typename Container::value_type value_type;
                };

                template<typename Container>
                struct hex_iterator_traits<std::insert_iterator<Container> > {
                    typedef typename Container::value_type value_type;
                };

                /*!
                 *
                 * @tparam T
                 * @tparam charType
                 * @tparam traits
                 *
                 * @note ostream_iterators have three template parameters.
                 * The first one is the output type, the second one is the character type of
                 * the underlying stream, the third is the character traits.
                 * We only care about the first one.
                 */
                template<typename T, typename charType, typename traits>
                struct hex_iterator_traits<std::ostream_iterator<T, charType, traits> > {
                    typedef T value_type;
                };

                template<typename Iterator>
                inline static bool iter_end(Iterator current, Iterator last) {
                    return current == last;
                }

                template<typename T>
                inline static bool ptr_end(const T *ptr, const T * /*end*/ ) {
                    return *ptr == '\0';
                }
            }

            /*!
             * @brief Hex encoder
             * @tparam Mode Hex encoder mode selector. Defines which alphabet to use - upper or lower
             */
            template<typename Mode = mode::upper>
            class hex {
                typedef typename detail::hex_policy<Mode> policy_type;
            public:

                typedef typename policy_type::mode_type mode_type;

                typedef nop_finalizer encoding_finalizer_type;
                typedef nop_finalizer decoding_finalizer_type;

                typedef typename detail::isomorphic_encoding_mode<hex<Mode>> stream_encoder_type;
                typedef typename detail::isomorphic_decoding_mode<hex<Mode>> stream_decoder_type;

                constexpr static const std::size_t encoded_value_bits = policy_type::encoded_value_bits;
                typedef typename policy_type::encoded_value_type encoded_value_type;

                constexpr static const std::size_t decoded_value_bits = policy_type::decoded_value_bits;
                typedef typename policy_type::decoded_value_type decoded_value_type;

                typedef typename policy_type::encoded_block_type encoded_block_type;
                constexpr static const std::uint8_t encoded_block_bits = policy_type::encoded_block_bits;

                typedef typename policy_type::decoded_block_type decoded_block_type;
                constexpr static const std::uint8_t decoded_block_bits = policy_type::decoded_block_bits;

                static encoded_block_type encode(const decoded_block_type &plaintext) {
                    BOOST_STATIC_ASSERT(std::tuple_size<decoded_block_type>::value == 1);

                    encoded_block_type res = {0};

                    typename encoded_block_type::iterator p = res.end();
                    typename decoded_block_type::value_type integral_plaintext = plaintext.back();

                    for (std::size_t i = 0;
                         i < encoded_block_bits / CHAR_BIT && p != res.begin(); ++i, integral_plaintext >>= 4) {
                        *--p = policy_type::constants[integral_plaintext & 0x0F];
                    }

                    return res;
                }

                static decoded_block_type decode(const encoded_block_type &plaintext) {
                    BOOST_STATIC_ASSERT(std::tuple_size<decoded_block_type>::value == 1);

                    decoded_block_type res = {0};

                    for (const typename encoded_block_type::value_type &v : plaintext) {
                        res[0] = (16 * res[0]) + hex_char_to_int(v);
                    }

                    return res;
                }

                template<typename ProcessingMode, typename StateAccumulator, std::size_t ValueBits>
                struct stream_processor {
                    struct params_type {
                        typedef typename stream_endian::little_octet_big_bit endian_type;

                        constexpr static const std::size_t value_bits = ValueBits;
                        constexpr static const std::size_t length_bits = CHAR_BIT * CHAR_BIT;
                    };

                    typedef block_state_preprocessor<ProcessingMode, StateAccumulator, params_type> type;
                };

            protected:
                template<typename T>
                static uint8_t hex_char_to_int(T val) {
                    char c = static_cast<char>(val);
                    uint8_t retval = 0;
                    if (c >= '0' && c <= '9') {
                        retval = static_cast<uint8_t>(c - '0');
                    } else if (c >= 'A' && c <= 'F') {
                        retval = static_cast<uint8_t>(c - 'A' + 10);
                    } else if (c >= 'a' && c <= 'f') {
                        retval = static_cast<uint8_t>(c - 'a' + 10);
                    } else {
                        BOOST_THROW_EXCEPTION(non_hex_input() << bad_char(c));
                    }
                    return static_cast<char>(retval);
                }
            };
        }
    }
}

#endif
