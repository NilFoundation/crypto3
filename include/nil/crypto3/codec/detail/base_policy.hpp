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

#ifndef CRYPTO3_BASE_POLICY_HPP
#define CRYPTO3_BASE_POLICY_HPP

#include <array>

#include <boost/integer.hpp>

#include <boost/container/small_vector.hpp>

#include <nil/crypto3/multiprecision/cpp_int.hpp>
#include <nil/crypto3/multiprecision/integer.hpp>

#include <nil/crypto3/detail/inline_variable.hpp>

using namespace nil::crypto3::multiprecision;

namespace nil {
    namespace crypto3 {
        namespace codec {
            /*!
             * @struct base_decode_error
             * @brief Base exception class for all base64 decoding errors
             */
            template<std::uint8_t Version>
            struct base_decode_error : virtual boost::exception, virtual std::exception {};

            /*!
             * @struct wrong_input_range
             * @brief Thrown in case of the range passed to base64 encoding is larger than 4 or smaller than 1
             */
            template<std::uint8_t Version>
            struct wrong_input_range : virtual base_decode_error<Version> {};

            /*!
             * @struct wrong_input_symbol
             * @brief Thrown in case of the symbol passed to base58 encoding isn't in correct set for base58
             */
            template<std::uint8_t Version>
            struct wrong_input_symbol : virtual base_decode_error<Version> {};

            /*!
             * @struct non_base_input
             * @brief  Thrown when a non-base64 value (0-9, A-F) encountered when decoding.
             * Contains the offending character
             */
            template<std::uint8_t Version>
            struct non_base_input : virtual base_decode_error<Version> {};

            typedef boost::error_info<struct bad_char_, char> bad_char;

            namespace detail {

                template<std::size_t Version>
                class basic_base_policy {};

                template<>
                class basic_base_policy<32> {
                public:
                    typedef typename boost::uint_t<CHAR_BIT>::exact byte_type;

                    constexpr static const std::size_t decoded_value_bits = CHAR_BIT;
                    typedef byte_type decoded_value_type;

                    constexpr static const std::size_t encoded_value_bits = CHAR_BIT;
                    typedef byte_type encoded_value_type;

                    constexpr static const std::size_t decoded_block_values = 5;
                    constexpr static const std::size_t decoded_block_bits = decoded_block_values * decoded_value_bits;
                    typedef std::array<decoded_value_type, decoded_block_bits / CHAR_BIT> decoded_block_type;

                    constexpr static const std::size_t encoded_block_values = 8;
                    constexpr static const std::size_t encoded_block_bits = encoded_block_values * encoded_value_bits;
                    typedef std::array<encoded_value_type, encoded_block_bits / CHAR_BIT> encoded_block_type;

                    constexpr static const std::size_t padding_block_bits = 5;
                    constexpr static const std::size_t padding_bits = 6;

                    constexpr static const std::size_t constants_size = 32;
                    typedef std::array<byte_type, constants_size> constants_type;

                    CRYPTO3_INLINE_VARIABLE(constants_type, constants,
                                            ({'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K',
                                              'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
                                              'W', 'X', 'Y', 'Z', '2', '3', '4', '5', '6', '7'}));

                    constexpr static const std::size_t inverted_constants_size = constants_size * 8;
                    typedef std::array<byte_type, inverted_constants_size> inverted_constants_type;

                    CRYPTO3_INLINE_VARIABLE(
                        inverted_constants_type, inverted_constants,
                        ({0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x80, 0x80, 0xFF, 0xFF, 0x80, 0xFF,
                          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                          0xFF, 0xFF, 0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0xFF, 0xFF, 0xFF, 0xFF,
                          0xFF, 0x81, 0xFF, 0xFF, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
                          0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                          0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                          0xFF}));
                };

                template<>
                class basic_base_policy<64> {
                public:
                    typedef typename boost::uint_t<CHAR_BIT>::exact byte_type;

                    constexpr static const std::size_t decoded_value_bits = CHAR_BIT;
                    typedef byte_type decoded_value_type;

                    constexpr static const std::size_t encoded_value_bits = CHAR_BIT;
                    typedef byte_type encoded_value_type;

                    constexpr static const std::size_t decoded_block_values = 3;
                    constexpr static const std::size_t decoded_block_bits = decoded_block_values * decoded_value_bits;
                    typedef std::array<decoded_value_type, decoded_block_bits / CHAR_BIT> decoded_block_type;

                    constexpr static const std::size_t encoded_block_values = 4;
                    constexpr static const std::size_t encoded_block_bits = encoded_block_values * encoded_value_bits;
                    typedef std::array<encoded_value_type, encoded_block_bits / CHAR_BIT> encoded_block_type;

                    constexpr static const std::size_t padding_block_bits = 6;
                    constexpr static const std::size_t padding_bits = 8;

                    constexpr static const std::size_t constants_size = 64;
                    typedef std::array<byte_type, constants_size> constants_type;

                    CRYPTO3_INLINE_VARIABLE(constants_type, constants,
                                            ({'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
                                              'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
                                              'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
                                              'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
                                              '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'}));

                    constexpr static const std::size_t inverted_constants_size = constants_size * 4;
                    typedef std::array<byte_type, inverted_constants_size> inverted_constants_type;

                    CRYPTO3_INLINE_VARIABLE(
                        inverted_constants_type, inverted_constants,
                        ({0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x80, 0x80, 0xFF, 0xFF, 0x80, 0xFF,
                          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                          0xFF, 0xFF, 0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x3E, 0xFF,
                          0xFF, 0xFF, 0x3F, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0xFF, 0xFF,
                          0xFF, 0x81, 0xFF, 0xFF, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
                          0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                          0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21,
                          0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
                          0x31, 0x32, 0x33, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                          0xFF}));
                };

                template<std::size_t Version>
                class base_functions : public basic_base_policy<Version> {};

                template<>
                class base_functions<32> : public basic_base_policy<32> {
                public:
                    static inline encoded_block_type encode_block(const decoded_block_type &plaintext) {
                        encoded_block_type out = {0};

                        out[0] = constants()[(plaintext[0] & 0xF8U) >> 3];
                        out[1] = constants()[((plaintext[0] & 0x07U) << 2) | (plaintext[1] >> 6)];
                        out[2] = constants()[((plaintext[1] & 0x3EU) >> 1)];
                        out[3] = constants()[((plaintext[1] & 0x01U) << 4) | (plaintext[2] >> 4)];
                        out[4] = constants()[((plaintext[2] & 0x0FU) << 1) | (plaintext[3] >> 7)];
                        out[5] = constants()[((plaintext[3] & 0x7CU) >> 2)];
                        out[6] = constants()[((plaintext[3] & 0x03U) << 3) | (plaintext[4] >> 5)];
                        out[7] = constants()[plaintext[4] & 0x1FU];

                        return out;
                    }

                    static inline decoded_block_type decode_block(const encoded_block_type &encoded) {
                        decoded_block_type out = {0};
                        encoded_block_type output_buffer = {0};

                        auto oit = std::begin(output_buffer);

                        for (auto it = std::begin(encoded); it != std::end(encoded); ++it) {
                            const uint8_t bin = inverted_constants()[*it];

                            if (bin <= 0x3f) {
                                *oit++ = bin;
                            } else if (!(bin == 0x81 || bin == 0x80)) {
                                BOOST_THROW_EXCEPTION(non_base_input<32>());
                            }

                            /*
                             * If we're at the end of the input, pad with 0s and truncate
                             */
                            if (std::distance(it, encoded.end()) == 1 && std::distance(output_buffer.begin(), oit)) {
                                for (auto itr = oit;
                                     std::distance(output_buffer.begin(), itr) < decoded_block_bits / CHAR_BIT;
                                     ++itr) {
                                    *itr = 0x00U;
                                }

                                oit = output_buffer.end();
                            }

                            if (oit == output_buffer.end()) {
                                out[0] = (output_buffer[0] << 3U) | (output_buffer[1] >> 2U);
                                out[1] = (output_buffer[1] << 6U) | (output_buffer[2] << 1U) | (output_buffer[3] >> 4U);
                                out[2] = (output_buffer[3] << 4U) | (output_buffer[4] >> 1U);
                                out[3] = (output_buffer[4] << 7U) | (output_buffer[5] << 2U) | (output_buffer[6] >> 3U);
                                out[4] = (output_buffer[6] << 5U) | output_buffer[7];

                                oit = output_buffer.begin();
                            }
                        }

                        return out;
                    }
                };

                template<>
                class basic_base_policy<58> {
                public:
                    typedef typename boost::uint_t<CHAR_BIT>::exact byte_type;
                    typedef byte_type encoded_value_type;
                    typedef byte_type decoded_value_type;

                    constexpr static const std::size_t constants_size = 58;
                    constexpr static const std::size_t inverted_constants_size = 256;

                    typedef std::array<encoded_value_type, constants_size> constants_type;
                    typedef std::array<decoded_value_type, inverted_constants_size> inverted_constants_type;

                    CRYPTO3_INLINE_VARIABLE(constants_type, constants,
                                            ({'1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
                                              'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
                                              'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'm',
                                              'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'}));

                    CRYPTO3_INLINE_VARIABLE(inverted_constants_type, inverted_constants,
                        ({0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
                          0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
                          0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
                          0x80, 0x80, 0x80, 0x80, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x80, 0x80,
                          0x80, 0x80, 0x80, 0x80, 0x80, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x80, 0x11,
                          0x12, 0x13, 0x14, 0x15, 0x80, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
                          0x20, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
                          0x29, 0x2A, 0x2B, 0x80, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
                          0x37, 0x38, 0x39, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
                          0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
                          0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
                          0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
                          0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
                          0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
                          0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
                          0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
                          0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
                          0x80}));

                    constexpr static const std::size_t decoded_value_bits = CHAR_BIT;

                    constexpr static const std::size_t encoded_value_bits = CHAR_BIT;

                    constexpr static const std::size_t decoded_block_values = 1;
                    constexpr static const std::size_t decoded_block_bits = decoded_block_values * decoded_value_bits;
                    typedef boost::container::small_vector<decoded_value_type, decoded_block_values> decoded_block_type;

                    constexpr static const std::size_t encoded_block_values = 1;
                    constexpr static const std::size_t encoded_block_bits = encoded_block_values * encoded_value_bits;
                    typedef boost::container::small_vector<encoded_value_type, encoded_block_values> encoded_block_type;
                };

                template<>
                class base_functions<58> : public basic_base_policy<58> {
                public:
                    template<typename NumberType = cpp_int>
                    static inline encoded_block_type encode_block(const decoded_block_type &plaintext) {
                        encoded_block_type out;
                        std::size_t csint = basic_base_policy<58>::constants_size;
                        NumberType v = 0, q = 0, r = 0, cs(csint);

                        import_bits(v, plaintext.begin(), plaintext.end(), encoded_value_bits);
                        while (v != 0) {
                            divide_qr(v, cs, q, r);
                            out.emplace_back(constants()[r.template convert_to<std::uint8_t>()]);
                            v = q;
                        }
                        return out;
                    }

                    template<typename NumberType = cpp_int>
                    static inline decoded_block_type decode_block(const encoded_block_type &plaintext) {
                        decoded_block_type out;
                        std::size_t csint = basic_base_policy<58>::constants_size;
                        NumberType v = 0;

                        for (const typename encoded_block_type::value_type &c : plaintext) {
                            if (c == ' ' || c == '\n') {
                                continue;
                            }
                            const size_t idx = inverted_constants()[c];

                            if (idx == 0x80) {
                                throw wrong_input_symbol<58>();
                                // throw std::invalid_argument("Invalid base58");
                            }
                            v *= csint;
                            v += idx;
                        }
                        export_bits(v, std::inserter(out, out.end()), decoded_value_bits);
                        std::reverse(out.begin(), out.end());
                        return out;
                    }
                };

                template<>
                class base_functions<64> : public basic_base_policy<64> {
                public:
                    static inline encoded_block_type encode_block(const decoded_block_type &plaintext) {
                        encoded_block_type output = {0};

                        output[0] = constants()[(plaintext[0] & 0xfcU) >> 2U];
                        output[1] = constants()[((plaintext[0] & 0x03U) << 4U) | (plaintext[1] >> 4U)];
                        output[2] = constants()[((plaintext[1] & 0x0fU) << 2U) | (plaintext[2] >> 6U)];
                        output[3] = constants()[plaintext[2] & 0x3fU];

                        return output;
                    }

                    static inline decoded_block_type decode_block(const encoded_block_type &encoded) {
                        decoded_block_type out = {0};
                        encoded_block_type output_buffer = {0};

                        typename decoded_block_type::iterator oit = std::begin(output_buffer);

                        for (typename encoded_block_type::const_iterator it = std::begin(encoded);
                             it != std::end(encoded);
                             ++it) {
                            const uint8_t bin = inverted_constants()[*it];

                            if (bin <= 0x3f) {
                                *oit++ = bin;
                            } else if (!(bin == 0x81 || bin == 0x80)) {
                                BOOST_THROW_EXCEPTION(non_base_input<64>());
                            }

                            /*
                             * If we're at the end of the input, pad with 0s and truncate
                             */
                            if (std::distance(it, encoded.end()) == 1 && std::distance(output_buffer.begin(), oit)) {
                                for (auto itr = oit;
                                     std::distance(output_buffer.begin(), itr) < decoded_block_bits / CHAR_BIT;
                                     ++itr) {
                                    *itr = 0x00;
                                }

                                oit = output_buffer.end();
                            }

                            if (oit == output_buffer.end()) {
                                out[0] = (output_buffer[0] << 2U) | (output_buffer[1] >> 4U);
                                out[1] = (output_buffer[1] << 4U) | (output_buffer[2] >> 2U);
                                out[2] = (output_buffer[2] << 6U) | output_buffer[3];

                                oit = output_buffer.begin();
                            }
                        }

                        return out;
                    }
                };

                template<std::size_t Version>
                class base_policy : public base_functions<Version> {
                public:
                };
            }    // namespace detail
        }        // namespace codec
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BASE_POLICY_HPP
