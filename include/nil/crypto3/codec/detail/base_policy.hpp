//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BASE_POLICY_HPP
#define CRYPTO3_BASE_POLICY_HPP

#include <array>

#include <boost/integer.hpp>

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/integer.hpp>

using namespace boost::multiprecision;

namespace nil {
    namespace crypto3 {
        namespace codec {
            /*!
             * @struct base_decode_error
             * @brief Base exception class for all base64 decoding errors
             */
            template<std::uint8_t Version>
            struct base_decode_error : virtual boost::exception, virtual std::exception {

            };

            /*!
             * @struct wrong_input_range
             * @brief Thrown in case of the range passed to base64 encoding is larger than 4 or smaller than 1.
             */
            template<std::uint8_t Version>
            struct wrong_input_range : virtual base_decode_error<Version> {

            };

            /*!
             * @struct non_base_input
             * @brief  Thrown when a non-base64 value (0-9, A-F) encountered when decoding.
             * Contains the offending character
             */
            template<std::uint8_t Version>
            struct non_base_input : virtual base_decode_error<Version> {

            };

            typedef boost::error_info<struct bad_char_, char> bad_char;

            namespace detail {

                template<std::size_t Version>
                class basic_base_policy {

                };

                template<>
                class basic_base_policy<32> {
                public:
                    typedef typename boost::uint_t<CHAR_BIT>::exact byte_type;

                    constexpr static const std::size_t decoded_block_bits = 5 * CHAR_BIT;
                    typedef std::array<byte_type, decoded_block_bits / CHAR_BIT> decoded_block_type;

                    constexpr static const std::size_t encoded_block_bits = 8 * CHAR_BIT;
                    typedef std::array<byte_type, encoded_block_bits / CHAR_BIT> encoded_block_type;

                    constexpr static const std::size_t padding_block_bits = 5;
                    constexpr static const std::size_t padding_bits = 6;

                    constexpr static const std::size_t constants_size = 32;
                    typedef std::array<byte_type, constants_size> constants_type;

                    constexpr static const constants_type constants = {
                            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R',
                            'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '2', '3', '4', '5', '6', '7'
                    };

                    constexpr static const std::size_t inverted_constants_size = constants_size * 8;
                    typedef std::array<byte_type, inverted_constants_size> inverted_constants_type;

                    constexpr static const inverted_constants_type inverted_constants = {
                            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x80, 0x80, 0xFF, 0xFF, 0x80, 0xFF,
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
                            0xFF
                    };
                };

                template<>
                class basic_base_policy<64> {
                public:
                    typedef typename boost::uint_t<CHAR_BIT>::exact byte_type;

                    constexpr static const std::size_t decoded_block_bits = 3 * CHAR_BIT;
                    typedef std::array<byte_type, decoded_block_bits / CHAR_BIT> decoded_block_type;

                    constexpr static const std::size_t encoded_block_bits = 4 * CHAR_BIT;
                    typedef std::array<byte_type, encoded_block_bits / CHAR_BIT> encoded_block_type;

                    constexpr static const std::size_t padding_block_bits = 6;
                    constexpr static const std::size_t padding_bits = 8;

                    constexpr static const std::size_t constants_size = 64;
                    typedef std::array<byte_type, constants_size> constants_type;

                    constexpr static const constants_type constants = {
                            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R',
                            'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
                            'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1',
                            '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
                    };

                    constexpr static const std::size_t inverted_constants_size = constants_size * 4;
                    typedef std::array<byte_type, inverted_constants_size> inverted_constants_type;

                    constexpr static const inverted_constants_type inverted_constants = {
                            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x80, 0x80, 0xFF, 0xFF, 0x80, 0xFF,
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
                            0xFF
                    };
                };

                constexpr typename basic_base_policy<32>::constants_type const
                        basic_base_policy<32>::constants;

                constexpr typename basic_base_policy<64>::constants_type const
                        basic_base_policy<64>::constants;

                constexpr typename basic_base_policy<32>::inverted_constants_type const
                        basic_base_policy<32>::inverted_constants;

                constexpr typename basic_base_policy<64>::inverted_constants_type const
                        basic_base_policy<64>::inverted_constants;

                template<std::size_t Version>
                class base_functions : public basic_base_policy<Version> {

                };

                template<>
                class base_functions<32> : public basic_base_policy<32> {
                public:
                    static inline encoded_block_type encode_block(const decoded_block_type &plaintext) {
                        encoded_block_type out = {0};

                        out[0] = constants[(plaintext[0] & 0xF8U) >> 3];
                        out[1] = constants[((plaintext[0] & 0x07U) << 2) | (plaintext[1] >> 6)];
                        out[2] = constants[((plaintext[1] & 0x3EU) >> 1)];
                        out[3] = constants[((plaintext[1] & 0x01U) << 4) | (plaintext[2] >> 4)];
                        out[4] = constants[((plaintext[2] & 0x0FU) << 1) | (plaintext[3] >> 7)];
                        out[5] = constants[((plaintext[3] & 0x7CU) >> 2)];
                        out[6] = constants[((plaintext[3] & 0x03U) << 3) | (plaintext[4] >> 5)];
                        out[7] = constants[plaintext[4] & 0x1FU];

                        return out;
                    }

                    static inline decoded_block_type decode_block(const encoded_block_type &encoded) {
                        decoded_block_type out = {0};
                        encoded_block_type output_buffer = {0};

                        auto oit = std::begin(output_buffer);

                        for (auto it = std::begin(encoded); it != std::end(encoded); ++it) {
                            const uint8_t bin = inverted_constants[*it];

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
                                     std::distance(output_buffer.begin(), itr) < decoded_block_bits / CHAR_BIT; ++itr) {
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

                    constexpr static const std::size_t decoded_block_bits = 0;
                    typedef std::vector<byte_type> decoded_block_type;

                    constexpr static const std::size_t encoded_block_bits = 0;
                    typedef std::vector<byte_type> encoded_block_type;

                    constexpr static const std::size_t constants_size = 64;
                    typedef std::array<byte_type, constants_size> constants_type;

                    constexpr static const constants_type constants = {
                            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                            'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
                            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r',
                            's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
                    };
                };

                constexpr typename basic_base_policy<58>::constants_type const
                        basic_base_policy<58>::constants;

                template<>
                class base_functions<58> : public basic_base_policy<58> {
                public:
                    static inline encoded_block_type encode_block(const decoded_block_type &plaintext) {
                        encoded_block_type out;

                        cpp_int v = 0, q = 0, r = 0, cs(constants_size);

                        import_bits(v, plaintext.begin(), plaintext.end());

                        while (v != 0) {
                            divide_qr(v, cs, q, r);
                            out.emplace_back(constants[static_cast<std::size_t>(r)]);
                            v = q;
                        }

                        return out;
                    }

                    static inline decoded_block_type decode_block(const encoded_block_type &plaintext) {
//                        const auto base58 = BASE58_ALPHA();
//
//                        const size_t leading_zeros = count_leading_zeros(input, input_length, base58[0]);
//
//                        cpp_int v;
//
//                        for (size_t i = leading_zeros; i != input_length; ++i) {
//                            const char c = input[i];
//
//                            if (c == ' ' || c == '\n') {
//                                continue;
//                            }
//
//                            const size_t idx = base58.code_for(c);
//
//                            if (idx == 0x80) {
//                                throw Decoding_Error("Invalid base58");
//                            }
//
//                            v *= base58.radix();
//                            v += idx;
//                        }
//
//                        std::vector<uint8_t> output(v.bytes() + leading_zeros);
//                        v.binary_encode(output.data() + leading_zeros);
//                        return output;
                    }

                protected:
                    template<typename T, typename Z>
                    static inline std::size_t count_leading_zeros(const T input[], size_t input_length, Z zero) {
                        size_t leading_zeros = 0;

                        while (leading_zeros < input_length && input[leading_zeros] == zero) {
                            leading_zeros += 1;
                        }

                        return leading_zeros;
                    }
                };

                template<>
                class base_functions<64> : public basic_base_policy<64> {
                public:
                    static inline encoded_block_type encode_block(const decoded_block_type &plaintext) {
                        encoded_block_type output = {0};

                        output[0] = constants[(plaintext[0] & 0xfcU) >> 2U];
                        output[1] = constants[((plaintext[0] & 0x03U) << 4U) | (plaintext[1] >> 4U)];
                        output[2] = constants[((plaintext[1] & 0x0fU) << 2U) | (plaintext[2] >> 6U)];
                        output[3] = constants[plaintext[2] & 0x3fU];

                        return output;
                    }

                    static inline decoded_block_type decode_block(const encoded_block_type &encoded) {
                        decoded_block_type out = {0};
                        encoded_block_type output_buffer = {0};

                        typename decoded_block_type::iterator oit = std::begin(output_buffer);

                        for (typename encoded_block_type::const_iterator it = std::begin(encoded);
                             it != std::end(encoded); ++it) {
                            const uint8_t bin = inverted_constants[*it];

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
                                     std::distance(output_buffer.begin(), itr) < decoded_block_bits / CHAR_BIT; ++itr) {
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
            }
        }
    }
}

#endif //CRYPTO3_BASE_POLICY_HPP
