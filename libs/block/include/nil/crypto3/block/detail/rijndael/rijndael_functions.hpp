//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_RIJNDAEL_FUNCTIONS_CPP_HPP
#define CRYPTO3_RIJNDAEL_FUNCTIONS_CPP_HPP

#include <array>

#include <nil/crypto3/block/algorithm/copy_n_if.hpp>

#include <nil/crypto3/detail/basic_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace detail {
                template<std::size_t WordBits, std::size_t BlockBits>
                struct rijndael_functions : public ::nil::crypto3::detail::basic_functions<WordBits> {
                    constexpr static const std::size_t byte_bits =
                        ::nil::crypto3::detail::basic_functions<WordBits>::byte_bits;
                    typedef typename ::nil::crypto3::detail::basic_functions<WordBits>::byte_type byte_type;

                    constexpr static const std::size_t word_bits =
                        ::nil::crypto3::detail::basic_functions<WordBits>::word_bits;
                    constexpr static const std::size_t word_bytes = word_bits / byte_bits;
                    typedef std::array<byte_type, word_bytes> word_type;

                    constexpr static const std::size_t constants_size = 256;
                    typedef std::array<byte_type, constants_size> constants_type;
                    typedef std::array<word_type, constants_size> prefetched_constants_type;

                    BOOST_ALIGNMENT(64)
                    constexpr static const constants_type log_ = {
                        0,   0,   25,  1,   50,  2,   26,  198, 75,  199, 27,  104, 51,  238, 223, 3,   100, 4,   224,
                        14,  52,  141, 129, 239, 76,  113, 8,   200, 248, 105, 28,  193, 125, 194, 29,  181, 249, 185,
                        39,  106, 77,  228, 166, 114, 154, 201, 9,   120, 101, 47,  138, 5,   33,  15,  225, 36,  18,
                        240, 130, 69,  53,  147, 218, 142, 150, 143, 219, 189, 54,  208, 206, 148, 19,  92,  210, 241,
                        64,  70,  131, 56,  102, 221, 253, 48,  191, 6,   139, 98,  179, 37,  226, 152, 34,  136, 145,
                        16,  126, 110, 72,  195, 163, 182, 30,  66,  58,  107, 40,  84,  250, 133, 61,  186, 43,  121,
                        10,  21,  155, 159, 94,  202, 78,  212, 172, 229, 243, 115, 167, 87,  175, 88,  168, 80,  244,
                        234, 214, 116, 79,  174, 233, 213, 231, 230, 173, 232, 44,  215, 117, 122, 235, 22,  11,  245,
                        89,  203, 95,  176, 156, 169, 81,  160, 127, 12,  246, 111, 23,  196, 73,  236, 216, 67,  31,
                        45,  164, 118, 123, 183, 204, 187, 62,  90,  251, 96,  177, 134, 59,  82,  161, 108, 170, 85,
                        41,  157, 151, 178, 135, 144, 97,  190, 220, 252, 188, 149, 207, 205, 55,  63,  91,  209, 83,
                        57,  132, 60,  65,  162, 109, 71,  20,  42,  158, 93,  86,  242, 211, 171, 68,  17,  146, 217,
                        35,  32,  46,  137, 180, 124, 184, 38,  119, 153, 227, 165, 103, 74,  237, 222, 197, 49,  254,
                        24,  13,  99,  140, 128, 192, 247, 112, 7};

                    BOOST_ALIGNMENT(64)
                    constexpr static const constants_type pow_ = {
                        1,   3,   5,   15,  17,  51,  85,  255, 26,  46,  114, 150, 161, 248, 19,  53,  95,  225, 56,
                        72,  216, 115, 149, 164, 247, 2,   6,   10,  30,  34,  102, 170, 229, 52,  92,  228, 55,  89,
                        235, 38,  106, 190, 217, 112, 144, 171, 230, 49,  83,  245, 4,   12,  20,  60,  68,  204, 79,
                        209, 104, 184, 211, 110, 178, 205, 76,  212, 103, 169, 224, 59,  77,  215, 98,  166, 241, 8,
                        24,  40,  120, 136, 131, 158, 185, 208, 107, 189, 220, 127, 129, 152, 179, 206, 73,  219, 118,
                        154, 181, 196, 87,  249, 16,  48,  80,  240, 11,  29,  39,  105, 187, 214, 97,  163, 254, 25,
                        43,  125, 135, 146, 173, 236, 47,  113, 147, 174, 233, 32,  96,  160, 251, 22,  58,  78,  210,
                        109, 183, 194, 93,  231, 50,  86,  250, 21,  63,  65,  195, 94,  226, 61,  71,  201, 64,  192,
                        91,  237, 44,  116, 156, 191, 218, 117, 159, 186, 213, 100, 172, 239, 42,  126, 130, 157, 188,
                        223, 122, 142, 137, 128, 155, 182, 193, 88,  232, 35,  101, 175, 234, 37,  111, 177, 200, 67,
                        197, 84,  252, 31,  33,  99,  165, 244, 7,   9,   27,  45,  119, 153, 176, 203, 70,  202, 69,
                        207, 74,  222, 121, 139, 134, 145, 168, 227, 62,  66,  198, 81,  243, 14,  18,  54,  90,  238,
                        41,  123, 141, 140, 143, 138, 133, 148, 167, 242, 13,  23,  57,  75,  221, 124, 132, 151, 162,
                        253, 28,  36,  108, 180, 199, 82,  246, 1};

                    inline static byte_type mul(byte_type x, byte_type y) {
                        if (x && y) {
                            return pow_[(log_[x] + log_[y]) % 255];
                        } else {
                            return 0;
                        }
                    }

                    inline static typename ::nil::crypto3::detail::basic_functions<WordBits>::word_type
                        rotate_left(typename ::nil::crypto3::detail::basic_functions<WordBits>::word_type x) {
                        uint8_t c = reinterpret_cast<uint8_t *>(&x)[0];
                        for (int i = 0; i < 3; i++) {
                            reinterpret_cast<uint8_t *>(&x)[i] = reinterpret_cast<uint8_t *>(&x)[i + 1];
                        }
                        reinterpret_cast<uint8_t *>(&x)[3] = c;
                        return x;
                    }

                    inline static byte_type xtime(byte_type s) {
                        return static_cast<byte_type>(static_cast<byte_type>(s << 1) ^ ((s >> 7) * 0x1B));
                    }

                    inline static byte_type xtime4(byte_type s) {
                        return xtime(xtime(s));
                    }

                    inline static byte_type xtime8(byte_type s) {
                        return xtime(xtime(xtime(s)));
                    }

                    inline static byte_type xtime3(byte_type s) {
                        return xtime(s) ^ s;
                    }

                    inline static byte_type xtime9(byte_type s) {
                        return xtime8(s) ^ s;
                    }

                    inline static byte_type xtime11(byte_type s) {
                        return xtime8(s) ^ xtime(s) ^ s;
                    }

                    inline static byte_type xtime13(byte_type s) {
                        return xtime8(s) ^ xtime4(s) ^ s;
                    }

                    inline static byte_type xtime14(byte_type s) {
                        return xtime8(s) ^ xtime4(s) ^ xtime(s);
                    }

                    static const prefetched_constants_type prefetch_constants(const constants_type &constants) {
                        BOOST_ALIGNMENT(64) prefetched_constants_type result;

                        copy_n_if(constants.begin(), result.size(), result.begin(),
                                  [](const typename constants_type::value_type &c) ->
                                  typename prefetched_constants_type::value_type {
                                      return {xtime(c), c, c, xtime3(c)};
                                  });

                        return result;
                    }

                    static const prefetched_constants_type
                        prefetch_inverted_constants(const constants_type &constants) {
                        BOOST_ALIGNMENT(64) prefetched_constants_type result;

                        copy_n_if(constants.begin(), result.size(), result.begin(),
                                  [](const typename constants_type::value_type &c) ->
                                  typename prefetched_constants_type::value_type {
                                      return {xtime14(c), xtime9(c), xtime13(c), xtime11(c)};
                                  });

                        return result;
                    }
                };

                template<std::size_t KeyBits, std::size_t BlockBits>
                BOOST_ALIGNMENT(64)
                constexpr typename rijndael_functions<KeyBits, BlockBits>::constants_type const
                    rijndael_functions<KeyBits, BlockBits>::log_;

                template<std::size_t KeyBits, std::size_t BlockBits>
                BOOST_ALIGNMENT(64)
                constexpr typename rijndael_functions<KeyBits, BlockBits>::constants_type const
                    rijndael_functions<KeyBits, BlockBits>::pow_;
            }    // namespace detail
        }        // namespace block
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_RIJNDAEL_FUNCTIONS_CPP_HPP
