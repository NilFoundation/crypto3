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

#ifndef CRYPTO3_MODE_PADDING_HPP
#define CRYPTO3_MODE_PADDING_HPP

#include <nil/crypto3/utilities/secmem.hpp>

#include <string>

#include <boost/static_assert.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace modes {
                namespace padding {
                    /*!
                     * @brief  Block Cipher Mode Padding Method
                     * @tparam Cipher Block cipher used
                     *
                     * This class is pretty limited, it cannot deal well with
                     * randomized padding methods, or any padding method that
                     * wants to add more than one block. For instance, it should
                     * be possible to define cipher text stealing mode as simply
                     * a padding mode for CBC, which happens to consume the last
                     * two block (and requires use of the block cipher).
                     */
                    template<typename Cipher>
                    struct basic_padding {
                        typedef std::size_t size_type;

                        typedef Cipher cipher_type;

                        constexpr static const size_type block_bits = cipher_type::block_bits;
                        constexpr static const size_type block_words = cipher_type::block_words;
                        typedef typename cipher_type::block_type block_type;
                    };

                    /*!
                     * @tparam Cipher Block cipher used
                     */
                    template<typename Cipher>
                    struct zeros : public basic_padding<Cipher> {
                        typedef typename basic_padding<Cipher>::size_type size_type;

                        typedef typename basic_padding<Cipher>::cipher_type cipher_type;

                        constexpr static const size_type block_bits = basic_padding<Cipher>::block_bits;
                        constexpr static const size_type block_words = basic_padding<Cipher>::block_words;
                        typedef typename basic_padding<Cipher>::block_type block_type;

                        constexpr static const bool always_pad = false;

                        inline static size_type required_output_size(size_type len, size_type block_size) {
                            if (len) {
                                const size_type rem = len % block_size;
                                if (rem) {
                                    if (std::numeric_limits<size_type>::max() - len < block_size) {
                                        throw std::overflow_error("message length is too long");
                                    } else {
                                        return len - rem + block_size;
                                    }
                                }
                            }
                            return len;
                        }

                        inline static block_type pad(const block_type &block, size_type bytes_in_block) {
                            block_type result = block;
                            uint8_t *ptr = static_cast<uint8_t *>(&*result.data());
                            std::memset(ptr + bytes_in_block, 0, block_bits / CHAR_BIT - bytes_in_block);

                            return result;
                        }

                        inline static block_type unpad(const block_type &block, size_type bytes_in_block) {
                            ct::poison(block, bytes_in_block);
                            uint8_t bad_input = 0;
                            uint8_t seen_one = 0;
                            size_t pad_pos = bytes_in_block - 1;
                            size_t i = bytes_in_block;

                            while (i) {
                                seen_one |= ct::is_equal<uint8_t>(block[i - 1], 0x80);
                                pad_pos -= ct::select<uint8_t>(~seen_one, 1, 0);
                                bad_input |= ~ct::is_zero<uint8_t>(block[i - 1]) & ~seen_one;
                                i--;
                            }
                            bad_input |= ~seen_one;

                            ct::conditional_copy_mem(size_t(bad_input), &pad_pos, &bytes_in_block, &pad_pos, 1);
                            ct::unpoison(block, bytes_in_block);
                            ct::unpoison(pad_pos);
                        }
                    };

                    /*!
                     * @brief (ISO/IEC 9797-1, padding method 2)
                     * @tparam Cipher Block cipher used
                     * 0x80 0x00 0x00 ....
                     */
                    template<typename Cipher>
                    struct one_and_zeros : public basic_padding<Cipher> {
                        typedef typename basic_padding<Cipher>::size_type size_type;

                        typedef typename basic_padding<Cipher>::cipher_type cipher_type;

                        constexpr static const size_type block_bits = basic_padding<Cipher>::block_bits;
                        constexpr static const size_type block_words = basic_padding<Cipher>::block_words;
                        typedef typename basic_padding<Cipher>::block_type block_type;

                        BOOST_STATIC_ASSERT(block_bits > 0);

                        constexpr static const bool always_pad = true;

                        inline static size_type required_output_size(size_type len, size_type block_size) {
                            if (len) {
                                const size_type rem = len % block_size;
                                if (rem) {
                                    if (std::numeric_limits<size_type>::max() - len < block_size) {
                                        throw std::overflow_error("message length is too long");
                                    } else {
                                        return len - rem + block_size;
                                    }
                                }
                            }
                            return len + block_size;
                        }

                        inline static block_type pad(const block_type &block, size_type bytes_in_block) {
                            block_type result = block;
                            uint8_t *ptr = static_cast<uint8_t *>(result);
                            ptr += bytes_in_block;
                            *ptr++ = 0x80;
                            ++bytes_in_block;
                            std::memset(ptr, 0, block_bits / CHAR_BIT - bytes_in_block);
                            return result;
                        }
                    };

                    /*!
                     * @brief
                     * @tparam Cipher Block cipher used
                     */
                    template<typename Cipher>
                    struct trailing_bit : public basic_padding<Cipher> {
                        typedef typename basic_padding<Cipher>::size_type size_type;

                        typedef typename basic_padding<Cipher>::cipher_type cipher_type;

                        constexpr static const size_type block_bits = basic_padding<Cipher>::block_bits;
                        constexpr static const size_type block_words = basic_padding<Cipher>::block_words;
                        typedef typename basic_padding<Cipher>::block_type block_type;
                    };

                    /*!
                     * @tparam Cipher Block cipher used
                     * RFC 2315 (10.3.2)
                     * Some content-encryption algorithms assume the
                     * input length is a multiple of k octets, where k > 1, and
                     * let the application define a method for handling inputs
                     * whose lengths are not a multiple of k octets. For such
                     * algorithms, the method shall be to pad the input at the
                     * trailing end with k - (l mod k) octets all having value k -
                     * (l mod k), where l is the length of the input. In other
                     * words, the input is padded at the trailing end with one of
                     * the following strings:
                     *
                     *          01 -- if l mod k = k-1
                     *         02 02 -- if l mod k = k-2
                     *                     .
                     *                     .
                     *                     .
                     *       k k ... k k -- if l mod k = 0
                     *
                     * The padding can be removed unambiguously since all input is
                     * padded and no padding string is a suffix of another. This
                     * padding method is well-defined if and only if k < 256;
                     * methods for larger k are an open issue for further study.
                     */
                    template<typename Cipher>
                    struct pkcs7 : public basic_padding<Cipher> {
                        typedef typename basic_padding<Cipher>::size_type size_type;

                        typedef typename basic_padding<Cipher>::cipher_type cipher_type;

                        constexpr static const size_type block_bits = basic_padding<Cipher>::block_bits;
                        constexpr static const size_type block_words = basic_padding<Cipher>::block_words;
                        typedef typename basic_padding<Cipher>::block_type block_type;

                        BOOST_STATIC_ASSERT(block_bits > 0 && block_bits < 256);

                        inline static void pad(const block_type &block, size_type bytes_in_block) {
                            const uint8_t pad_value = static_cast<uint8_t>(block_size - last_byte_pos);

                            for (size_t i = 0; i != pad_value; ++i) {
                                buffer.push_back(pad_value);
                            }
                        }

                        inline static void unpad(const block_type &block, size_type bytes_in_block) {
                            ct::poison(block, bytes_in_block);
                            size_t bad_input = 0;
                            const uint8_t last_byte = block[bytes_in_block - 1];

                            bad_input |= ct::expand_mask<size_t>(last_byte > bytes_in_block);

                            size_t pad_pos = bytes_in_block - last_byte;
                            size_t i = bytes_in_block - 2;
                            while (i) {
                                bad_input |=
                                    (~ct::is_equal(block[i], last_byte)) & ct::expand_mask<uint8_t>(i >= pad_pos);
                                --i;
                            }

                            ct::conditional_copy_mem(bad_input, &pad_pos, &bytes_in_block, &pad_pos, 1);
                            ct::unpoison(block, bytes_in_block);
                            ct::unpoison(pad_pos);
                        }
                    };

                    /*!
                     * @brief ESP Padding (RFC 4304)
                     * @tparam Cipher
                     */
                    template<typename Cipher>
                    struct esp : public basic_padding<Cipher> {
                        typedef typename basic_padding<Cipher>::size_type size_type;

                        typedef typename basic_padding<Cipher>::cipher_type cipher_type;

                        constexpr static const size_type block_bits = basic_padding<Cipher>::block_bits;
                        constexpr static const size_type block_words = basic_padding<Cipher>::block_words;
                        typedef typename basic_padding<Cipher>::block_type block_type;

                        inline static void pad(const block_type &block, size_type bytes_in_block) {
                            uint8_t pad_value = 0x01;

                            for (size_t i = last_byte_pos; i < bytes_in_block; ++i) {
                                buffer.push_back(pad_value++);
                            }
                        }

                        inline static void unpad(const block_type &block, size_type size) {
                            ct::poison(block, size);

                            const size_t last_byte = block[size - 1];
                            size_t bad_input = 0;
                            bad_input |= ct::expand_mask<size_t>(last_byte > size);

                            size_t pad_pos = size - last_byte;
                            size_t i = size - 1;
                            while (i) {
                                bad_input |= ~ct::is_equal<uint8_t>(size_t(block[i - 1]), size_t(block[i]) - 1) &
                                             ct::expand_mask<uint8_t>(i > pad_pos);
                                --i;
                            }
                            ct::conditional_copy_mem(bad_input, &pad_pos, &size, &pad_pos, 1);
                            ct::unpoison(block, size);
                            ct::unpoison(pad_pos);
                        }
                    };

                    /*!
                     * @brief ANSI X9.23 Padding
                     * @tparam Cipher
                     */
                    template<typename Cipher>
                    struct ansi_x923 : public basic_padding<Cipher> {
                        typedef typename basic_padding<Cipher>::size_type size_type;

                        typedef typename basic_padding<Cipher>::cipher_type cipher_type;

                        constexpr static const size_type block_bits = basic_padding<Cipher>::block_bits;
                        constexpr static const size_type block_words = basic_padding<Cipher>::block_words;
                        typedef typename basic_padding<Cipher>::block_type block_type;

                        BOOST_STATIC_ASSERT(block_bits > 0 && block_bits < 256);

                        inline static void pad(const block_type &block, size_type bytes_in_block) {
                            const uint8_t pad_value = static_cast<uint8_t>(bytes_in_block - last_byte_pos);

                            for (size_t i = last_byte_pos; i < bytes_in_block - 1; ++i) {
                                buffer.push_back(0);
                            }
                            buffer.push_back(pad_value);
                        }

                        inline static void unpad(const block_type &block, size_type size) {
                            ct::poison(block, size);
                            size_t bad_input = 0;
                            const size_t last_byte = block[size - 1];

                            bad_input |= ct::expand_mask<size_t>(last_byte > size);

                            size_t pad_pos = size - last_byte;
                            size_t i = size - 2;
                            while (i) {
                                bad_input |= (~ct::is_zero(block[i])) & ct::expand_mask<uint8_t>(i >= pad_pos);
                                --i;
                            }
                            ct::conditional_copy_mem(bad_input, &pad_pos, &size, &pad_pos, 1);
                            ct::unpoison(block, size);
                            ct::unpoison(pad_pos);
                        }
                    };
                }    // namespace padding
            }        // namespace modes
        }            // namespace block
    }                // namespace crypto3
}    // namespace nil

#endif
