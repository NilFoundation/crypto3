//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_CIPHER_STATE_PREPROCESSOR_HPP
#define CRYPTO3_CIPHER_STATE_PREPROCESSOR_HPP

#include <array>
#include <iterator>

#include <nil/crypto3/block/block_cipher.hpp>

#include <nil/crypto3/block/algorithm/move.hpp>

#include <nil/crypto3/block/detail/pack.hpp>
#include <nil/crypto3/block/detail/digest.hpp>
#include <nil/crypto3/block/detail/cipher_modes.hpp>

#include <nil/crypto3/utilities/secmem.hpp>

#include <boost/integer.hpp>
#include <boost/static_assert.hpp>
#include <boost/utility/enable_if.hpp>

#include <boost/range/algorithm/copy.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            template<typename Cipher, typename Padding>
            struct nop_cipher_mode {
                typedef Cipher cipher_type;

                typedef typename Cipher::block_type block_type;

                inline block_type begin_message(const block_type &plaintext) {
                    return cipher_type::encrypt(plaintext);
                }

                inline block_type process_block(const block_type &plaintext) {
                    return cipher_type::encrypt(plaintext);
                }

                inline block_type end_message(const block_type &plaintext) {
                    return cipher_type::encrypt(plaintext);
                }
            };

            struct nop_finalizer {
                template<typename T>
                void operator()(T &) {
                }
            };

            template<typename Mode, typename Endian, std::size_t ValueBits, std::size_t LengthBits>
            struct cipher_state_preprocessor {
                typedef Mode mode_type;

                typedef typename mode_type::cipher_mode cipher_mode_type;
                typedef typename cipher_mode_type::cipher_type cipher_type;
                typedef typename cipher_mode_type::padding_type cipher_padding_type;

                constexpr static const std::size_t word_bits = cipher_type::word_bits;
                typedef typename cipher_type::word_type word_type;

                constexpr static const std::size_t block_bits = cipher_type::block_bits;
                constexpr static const std::size_t block_words = cipher_type::block_words;
                typedef typename cipher_type::block_type block_type;

                constexpr static const std::size_t value_bits = ValueBits;
                typedef typename boost::uint_t<value_bits>::least value_type;
                BOOST_STATIC_ASSERT(word_bits % value_bits == 0);
                constexpr static const std::size_t block_values = block_bits / value_bits;
                typedef std::array<value_type, block_values> value_array_type;

            private:

                constexpr static const std::size_t length_bits = LengthBits;
                // FIXME: do something more intelligent than capping at 64
                constexpr static const std::size_t length_type_bits =
                        length_bits < word_bits ? word_bits : length_bits > 64 ? 64 : length_bits;
                typedef typename boost::uint_t<length_type_bits>::least length_type;

                BOOST_STATIC_ASSERT(!length_bits || length_bits % word_bits == 0);
                BOOST_STATIC_ASSERT(block_bits % value_bits == 0);

                BOOST_STATIC_ASSERT(!length_bits || value_bits <= length_bits);

            public:
                template<typename OutputIterator>
                OutputIterator update_one(value_type value, OutputIterator out) {
                    unsigned i = seen % block_bits;
                    unsigned j = i / value_bits;
                    value_array[j] = value;
                    seen += value_bits;
                    if (i == block_bits - value_bits) {
                        // Process the completed block
                        // Convert the input into words
                        block_type block = {0};
                        pack<Endian, value_bits, word_bits>(value_array, block);

                        // Process the block
                        out = move(c.encrypt(block), out);

                        // Reset seen if we don't need to track the length
                        if (!length_bits) {
                            seen = 0;
                        }
                    }
                    return *this;
                }

                template<typename InputIterator, typename OutputIterator>
                OutputIterator update_n(InputIterator p, size_t n, OutputIterator out) {
#ifndef CRYPTO3_BLOCK_NO_OPTIMIZATION
                    for (; n && (seen % block_bits); --n, ++p) {
                        out = update_one(*p, out);
                    }
                    for (; n >= block_values; n -= block_values, p += block_values) {
                        // Convert the input into words
                        block_type block = {0};
                        pack_n<Endian, value_bits, word_bits>(p, block_values, std::begin(block), block_words);

                        // Process the block
                        out = move(c.encrypt(block), out);
                        seen += block_bits;

                        // Reset seen if we don't need to track the length
                        if (!length_bits) {
                            seen = 0;
                        }
                    }
#endif
                    for (; n; --n, ++p) {
                        out = update_one(*p, out);
                    }
                    return *this;
                }

                template<typename InputIterator, typename OutputIterator>
                OutputIterator operator()(InputIterator b, InputIterator e, OutputIterator out,
                                          std::random_access_iterator_tag) {
                    return update_n(b, e - b, out);
                }

                template<typename InputIterator, typename OutputIterator, typename Category>
                OutputIterator operator()(InputIterator first, InputIterator last, OutputIterator out, Category) {
                    while (first != last) {
                        update_one(*first++, out);
                    }
                    return *this;
                }

                template<typename InputIterator, typename OutputIterator>
                OutputIterator operator()(InputIterator b, InputIterator e, OutputIterator out) {
                    typedef typename std::iterator_traits<InputIterator>::iterator_category cat;
                    return update(b, e, cat(), out);
                }

                template<typename SinglePassRange, typename OutputIterator>
                OutputIterator operator()(const SinglePassRange &rng, OutputIterator out) {
                    return update_n(rng.data(), rng.size(), out);
                }

            public:
                cipher_state_preprocessor(const cipher_type &cipher = cipher_type())
                        : value_array(), c(cipher, cipher_padding_type()), seen() {
                }

                cipher_state_preprocessor(const cipher_mode_type &mode = cipher_mode_type())
                        : value_array(), c(mode), seen() {
                }

                cipher_state_preprocessor(const cipher_type &cipher = cipher_type(),
                                          const cipher_padding_type &padding = cipher_padding_type())
                        : value_array(), c(cipher, padding), seen() {
                }

                void reset() {
                    seen = 0;
                    c.reset();
                }

            private:
                value_array_type value_array;
                cipher<cipher_type, cipher_mode_type, cipher_padding_type> c;
                length_type seen;
            };
        }
    }
} // namespace nil

#endif // CRYPTO3_BLOCK_STREAM_PREPROCESSOR_HPP
