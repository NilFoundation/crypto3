//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_MERKLE_DAMGARD_STREAM_PROCESSOR_HPP
#define CRYPTO3_HASH_MERKLE_DAMGARD_STREAM_PROCESSOR_HPP

#include <array>
#include <iterator>

#include <nil/crypto3/hash/detail/pack.hpp>

#include <boost/integer.hpp>
#include <boost/static_assert.hpp>
#include <boost/utility/enable_if.hpp>

namespace nil {
    namespace crypto3 {
        namespace hash {

            /*!
             * @brief This will do the usual Merkle-Damgård-style strengthening,
             * padding with a 1 bit, then 0 bits as needed, then, if requested,
             * the length.
             *
             * @tparam Hash
             * @tparam StateAccumulator
             * @tparam Params
             */
            template<typename Hash, typename StateAccumulator, typename Params>
            class merkle_damgard_state_preprocessor {
            protected:
                typedef Hash block_hash_type;
                typedef StateAccumulator accumulator_type;
                typedef Params params_type;

                constexpr static const std::size_t word_bits = block_hash_type::word_bits;
                typedef typename block_hash_type::word_type word_type;

                constexpr static const std::size_t block_bits = block_hash_type::block_bits;
                constexpr static const std::size_t block_words = block_hash_type::block_words;
                typedef typename block_hash_type::block_type block_type;

            public:
                typedef typename block_hash_type::digest_type digest_type;

                typedef typename params_type::endian endian_type;

                constexpr static const std::size_t value_bits = params_type::value_bits;
                typedef typename boost::uint_t<value_bits>::least value_type;
                BOOST_STATIC_ASSERT(word_bits % value_bits == 0);
                constexpr static const std::size_t block_values = block_bits / value_bits;
                typedef std::array<value_type, block_values> value_array_type;

            protected:

                constexpr static const std::size_t length_bits = params_type::length_bits;
                // FIXME: do something more intelligent than capping at 64
                constexpr static const std::size_t length_type_bits =
                        length_bits < word_bits ? word_bits : length_bits > 64 ? 64 : length_bits;
                typedef typename boost::uint_t<length_type_bits>::least length_type;
                constexpr static const std::size_t length_words = length_bits / word_bits;
                BOOST_STATIC_ASSERT(!length_bits || length_bits % word_bits == 0);
                BOOST_STATIC_ASSERT(block_bits % value_bits == 0);

                BOOST_STATIC_ASSERT(!length_bits || value_bits <= length_bits);

                void process_block() {
                    // Convert the input into words
                    block_type block;
                    pack<endian_type, value_bits, word_bits>(value_array, block);

                    // Process the block
                    acc(block);

                    // Reset seen if we don't need to track the length
                    if (!length_bits) {
                        seen = 0;
                    }
                }

                template<typename Dummy>
                typename boost::enable_if_c<length_bits && sizeof(Dummy)>::type append_length(length_type length) {
                    // Convert the input into words
                    block_type block;
                    pack<endian_type, value_bits, word_bits>(value_array, block);

                    // Append length
                    std::array<length_type, 1> length_array = {{length}};
                    std::array<word_type, length_words> length_words_array;
                    pack<endian_type, length_bits, word_bits>(length_array, length_words_array);
                    for (std::size_t i = length_words; i; --i) {
                        block[block_words - i] = length_words_array[length_words - i];
                    }

                    // Process the last block
                    acc(block);
                }

                template<typename Dummy>
                typename boost::disable_if_c<length_bits && sizeof(Dummy)>::type append_length(length_type) {
                    // No appending requested, so nothing to do
                }

                merkle_damgard_state_preprocessor &update_one(value_type value) {
                    std::size_t i = seen % block_bits;
                    std::size_t j = i / value_bits;
                    value_array[j] = value;
                    seen += value_bits;
                    if (i == block_bits - value_bits) {
                        // Process the completed block
                        process_block();
                    }
                    return *this;
                }

                template<typename InputIterator>
                merkle_damgard_state_preprocessor &update_n(InputIterator p, size_t n) {
#ifndef CRYPTO3_HASH_NO_OPTIMIZATION
                    for (; n && (seen % block_bits); --n, ++p) {
                        update_one(*p);
                    }
                    for (; n >= block_values; n -= block_values, p += block_values) {
                        // Convert the input into words
                        block_type block;
                        pack_n<endian_type, value_bits, word_bits>(p, block_values, std::begin(block), block_words);

                        // Process the block
                        acc(block);
                        seen += block_bits;

                        // Reset seen if we don't need to track the length
                        if (!length_bits) {
                            seen = 0;
                        }
                    }
#endif
                    for (; n; --n, ++p) {
                        update_one(*p);
                    }
                    return *this;
                }

            public:

                template<typename InputIterator>
                void operator()(InputIterator b, InputIterator e, std::random_access_iterator_tag) {
                    return update_n(b, e - b);
                }

                template<typename InputIterator, typename Category>
                void operator()(InputIterator first, InputIterator last, Category) {
                    while (first != last) {
                        update_one(*first++);
                    }
                    return *this;
                }

                template<typename InputIterator>
                void operator()(InputIterator b, InputIterator e) {
                    typedef typename std::iterator_traits<InputIterator>::iterator_category cat;
                    return update(b, e, cat());
                }

                template<typename ContainerT>
                void operator()(const ContainerT &c) {
                    return update_n(c.data(), c.size());
                }

                template<typename DigestType = digest_type>
                DigestType end_message() {
                    length_type length = seen;

                    // Add a 1 bit
#ifdef CRYPTO3_HASH_NO_OPTIMIZATION
                    std::array<bool, value_bits> padding_bits = {{1}};
                    std::array<value_type, 1> padding_values;
                    pack<endian_type, 1, value_bits>(padding_bits, padding_values);
                    update_one(padding_values[0]);
#else
                    value_type pad = 0;
                    detail::imploder_step<endian_type, 1, value_bits, 0>::step(1, pad);
                    update_one(pad);
#endif

                    // Pad with 0 bits
                    while ((seen + length_bits) % block_bits != 0) {
                        update_one(value_type());
                    }

                    // Append length
                    append_length<int>(length);

                    // Reset for next message
                    seen = 0;

                    // Calculate static_digest and reset block_hash
                    return block_hash.end_message();
                }

                template<typename DigestType = digest_type>
                DigestType digest() const {
                    return merkle_damgard_state_preprocessor(*this).end_message();
                }

            public:
                merkle_damgard_state_preprocessor(accumulator_type &acc) : acc(acc), value_array(), block_hash(),
                        seen() {
                }

                virtual ~merkle_damgard_state_preprocessor() {

                }

                void reset() {
                    seen = 0;
                    block_hash.reset();
                }

            private:
                accumulator_type &acc;

                value_array_type value_array;
                block_hash_type block_hash;
                length_type seen;
            };
        }
    }
} // namespace nil

#endif
