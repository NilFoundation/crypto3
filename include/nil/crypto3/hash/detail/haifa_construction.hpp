//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_HAIFA_CONSTRUCTION_HPP
#define CRYPTO3_HASH_HAIFA_CONSTRUCTION_HPP

#include <nil/crypto3/hash/detail/nop_finalizer.hpp>

#include <nil/crypto3/detail/static_digest.hpp>
#include <nil/crypto3/detail/pack.hpp>

namespace nil {
    namespace crypto3 {
        namespace hash {
            /*!
             * @brief
             * @tparam DigestEndian
             * @tparam DigestBits
             * @tparam IV
             * @tparam Compressor
             * @tparam Finalizer
             *
             * The HAIFA construction builds a block hash from a
             * one-way compressor.  As this version operated on the block
             * level, it doesn't contain any padding or other strengthening.
             * For a Wide Pipe construction, use a digest that will
             * truncate the internal state.
             *
             * @note https://eprint.iacr.org/2007/278.pdf
             */
            template<typename Params, typename IV, typename Compressor, typename Finalizer = nop_finalizer>
            class haifa_construction {
            public:
                typedef Compressor compressor_functor;
                typedef Finalizer finalizer_functor;

                typedef typename Params::digest_endian endian_type;

                constexpr static const std::size_t salt_bits = compressor_functor::salt_bits;
                typedef typename compressor_functor::salt_type salt_type;
                constexpr static const salt_type salt_value = compressor_functor::salt_value;

                typedef typename compressor_functor::iv_generator iv_generator;

                constexpr static const std::size_t word_bits = compressor_functor::word_bits;
                typedef typename compressor_functor::word_type word_type;

                constexpr static const std::size_t state_bits = compressor_functor::state_bits;
                constexpr static const std::size_t state_words = compressor_functor::state_words;
                typedef typename compressor_functor::state_type state_type;

                constexpr static const std::size_t block_bits = compressor_functor::block_bits;
                constexpr static const std::size_t block_words = compressor_functor::block_words;
                typedef typename compressor_functor::block_type block_type;

                constexpr static const std::size_t digest_bits = Params::digest_bits;
                constexpr static const std::size_t digest_bytes = digest_bits / octet_bits;
                constexpr static const std::size_t digest_words = digest_bits / word_bits + ((digest_bits % word_bits) ? 1 : 0);
                typedef static_digest<digest_bits> digest_type;

            protected:
                constexpr static const std::size_t length_bits = Params::length_bits;
                // FIXME: do something more intelligent than capping at 64
                constexpr static const std::size_t length_type_bits =
                    length_bits < word_bits ? word_bits : length_bits > 64 ? 64 : length_bits;
                typedef typename boost::uint_t<length_type_bits>::least length_type;
                constexpr static const std::size_t length_words = length_bits / word_bits;
                BOOST_STATIC_ASSERT(!length_bits || length_bits % word_bits == 0);

            public:
                template<typename Integer = std::size_t>
                inline haifa_construction &process_block(const block_type &block, Integer seen,
                                                         Integer finalization = 0) {
                    compressor_functor::process_block(state_, block, seen, finalization);
                    return *this;
                }

                inline digest_type end_message() {
                    digest_type d = digest();
                    reset();
                    return d;
                }

                // Creates mask with shift left bits
                template<typename T>
                static T left_bits(length_type shift) {
                    return (shift == word_bits || shift == length_bits)? ~T() : ~(~T() >> shift);
                }

                // Creates mask with shift right bits
                template<typename T>
                static T right_bits(length_type shift) {
                    return (shift == word_bits || shift == length_bits) ? ~T() : ~(~T() << shift);
                }   

                template<typename Endianness>
                struct injector;

                template<int UnitBits>
                struct injector<stream_endian::big_unit_big_bit<UnitBits>> {
                    static void inject(word_type w, length_type word_seen, block_type &b, length_type &block_seen) {
                        //Insert word_seen-bit part of word into the block b according to endianness

                        // Check whether we fall out of the block
                        if (block_seen + word_seen <= block_bits) {
                            length_type last_word_ind = block_seen / word_bits;
                            length_type last_word_seen = block_seen % word_bits;
                            // Remove garbage
                            w &= left_bits<word_type>(word_seen);
                            b[last_word_ind] &= left_bits<word_type>(last_word_seen);

                            // Add significant word bits to block word
                            b[last_word_ind] |= (w >> last_word_seen);
                            // If we fall out of the block word, push the remainder of element to the next block word
                            if (last_word_seen + word_seen > word_bits)
                                b[last_word_ind + 1] = w << (word_bits - last_word_seen);

                            block_seen += word_seen;
                        }
                    }
                };

                template<int UnitBits>
                struct injector<stream_endian::little_unit_big_bit<UnitBits>> {
                    static void inject(word_type w, length_type word_seen, block_type &b, length_type block_seen) {
                        //Insert word_seen-bit part of word into the block b according to endianness

                        // Check whether we fall out of the block
                        if (block_seen + word_seen <= block_bits) {
                            length_type last_word_ind = block_seen / word_bits;
                            length_type last_word_seen = block_seen % word_bits;
                            // Remove garbage
                            length_type w_rem = word_seen % UnitBits;
                            length_type w_unit_bits = word_seen - w_rem;
                            word_type mask = right_bits<word_type>(w_unit_bits) | (right_bits<word_type>(w_rem) << (w_unit_bits + UnitBits - w_rem)); 
                            w &= mask; 
                            length_type b_rem = last_word_seen % UnitBits;
                            length_type b_unit_bits = last_word_seen - b_rem;
                            mask = right_bits<word_type>(b_unit_bits) | (right_bits<word_type>(b_rem) << (b_unit_bits + UnitBits - b_rem));
                            b[last_word_ind] &= mask;   
                            // Split and combine parts of unit values
                            length_type sz[2] = {UnitBits - b_rem, b_rem};
                            word_type masks[2] = {right_bits<word_type>(UnitBits - b_rem) << b_rem, right_bits<word_type>(b_rem)};
                            length_type bw_space = word_bits - last_word_seen;
                            word_type w_split = 0;
                            std::size_t sz_ind = 0;
                              
                            while (bw_space && w) {
                                w_split |= (!sz_ind ? ((w & masks[0]) >> b_rem) : ((w & masks[1]) << (UnitBits + sz[0]))); 
                                bw_space -= sz[sz_ind];
                                w &= ~masks[sz_ind];
                                masks[sz_ind] <<= UnitBits;
                                sz_ind = 1 - sz_ind;
                            }
                            // Add significant word bits to block word
                            b[last_word_ind] |= w_split << b_unit_bits;
                            // If we fall out of the block word, push the remainder of element to the next block word
                            if (w) {
                                w >>= (word_bits - b_unit_bits - UnitBits);
                                w_split = 0;
                                masks[0] = right_bits<word_type>(UnitBits - b_rem) << b_rem; 
                                masks[1] = right_bits<word_type>(b_rem);

                                while (w) {
                                    w_split |= (!sz_ind ? ((w & masks[0]) >> b_rem) : ((w & masks[1]) << (UnitBits + sz[0]))); 
                                    w &= ~masks[sz_ind];
                                    masks[sz_ind] <<= UnitBits;
                                    sz_ind = 1 - sz_ind;
                                }

                                b[last_word_ind + 1] = w_split >> UnitBits;
                            }

                            block_seen += word_seen;
                        }
                    }
                };

                template<int UnitBits>
                struct injector<stream_endian::big_unit_little_bit<UnitBits>> {
                    static void inject(word_type w, length_type word_seen, block_type &b, length_type block_seen) {
                        //Insert word_seen-bit part of word into the block b according to endianness

                        // Check whether we fall out of the block
                        if (block_seen + word_seen <= block_bits) {
                            length_type last_word_ind = block_seen / word_bits;
                            length_type last_word_seen = block_seen % word_bits;
                            // Remove garbage
                            length_type w_rem = word_seen % UnitBits;
                            length_type w_unit_bits = word_seen - w_rem;
                            word_type mask = left_bits<word_type>(w_unit_bits) | (left_bits<word_type>(w_rem) >> (w_unit_bits + UnitBits - w_rem)); 
                            w &= mask; 
                            length_type b_rem = last_word_seen % UnitBits;
                            length_type b_unit_bits = last_word_seen - b_rem;
                            mask = left_bits<word_type>(b_unit_bits) | (left_bits<word_type>(b_rem) >> (b_unit_bits + UnitBits - b_rem));
                            b[last_word_ind] &= mask; 
                            // Split and combine parts of unit values 
                            length_type sz[2] = {UnitBits - b_rem, b_rem};
                            word_type masks[2] = {left_bits<word_type>(UnitBits - b_rem) >> b_rem, left_bits<word_type>(b_rem)};
                            length_type bw_space = word_bits - last_word_seen;
                            word_type w_split = 0;
                            std::size_t sz_ind = 0;
                             
                            while (bw_space && w) {
                                w_split |= (!sz_ind ? ((w & masks[0]) << b_rem) : ((w & masks[1]) >> (UnitBits + sz[0]))); 
                                bw_space -= sz[sz_ind];
                                w &= ~masks[sz_ind];
                                masks[sz_ind] >>= UnitBits;
                                sz_ind = 1 - sz_ind;
                            }
                            // Add significant word bits to block word
                            b[last_word_ind] |= w_split >> b_unit_bits;
                            // If we fall out of the block word, push the remainder of element to the next block word
                            if (w) {
                                w <<= (word_bits - b_unit_bits - UnitBits);
                                w_split = 0;
                                masks[0] = left_bits<word_type>(UnitBits - b_rem) >> b_rem; 
                                masks[1] = left_bits<word_type>(b_rem);

                                while (w) {
                                    w_split |= (!sz_ind ? ((w & masks[0]) << b_rem) : ((w & masks[1]) >> (UnitBits + sz[0]))); 
                                    w &= ~masks[sz_ind];
                                    masks[sz_ind] >>= UnitBits;
                                    sz_ind = 1 - sz_ind;
                                }

                                b[last_word_ind + 1] = w_split << UnitBits;
                            }
                            block_seen += word_seen;
                        }
                    }
                };

                template<int UnitBits>
                struct injector<stream_endian::little_unit_little_bit<UnitBits>> {
                    static void inject(word_type w, length_type word_seen, block_type &b, length_type block_seen) {
                        //Insert word_seen-bit part of word into the block b according to endianness

                        // Check whether we fall out of the block
                        if (block_seen + word_seen <= block_bits) {
                            length_type last_word_ind = block_seen / word_bits;
                            length_type last_word_seen = block_seen % word_bits;
                            // Remove garbage
                            w &= right_bits<word_type>(word_seen);
                            b[last_word_ind] &= right_bits<word_type>(last_word_seen);
                            // Add significant word bits to block word
                            b[last_word_ind] |= (w << last_word_seen);
                            // If we fall out of the block word, push the remainder of element to the next block word
                            if (last_word_seen + word_seen > word_bits)
                                b[last_word_ind + 1] = w >> (word_bits - last_word_seen);

                            block_seen += word_seen;
                        }
                    }
                };

                inline digest_type digest(const block_type &block = block_type(), length_type seen = length_type()) {
                    // FIXME: this message padding works only for blake2b hash                     
                    using namespace nil::crypto3::detail;
                    block_type b;
                    length_type head_bits = seen % block_bits; // the number of significant bits in block
                    length_type head_words = (seen / word_bits) % block_words; // the number of significant block words
                        
                    std::move(block.begin(), block.end(), b.begin());
                    // Remove possible garbage from the block
                    std::fill(b.begin() + head_words + 1, b.end(), 0);
                    injector<endian_type>::inject(0, word_bits - (head_bits % word_bits), b, head_bits);

                    // Process the last block
                    process_block(b, seen, salt_value);

                    // Apply finalizer                   
                    finalizer_functor finalizer;
                    finalizer(state_);
                    
                    // Convert digest to byte representation
                    std::array<octet_type, state_bits / octet_bits> d_full;
                    pack_n<endian_type, word_bits, octet_bits>(state_.data(), state_words, d_full.data(), state_bits / octet_bits);

                    digest_type d;
                    for (size_t i = 0; i != digest_bytes; ++i)
                        d[i] = d_full[i];
                    
                    return d;
                }

                haifa_construction() {
                    reset();
                }

                void reset(const state_type &s) {
                    state_ = s;
                    state_[0] ^= 0x01010000U ^ (digest_bits / CHAR_BIT);
                }

                void reset() {
                    iv_generator iv;
                    reset(iv());
                }

                state_type const &state() const {
                    return state_;
                }

            private:
                state_type state_;
            };

        }    // namespace hash
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_HAIFA_CONSTRUCTION_HPP
