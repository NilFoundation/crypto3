//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_MERKLE_DAMGARD_CONSTRUCTION_HPP
#define CRYPTO3_HASH_MERKLE_DAMGARD_CONSTRUCTION_HPP

#include <nil/crypto3/detail/static_digest.hpp>
#include <nil/crypto3/detail/pack.hpp>
#include <nil/crypto3/detail/stream_endian.hpp>
#include <nil/crypto3/hash/detail/nop_finalizer.hpp>

#include <boost/utility/enable_if.hpp>

#include <algorithm>

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
             * The Merkle-Damgård construction builds a block hash from a
             * one-way compressor.  As this version operated on the block
             * level, it doesn't contain any padding or other strengthening.
             * For a Wide Pipe construction, use a digest that will
             * truncate the internal state.
             *
             * @note http://www.merkle.com/papers/Thesis1979.pdf
             */
            template<typename Params, typename IV, typename Compressor, typename Finalizer = nop_finalizer>
            class merkle_damgard_construction {
            public:
                typedef IV iv_generator;
                typedef Compressor compressor_functor;
                typedef Finalizer finalizer_functor;

                typedef typename Params::digest_endian endian_type;

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
                constexpr static const std::size_t digest_words = digest_bits / word_bits;
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
                inline merkle_damgard_construction &process_block(const block_type &block, Integer seen = Integer()) {
                    compressor_functor::process_block(state_, block);
                    return *this;
                }

                inline digest_type end_message(const block_type &block = block_type(),
                                               length_type seen = length_type()) {
                    digest_type d = digest(block, seen);
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
                struct endian_shift;

                template<int UnitBits>
                struct endian_shift<stream_endian::big_unit_big_bit<UnitBits>> {
                    static word_type& to_msb(word_type &w, length_type shift) {
                        //shift to most significant bits according to endianness
                        w <<= shift;
                        return w;
                    }
                };

                template<int UnitBits>
                struct endian_shift<stream_endian::little_unit_big_bit<UnitBits>> {
                    static word_type& to_msb(word_type &w, length_type shift) {
                        //shift to most significant bits according to endianness
                        length_type shift_rem = shift % UnitBits;
                        length_type shift_unit_bits = shift - shift_rem;
                        
                        length_type sz[2] = {UnitBits - shift_rem, shift_rem};
                        length_type masks[2] = {right_bits<word_type>(sz[0]) << shift_unit_bits, 
                        right_bits<word_type>(sz[1]) << (shift_unit_bits + UnitBits + sz[0])};
                        length_type bits_left = word_bits - shift;
                        word_type w_combined = 0;
                        int ind = 0;

                        while (bits_left) {
                            w_combined |= (!ind ? ((w & masks[0]) << shift_rem) : ((w & masks[1]) >> (UnitBits + sz[0])));
                            bits_left -= sz[ind];
                            masks[ind] <<= UnitBits;
                            ind = 1 - ind;
                        }

                        w = w_combined >> shift_unit_bits;
                        return w;
                    }
                };

                template<int UnitBits>
                struct endian_shift<stream_endian::big_unit_little_bit<UnitBits>> {
                    static word_type& to_msb(word_type &w, length_type shift) {
                        //shift to most significant bits according to endianness
                        length_type shift_rem = shift % UnitBits;
                        length_type shift_unit_bits = shift - shift_rem;

                        length_type sz[2] = {UnitBits - shift_rem, shift_rem};
                        length_type masks[2] = {left_bits<word_type>(sz[0]) >> shift_unit_bits, 
                        left_bits<word_type>(sz[1]) >> (shift_unit_bits + UnitBits + sz[0])};

                        length_type bits_left = word_bits - shift;
                        word_type w_combined = 0;
                        int ind = 0;

                        while (bits_left) {
                            w_combined |= (!ind ? ((w & masks[0]) >> shift_rem) : ((w & masks[1]) << (UnitBits + sz[0])));
                            bits_left -= sz[ind];
                            masks[ind] >>= UnitBits;
                            ind = 1 - ind;
                        }

                        w = w_combined << shift_unit_bits;
                        return w;
                    }
                };

                template<int UnitBits> 
                struct endian_shift<stream_endian::little_unit_little_bit<UnitBits>> {
                    static word_type& to_msb(word_type &w, length_type shift) {
                        //shift to most significant bits according to endianness
                        w >>= shift;
                        return w;
                    }
                };

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

                            //block_seen += word_seen;
                        }
                    }

                    static void inject(block_type &b_src, length_type b_src_seen, block_type &b_dst, length_type &b_dst_seen) {
                        //Insert word_seen-bit part of word into the block b according to endianness

                        // Check whether we fall out of the block
                        if (b_src_seen + b_dst_seen <= block_bits) {
                            
                            for (length_type i = 0; i< (b_src_seen / word_bits); i++){
                                inject(b_src[i], word_bits, b_dst, b_dst_seen);
                            }

                            inject(b_src[b_src_seen / word_bits + (b_src_seen%word_bits? 1 : 0)], b_src_seen%word_bits, b_dst, b_dst_seen);

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
                        }
                    }

                    static void inject(block_type &b_src, length_type b_src_seen, block_type &b_dst, length_type &b_dst_seen) {
                        //Insert word_seen-bit part of word into the block b according to endianness

                        // Check whether we fall out of the block
                        if (b_src_seen + b_dst_seen <= block_bits) {
                            
                            for (length_type i = 0; i< (b_src_seen / word_bits); i++){
                                inject(b_src[i], word_bits, b_dst, b_dst_seen);
                            }

                            inject(b_src[b_src_seen / word_bits + (b_src_seen%word_bits? 1 : 0)], b_src_seen%word_bits, b_dst, b_dst_seen);

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
                        }
                    }

                    static void inject(block_type &b_src, length_type b_src_seen, block_type &b_dst, length_type &b_dst_seen) {
                        //Insert word_seen-bit part of word into the block b according to endianness

                        // Check whether we fall out of the block
                        if (b_src_seen + b_dst_seen <= block_bits) {
                            
                            for (length_type i = 0; i< (b_src_seen / word_bits); i++){
                                inject(b_src[i], word_bits, b_dst, b_dst_seen);
                            }

                            inject(b_src[b_src_seen / word_bits + (b_src_seen%word_bits? 1 : 0)], b_src_seen%word_bits, b_dst, b_dst_seen);

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
                        }
                    }

                    static void inject(block_type &b_src, length_type b_src_seen, block_type &b_dst, length_type &b_dst_seen) {
                        //Insert word_seen-bit part of word into the block b according to endianness

                        // Check whether we fall out of the block
                        if (b_src_seen + b_dst_seen <= block_bits) {
                            
                            for (length_type i = 0; i< (b_src_seen / word_bits); i++){
                                inject(b_src[i], word_bits, b_dst, b_dst_seen);
                            }

                            inject(b_src[b_src_seen / word_bits + (b_src_seen%word_bits? 1 : 0)], b_src_seen%word_bits, b_dst, b_dst_seen);

                        }
                    }
                };

                inline digest_type digest(const block_type &block = block_type(), length_type seen = length_type()) {
                    
                    using namespace nil::crypto3::detail;
                    block_type b;
                    length_type head_bits = seen % block_bits; // the number of significant bits in block
                    length_type head_words = (seen / word_bits) % block_words; // the number of significant block words

                    // Case of full block
                    if (!head_bits) {
                        std::fill(b.begin(), b.end(), 0);
                    }
                    // Case of incomplete block 
                    else {
                        
                        std::move(block.begin(), block.end(), b.begin());

                        // Remove possible garbage from the block
                        std::fill(b.begin() + head_words + 1, b.end(), 0);
                        
                    }
                    // Fill the block with bit 1 and length
                    std::array<bool, word_bits> bit_one = {{1}};
                    std::array<word_type, 1> bit_one_word = {0};
                    pack<endian_type, 1, word_bits>(bit_one, bit_one_word);
                    injector<endian_type>::inject(bit_one_word[0], 1, b, head_bits);
                    
                    // Create new block if there is no sufficient data to hold length in the current block
                    if (head_bits > block_bits - length_bits - 1) {
                        process_block(b);
                        std::fill(b.begin(), b.end(), 0);                            
                    }
                    // Append length to last block
                    append_length<int>(b, seen);

                    // Process the last block
                    process_block(b);

                    // Apply finalizer                   
                    finalizer_functor finalizer;
                    finalizer(state_);
                    // Convert digest to byte representation
                    digest_type d;
                    pack_n<endian_type, word_bits, octet_bits>(state_.data(), digest_words, d.data(), digest_bytes);
                    return d;
                }

                merkle_damgard_construction() {
                    reset();
                }

                inline void reset(const state_type &s) {
                    state_ = s;
                }

                inline void reset() {
                    iv_generator iv;
                    reset(iv());
                }

                inline const state_type &state() const {
                    return state_;
                }

            protected:
                template<typename Dummy>
                typename boost::enable_if_c<length_bits && sizeof(Dummy)>::type append_length(block_type &block, length_type length) {
                    using namespace nil::crypto3::detail;
                    std::array<bool, length_bits> length_bits_array;
                    // FIXME1: message length can be more than 2^64 - 1 if we use 512-bit hash
                    bool is_greater = length_bits > 64;
                    // FIXME2: here we consider that length_bits == 2 * word_bits
                    if (is_greater)
                        for (length_type i = 0; i != word_bits; ++i)
                            length_bits_array[i] = false;                        

                    length_type tail_len = is_greater ? word_bits : length_bits;
                    for (length_type i = 0; i != tail_len; ++i)
                        length_bits_array[i + is_greater * word_bits] = length & (left_bits<length_type>(1) >> i);

                    // Append length
                    std::array<word_type, length_words> length_words_array;
                    for (std::size_t i = 0; i != length_words; ++i)
                        length_words_array[i] = 0;

                    pack<endian_type, 1, word_bits>(length_bits_array, length_words_array);
                    for (std::size_t i = length_words; i; --i) {
                        block[block_words - i] = length_words_array[length_words - i];
                    }

                    
                }
                /*
                template<>
                void append_length<0>(block_type &block, length_type length) {
                }*/
                template<typename Dummy>
                typename boost::disable_if_c<length_bits && sizeof(Dummy)>::type append_length(block_type &block, length_type length) {
                    // No appending requested, so nothing to do
                }

                state_type state_;
            };

        }    // namespace hash
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_MERKLE_DAMGARD_BLOCK_HASH_HPP